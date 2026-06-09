//! The relying-party (client) side of OIDC/OAuth2 — used by the OIDC backend.
//!
//! Runtime-agnostic: outbound HTTP goes through the injected
//! [`crate::HttpClient`].

use crate::jwt;
use crate::metadata::ProviderMetadata;
use crate::oauth_error::urlencode;
use crate::provider::CLIENT_ASSERTION_TYPE;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Audience, Claims, Validation};
use std::collections::BTreeMap;
use std::sync::Arc;
use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::keys::SigningKey;
use crate::util::now_secs;

/// Minimal upstream provider info the RP needs.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

impl From<ProviderMetadata> for ProviderInfo {
    fn from(m: ProviderMetadata) -> Self {
        Self {
            issuer: m.issuer,
            authorization_endpoint: m.authorization_endpoint,
            token_endpoint: m.token_endpoint,
            userinfo_endpoint: Some(m.userinfo_endpoint),
            jwks_uri: Some(m.jwks_uri),
        }
    }
}

/// How the RP authenticates to the upstream token endpoint.
#[derive(Clone)]
pub enum ClientAuth {
    None,
    ClientSecretBasic(String),
    ClientSecretPost(String),
    /// `private_key_jwt` using the given signing key.
    PrivateKeyJwt(SigningKey),
}

/// RP client configuration.
#[derive(Clone)]
pub struct RpClient {
    pub client_id: String,
    pub redirect_uri: String,
    pub auth: ClientAuth,
    pub scope: String,
}

/// The result of a successful token exchange.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub token_type: Option<String>,
    pub raw: serde_json::Value,
}

/// Build the authorization request URL (redirect the user here).
pub fn authorization_url(
    provider: &ProviderInfo,
    client: &RpClient,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
    extra: &[(&str, &str)],
) -> String {
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", client.client_id.as_str()),
        ("redirect_uri", client.redirect_uri.as_str()),
        ("scope", client.scope.as_str()),
        ("state", state),
        ("nonce", nonce),
    ];
    if let Some(cc) = code_challenge {
        params.push(("code_challenge", cc));
        params.push(("code_challenge_method", "S256"));
    }
    params.extend_from_slice(extra);

    let qs: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let sep = if provider.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{}{}", provider.authorization_endpoint, sep, qs)
}

/// Discover provider metadata from an issuer.
pub async fn discover(http: &Arc<dyn HttpClient>, issuer: &str) -> Result<ProviderMetadata> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "discovery failed ({}) for {url}",
            resp.status
        )));
    }
    resp.json()
}

/// Fetch a JWKS document.
pub async fn fetch_jwks(http: &Arc<dyn HttpClient>, jwks_uri: &str) -> Result<JwkSet> {
    let resp = http.get(jwks_uri).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!("jwks fetch failed ({})", resp.status)));
    }
    JwkSet::from_json(&resp.text()).map_err(Error::from)
}

/// Exchange an authorization code for tokens.
pub async fn exchange_code(
    http: &Arc<dyn HttpClient>,
    provider: &ProviderInfo,
    client: &RpClient,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<TokenSet> {
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.to_string()),
        ("redirect_uri".into(), client.redirect_uri.clone()),
        ("client_id".into(), client.client_id.clone()),
    ];
    if let Some(v) = code_verifier {
        form.push(("code_verifier".into(), v.to_string()));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    apply_client_auth(client, provider, &mut form, &mut headers)?;

    let resp = http
        .post_form(&provider.token_endpoint, &form, &headers)
        .await?;
    if resp.status != 200 {
        return Err(Error::Authn(format!(
            "token endpoint returned {}: {}",
            resp.status,
            resp.text()
        )));
    }
    let raw: serde_json::Value = resp.json()?;
    Ok(TokenSet {
        access_token: raw
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from),
        id_token: raw.get("id_token").and_then(|v| v.as_str()).map(String::from),
        token_type: raw
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        raw,
    })
}

/// Verify an id_token against the provider JWKS, issuer, audience and nonce.
pub fn verify_id_token(
    jwks: &JwkSet,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
) -> Result<Claims> {
    let validation = Validation::new()
        .with_issuer(issuer)
        .with_audience(client_id);
    let claims = jwt::verify_with_jwks(jwks, id_token, &validation)?;

    if let Some(nonce) = expected_nonce {
        let got = claims.extra.get("nonce").and_then(|v| v.as_str());
        if got != Some(nonce) {
            return Err(Error::Authn("id_token nonce mismatch".into()));
        }
    }
    Ok(claims)
}

/// Fetch userinfo with a Bearer access token.
pub async fn fetch_userinfo(
    http: &Arc<dyn HttpClient>,
    userinfo_endpoint: &str,
    access_token: &str,
) -> Result<serde_json::Value> {
    // The injected client has no per-request header API on GET, so userinfo is
    // fetched via post_form with an empty body carrying the Authorization
    // header. (Most OPs accept GET or POST at userinfo.)
    let headers = vec![("authorization".to_string(), format!("Bearer {access_token}"))];
    let resp = http.post_form(userinfo_endpoint, &[], &headers).await?;
    if resp.status != 200 {
        return Err(Error::Authn(format!("userinfo returned {}", resp.status)));
    }
    resp.json()
}

/// Build a `private_key_jwt` client assertion (RFC 7523) for token-endpoint auth.
pub fn build_client_assertion(
    key: &SigningKey,
    client_id: &str,
    audience: &str,
) -> Result<String> {
    let now = now_secs();
    let mut c = Claims::default();
    c.iss = Some(client_id.to_string());
    c.sub = Some(client_id.to_string());
    c.aud = Some(Audience::Single(audience.to_string()));
    c.iat = Some(now);
    c.exp = Some(now + 300);
    c.jti = Some(crate::util::random_token(16));
    jwt::sign(key, &c, None)
}

fn apply_client_auth(
    client: &RpClient,
    provider: &ProviderInfo,
    form: &mut Vec<(String, String)>,
    headers: &mut Vec<(String, String)>,
) -> Result<()> {
    match &client.auth {
        ClientAuth::None => {}
        ClientAuth::ClientSecretPost(secret) => {
            form.push(("client_secret".into(), secret.clone()));
        }
        ClientAuth::ClientSecretBasic(secret) => {
            use base64::Engine;
            let raw = format!("{}:{}", urlencode(&client.client_id), urlencode(secret));
            let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            headers.push(("authorization".into(), format!("Basic {b64}")));
        }
        ClientAuth::PrivateKeyJwt(key) => {
            let assertion =
                build_client_assertion(key, &client.client_id, &provider.token_endpoint)?;
            form.push((
                "client_assertion_type".into(),
                CLIENT_ASSERTION_TYPE.to_string(),
            ));
            form.push(("client_assertion".into(), assertion));
        }
    }
    Ok(())
}

/// Convert a userinfo / id_token claims object into the proxy's external
/// attribute map shape (`name -> [values]`).
pub fn claims_to_attributes(claims: &serde_json::Value) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            let values = match v {
                serde_json::Value::String(s) => vec![s.clone()],
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                serde_json::Value::Number(n) => vec![n.to_string()],
                serde_json::Value::Bool(b) => vec![b.to_string()],
                _ => continue,
            };
            if !values.is_empty() {
                out.insert(k.clone(), values);
            }
        }
    }
    out
}
