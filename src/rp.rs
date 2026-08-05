//! The relying-party (client) side of OIDC/OAuth2 — used by the OIDC backend.
//!
//! Runtime-agnostic: outbound HTTP goes through the injected
//! [`crate::HttpClient`].

use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::jwt;
use crate::keys::SigningKey;
use crate::metadata::ProviderMetadata;
use crate::oauth_error::urlencode;
use crate::provider::CLIENT_ASSERTION_TYPE;
use crate::util::now_secs;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Audience, Claims, Validation};
use std::collections::BTreeMap;
use std::sync::Arc;

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

/// Build a signed request object (RFC 9101, "JAR") carrying the
/// authorization-request parameters as JWT claims.
///
/// OpenID Federation **automatic registration** needs this: a federation OP
/// authenticates the RP at the authorization endpoint by verifying the
/// request object against the keys published in the RP's resolved
/// `openid_relying_party` metadata, and implementations (e.g. the Shibboleth
/// OIDC OP plugin) use its presence as the trigger to resolve the RP's trust
/// chain on the fly. Pass the result as the `request` parameter — typically
/// via [`authorization_url`]'s `extra` — alongside the plain parameters so
/// OPs that ignore request objects keep working.
///
/// `key` must be (one of) the RP's published client keys; for a federation
/// RP that is the `private_key_jwt` key from its entity configuration.
#[allow(clippy::too_many_arguments)]
pub fn signed_request_object(
    provider: &ProviderInfo,
    client: &RpClient,
    key: &SigningKey,
    state: &str,
    nonce: &str,
    code_challenge: Option<&str>,
) -> Result<String> {
    let now = now_secs();
    let mut c = Claims::default();
    c.iss = Some(client.client_id.clone());
    c.aud = Some(Audience::Single(provider.issuer.clone()));
    c.iat = Some(now);
    c.exp = Some(now + 300);
    c.jti = Some(crate::util::random_token(16));
    let extra = &mut c.extra;
    extra.insert("client_id".into(), client.client_id.clone().into());
    extra.insert("redirect_uri".into(), client.redirect_uri.clone().into());
    extra.insert("scope".into(), client.scope.clone().into());
    extra.insert("response_type".into(), "code".into());
    extra.insert("state".into(), state.into());
    extra.insert("nonce".into(), nonce.into());
    if let Some(cc) = code_challenge {
        extra.insert("code_challenge".into(), cc.into());
        extra.insert("code_challenge_method".into(), "S256".into());
    }
    jwt::sign(key, &c, None)
}

/// Discover provider metadata from an issuer.
///
/// The issuer URL must be https (plain http is only accepted for loopback
/// hosts, for local development), and per OIDC Discovery §4.3 the `issuer`
/// returned in the metadata MUST match the requested issuer exactly.
pub async fn discover(http: &Arc<dyn HttpClient>, issuer: &str) -> Result<ProviderMetadata> {
    let issuer = issuer.trim_end_matches('/');
    let parsed = url::Url::parse(issuer)
        .map_err(|e| Error::BadRequest(format!("invalid issuer URL {issuer}: {e}")))?;
    let scheme_ok = parsed.scheme() == "https"
        || (parsed.scheme() == "http" && parsed.host_str().map(is_loopback_host).unwrap_or(false));
    if !scheme_ok {
        return Err(Error::BadRequest(format!(
            "issuer must be an https URL (http allowed only for loopback hosts): {issuer}"
        )));
    }
    let url = format!("{issuer}/.well-known/openid-configuration");
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "discovery failed ({}) for {url}",
            resp.status
        )));
    }
    let metadata: ProviderMetadata = resp.json()?;
    if metadata.issuer.trim_end_matches('/') != issuer {
        return Err(Error::Authn(format!(
            "discovered issuer {} does not match requested issuer {issuer}",
            metadata.issuer
        )));
    }
    Ok(metadata)
}

/// localhost / 127.0.0.1 / ::1 — the only hosts permitted over plain http.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Fetch a JWKS document.
pub async fn fetch_jwks(http: &Arc<dyn HttpClient>, jwks_uri: &str) -> Result<JwkSet> {
    let resp = http.get(jwks_uri).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "jwks fetch failed ({})",
            resp.status
        )));
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
            sanitize_error_body(&resp.text())
        )));
    }
    let raw: serde_json::Value = resp.json()?;
    Ok(TokenSet {
        access_token: raw
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from),
        id_token: raw
            .get("id_token")
            .and_then(|v| v.as_str())
            .map(String::from),
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
        .with_audience(client_id)
        .require_exp()
        .require_iat();
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
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {access_token}"),
    )];
    let resp = http.post_form(userinfo_endpoint, &[], &headers).await?;
    if resp.status != 200 {
        return Err(Error::Authn(format!("userinfo returned {}", resp.status)));
    }
    resp.json()
}

/// Build a `private_key_jwt` client assertion (RFC 7523) for token-endpoint auth.
pub fn build_client_assertion(key: &SigningKey, client_id: &str, audience: &str) -> Result<String> {
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

/// Sanitize an upstream token-endpoint error body before embedding it in our
/// error: control characters are stripped (log/terminal injection) and the
/// text is truncated to 512 chars so a hostile or broken OP cannot blow up our
/// logs or responses.
fn sanitize_error_body(body: &str) -> String {
    body.chars().filter(|c| !c.is_control()).take(512).collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::signing_key_from_jwk_json;

    fn client_and_provider() -> (RpClient, ProviderInfo, SigningKey) {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some("rp-1"))
            .unwrap();
        let client = RpClient {
            client_id: "https://rp.example.com".into(),
            redirect_uri: "https://rp.example.com/callback".into(),
            auth: ClientAuth::PrivateKeyJwt(key.clone()),
            scope: "openid email".into(),
        };
        let provider = ProviderInfo {
            issuer: "https://op.example.org".into(),
            authorization_endpoint: "https://op.example.org/authorize".into(),
            token_endpoint: "https://op.example.org/token".into(),
            userinfo_endpoint: None,
            jwks_uri: None,
        };
        (client, provider, key)
    }

    #[test]
    fn signed_request_object_carries_request_params_and_verifies() {
        let (client, provider, key) = client_and_provider();
        let jar =
            signed_request_object(&provider, &client, &key, "st-1", "n-1", Some("chal")).unwrap();

        // Verifies against the RP's published public keys, audience = OP issuer.
        let validation = Validation::new()
            .with_issuer(&client.client_id)
            .with_audience(&provider.issuer);
        let claims = jwt::verify_with_jwks(&key.to_public_jwks(), &jar, &validation).unwrap();

        assert_eq!(claims.extra["client_id"], client.client_id);
        assert_eq!(claims.extra["redirect_uri"], client.redirect_uri);
        assert_eq!(claims.extra["response_type"], "code");
        assert_eq!(claims.extra["scope"], "openid email");
        assert_eq!(claims.extra["state"], "st-1");
        assert_eq!(claims.extra["nonce"], "n-1");
        assert_eq!(claims.extra["code_challenge"], "chal");
        assert_eq!(claims.extra["code_challenge_method"], "S256");
        assert!(claims.jti.is_some(), "jti for replay detection");
        let (iat, exp) = (claims.iat.unwrap(), claims.exp.unwrap());
        assert!(exp > iat && exp <= iat + 300);

        // Header: alg + kid, no typ (interop with Shibboleth's OIDC plugin,
        // which expects a plain JWT request object).
        let header = jwt::peek_header(&jar).unwrap();
        assert_eq!(header.kid.as_deref(), Some("rp-1"));
        assert!(header.typ.is_none());
    }

    #[test]
    fn signed_request_object_omits_pkce_when_absent() {
        let (client, provider, key) = client_and_provider();
        let jar = signed_request_object(&provider, &client, &key, "st", "n", None).unwrap();
        let claims = jwt::peek_claims_unverified(&jar).unwrap();
        assert!(!claims.extra.contains_key("code_challenge"));
        assert!(!claims.extra.contains_key("code_challenge_method"));
    }

    /// Minimal in-memory [`HttpClient`] for discovery / token-endpoint tests.
    struct MockHttp {
        get: Option<crate::http::HttpFetchResponse>,
        post: Option<crate::http::HttpFetchResponse>,
    }

    #[async_trait::async_trait]
    impl HttpClient for MockHttp {
        async fn get(&self, _url: &str) -> Result<crate::http::HttpFetchResponse> {
            self.get
                .clone()
                .ok_or_else(|| Error::Internal("unexpected GET".into()))
        }

        async fn post_form(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            self.post
                .clone()
                .ok_or_else(|| Error::Internal("unexpected POST".into()))
        }
    }

    fn metadata_response(issuer: &str) -> crate::http::HttpFetchResponse {
        let metadata = ProviderMetadata::new(issuer, issuer);
        crate::http::HttpFetchResponse {
            status: 200,
            body: serde_json::to_vec(&metadata).unwrap(),
            content_type: Some("application/json".into()),
        }
    }

    #[tokio::test]
    async fn discover_rejects_plain_http_for_non_loopback() {
        // The mock has no GET response: the request must be refused before any
        // fetch happens.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: None,
        });
        assert!(discover(&http, "http://op.example.com").await.is_err());
    }

    #[tokio::test]
    async fn discover_allows_http_for_loopback() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("http://127.0.0.1:8080")),
            post: None,
        });
        let metadata = discover(&http, "http://127.0.0.1:8080").await.unwrap();
        assert_eq!(metadata.issuer, "http://127.0.0.1:8080");
    }

    #[tokio::test]
    async fn discover_rejects_issuer_mismatch() {
        // OIDC Discovery §4.3: the returned issuer must match the requested one.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("https://evil.example.com")),
            post: None,
        });
        assert!(discover(&http, "https://op.example.com").await.is_err());
    }

    #[tokio::test]
    async fn exchange_code_error_body_is_sanitized() {
        let (client, provider, _key) = client_and_provider();
        // A hostile upstream: >512 chars, laced with ANSI escapes and newlines.
        let body = "oops\x1b[31m\n".repeat(200);
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: Some(crate::http::HttpFetchResponse {
                status: 400,
                body: body.into_bytes(),
                content_type: None,
            }),
        });
        let err = exchange_code(&http, &provider, &client, "code-1", None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.len() < 600,
            "upstream body must be truncated: {}",
            msg.len()
        );
        assert!(
            !msg.chars().any(|c| c.is_control()),
            "control characters must be stripped: {msg:?}"
        );
    }

    #[test]
    fn verify_id_token_requires_exp_and_iat() {
        let (_client, _provider, key) = client_and_provider();
        let jwks = key.to_public_jwks();
        let now = now_secs();

        // No exp -> rejected.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.iat = Some(now);
        let token = jwt::sign(&key, &c, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                "https://rp.example.com",
                None
            )
            .is_err(),
            "id_token without exp must be rejected"
        );

        // No iat -> rejected.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.exp = Some(now + 300);
        let token = jwt::sign(&key, &c, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                "https://rp.example.com",
                None
            )
            .is_err(),
            "id_token without iat must be rejected"
        );

        // Both present -> accepted.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.iat = Some(now);
        c.exp = Some(now + 300);
        let token = jwt::sign(&key, &c, None).unwrap();
        verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
        )
        .unwrap();
    }
}
