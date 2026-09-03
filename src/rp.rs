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
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Audience, Claims, Validation};
use std::collections::{BTreeMap, BTreeSet};
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

impl ProviderInfo {
    /// Validate every endpoint before it can receive requests or credentials.
    pub fn validate(&self) -> Result<()> {
        validate_issuer(&self.issuer)?;
        validate_service_endpoint("authorization_endpoint", &self.authorization_endpoint)?;
        validate_authorization_endpoint_query(&self.authorization_endpoint)?;
        validate_service_endpoint("token_endpoint", &self.token_endpoint)?;
        if let Some(endpoint) = self.userinfo_endpoint.as_deref() {
            validate_service_endpoint("userinfo_endpoint", endpoint)?;
        }
        if let Some(endpoint) = self.jwks_uri.as_deref() {
            validate_service_endpoint("jwks_uri", endpoint)?;
        }
        Ok(())
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
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
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
) -> Result<String> {
    provider.validate()?;
    validate_redirect_uri(&client.redirect_uri)?;
    if !client
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        return Err(Error::BadRequest(
            "OIDC authorization requests require the openid scope".into(),
        ));
    }
    if matches!(&client.auth, ClientAuth::None) && code_challenge.is_none() {
        return Err(Error::BadRequest(
            "public clients must use S256 PKCE".into(),
        ));
    }
    if let Some(challenge) = code_challenge {
        if !crate::pkce::is_valid_s256_challenge(challenge) {
            return Err(Error::BadRequest("invalid S256 code_challenge".into()));
        }
    }
    validate_authorization_extras(&provider.authorization_endpoint, extra)?;
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
    Ok(format!("{}{}{}", provider.authorization_endpoint, sep, qs))
}

fn validate_authorization_extras(endpoint: &str, extra: &[(&str, &str)]) -> Result<()> {
    const RESERVED: &[&str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ];
    // Seed the set from configured endpoint parameters so an application
    // cannot accidentally append a second, conflicting vendor parameter.
    let parsed = url::Url::parse(endpoint)
        .map_err(|e| Error::BadRequest(format!("invalid authorization_endpoint: {e}")))?;
    let mut seen = parsed
        .query_pairs()
        .filter(|(name, _)| name != "resource")
        .map(|(name, _)| name.into_owned())
        .collect::<BTreeSet<_>>();
    for (name, _) in extra {
        if RESERVED.contains(name) {
            return Err(Error::BadRequest(format!(
                "authorization extra parameter {name} is library-controlled"
            )));
        }
        // RFC 8707 permits repeated resource parameters. Other extension
        // parameters must remain unambiguous.
        if *name != "resource" && !seen.insert((*name).to_string()) {
            return Err(Error::BadRequest(format!(
                "duplicate authorization extra parameter: {name}"
            )));
        }
    }
    Ok(())
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
    provider.validate()?;
    validate_redirect_uri(&client.redirect_uri)?;
    if !client
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        return Err(Error::BadRequest(
            "OIDC authorization requests require the openid scope".into(),
        ));
    }
    if matches!(&client.auth, ClientAuth::None) && code_challenge.is_none() {
        return Err(Error::BadRequest(
            "public clients must use S256 PKCE".into(),
        ));
    }
    if let Some(challenge) = code_challenge {
        if !crate::pkce::is_valid_s256_challenge(challenge) {
            return Err(Error::BadRequest("invalid S256 code_challenge".into()));
        }
    }
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
    let requested_issuer = issuer;
    validate_issuer(requested_issuer)?;
    let discovery_prefix = requested_issuer.trim_end_matches('/');
    let url = format!("{discovery_prefix}/.well-known/openid-configuration");
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "discovery failed ({}) for {url}",
            resp.status
        )));
    }
    let metadata: ProviderMetadata = resp.json()?;
    if metadata.issuer != requested_issuer {
        return Err(Error::Authn(format!(
            "discovered issuer {} does not match requested issuer {requested_issuer}",
            metadata.issuer
        )));
    }
    ProviderInfo::from(metadata.clone()).validate()?;
    Ok(metadata)
}

/// localhost / 127.0.0.1 / ::1 — the only hosts permitted over plain http.
/// `Url::host_str` serializes IPv6 hosts in bracketed form (`[::1]`), so the
/// brackets are stripped before parsing as an address.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Require an absolute HTTPS endpoint. Plain HTTP is supported only for
/// loopback development servers, matching the issuer exception.
pub fn validate_service_endpoint(name: &str, endpoint: &str) -> Result<()> {
    // The URL parser discards some raw whitespace and control characters.
    // Reject them first because callers send or return the original string,
    // and validation must describe the same bytes that reach the sink.
    if endpoint
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(Error::BadRequest(format!(
            "{name} must not contain whitespace or control characters"
        )));
    }
    let parsed = url::Url::parse(endpoint)
        .map_err(|e| Error::BadRequest(format!("invalid {name} URL {endpoint}: {e}")))?;
    let scheme_ok = parsed.scheme() == "https"
        || (parsed.scheme() == "http" && parsed.host_str().is_some_and(is_loopback_host));
    if !scheme_ok || parsed.host_str().is_none() {
        return Err(Error::BadRequest(format!(
            "{name} must be an absolute https URL (http allowed only for loopback hosts): {endpoint}"
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::BadRequest(format!(
            "{name} must not contain userinfo: {endpoint}"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(Error::BadRequest(format!(
            "{name} must not contain a fragment: {endpoint}"
        )));
    }
    Ok(())
}

fn validate_authorization_endpoint_query(endpoint: &str) -> Result<()> {
    const RESERVED: &[&str] = &[
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ];
    let parsed = url::Url::parse(endpoint)
        .map_err(|e| Error::BadRequest(format!("invalid authorization_endpoint: {e}")))?;
    let mut seen = BTreeSet::new();
    for (name, _) in parsed.query_pairs() {
        if RESERVED.contains(&name.as_ref()) {
            return Err(Error::BadRequest(format!(
                "authorization_endpoint query parameter {name} is library-controlled"
            )));
        }
        if name != "resource" && !seen.insert(name.into_owned()) {
            return Err(Error::BadRequest(
                "authorization_endpoint contains duplicate query parameters".into(),
            ));
        }
    }
    Ok(())
}

fn validate_issuer(issuer: &str) -> Result<()> {
    validate_service_endpoint("issuer", issuer)?;
    let parsed = url::Url::parse(issuer)
        .map_err(|e| Error::BadRequest(format!("invalid issuer URL {issuer}: {e}")))?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::BadRequest(
            "issuer URL must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}

fn validate_redirect_uri(redirect_uri: &str) -> Result<()> {
    let parsed = url::Url::parse(redirect_uri)
        .map_err(|e| Error::BadRequest(format!("invalid redirect_uri {redirect_uri}: {e}")))?;
    if parsed.fragment().is_some() {
        return Err(Error::BadRequest(
            "redirect_uri must not contain a fragment".into(),
        ));
    }
    Ok(())
}

/// Fetch a JWKS document.
pub async fn fetch_jwks(http: &Arc<dyn HttpClient>, jwks_uri: &str) -> Result<JwkSet> {
    validate_service_endpoint("jwks_uri", jwks_uri)?;
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
    provider.validate()?;
    validate_redirect_uri(&client.redirect_uri)?;
    if matches!(&client.auth, ClientAuth::None) && code_verifier.is_none() {
        return Err(Error::BadRequest(
            "public clients must supply a PKCE code_verifier".into(),
        ));
    }
    if let Some(verifier) = code_verifier {
        if !crate::pkce::is_valid_verifier(verifier) {
            return Err(Error::BadRequest("invalid PKCE code_verifier".into()));
        }
    }
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
    let access_token = raw
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Authn("token response missing access_token".into()))?;
    let id_token = raw
        .get("id_token")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Authn("token response missing id_token".into()))?;
    let token_type = raw
        .get("token_type")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from)
        .ok_or_else(|| Error::Authn("token response missing token_type".into()))?;
    // This RP currently sends access tokens using the Bearer scheme. RFC 6749
    // section 7.1 forbids using a token type the client does not understand.
    if !token_type.eq_ignore_ascii_case("Bearer") {
        return Err(Error::Authn(format!(
            "unsupported token_type in token response: {token_type}"
        )));
    }
    Ok(TokenSet {
        access_token,
        id_token,
        token_type,
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
    allowed_algorithms: &[JwsAlgorithm],
    trusted_additional_audiences: &[&str],
) -> Result<Claims> {
    if allowed_algorithms.is_empty() {
        return Err(Error::BadRequest(
            "at least one allowed id_token signing algorithm is required".into(),
        ));
    }
    let validation = Validation::new()
        .with_issuer(issuer)
        .with_audience(client_id)
        .require_exp()
        .require_iat()
        .with_allowed_algorithms(allowed_algorithms.to_vec());
    let claims = jwt::verify_with_jwks(jwks, id_token, &validation)?;

    if claims.sub.as_deref().is_none_or(str::is_empty) {
        return Err(Error::Authn("id_token missing sub".into()));
    }
    if let Some(Audience::Multiple(values)) = claims.aud.as_ref() {
        let mut seen = BTreeSet::new();
        for audience in values {
            if !seen.insert(audience) {
                return Err(Error::Authn("id_token contains duplicate audiences".into()));
            }
            if audience != client_id
                && !trusted_additional_audiences
                    .iter()
                    .any(|trusted| audience == trusted)
            {
                return Err(Error::Authn(format!(
                    "id_token contains untrusted audience: {audience}"
                )));
            }
        }
        if values.len() > 1
            && claims.extra.get("azp").and_then(|value| value.as_str()) != Some(client_id)
        {
            return Err(Error::Authn(
                "multi-audience id_token requires azp equal to client_id".into(),
            ));
        }
    }
    if let Some(azp) = claims.extra.get("azp") {
        if azp.as_str() != Some(client_id) {
            return Err(Error::Authn("id_token azp mismatch".into()));
        }
    }

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
    expected_sub: &str,
) -> Result<serde_json::Value> {
    validate_service_endpoint("userinfo_endpoint", userinfo_endpoint)?;
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
    let claims: serde_json::Value = resp.json()?;
    if claims.get("sub").and_then(|value| value.as_str()) != Some(expected_sub) {
        return Err(Error::Authn(
            "userinfo sub does not match the validated id_token subject".into(),
        ));
    }
    Ok(claims)
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
    fn service_endpoints_reject_raw_whitespace_and_controls() {
        for endpoint in [
            "https://op.example.\torg/token",
            "ht\ntps://op.example.org/token",
            " https://op.example.org/token",
            "https://op.example.org/token\x1f",
            "https://op.example.org/token\r\nX-Test: injected",
        ] {
            assert!(
                validate_service_endpoint("token_endpoint", endpoint).is_err(),
                "unsafe raw endpoint must be rejected: {endpoint:?}"
            );
        }

        // Encoded octets do not create a parser/use mismatch, and the existing
        // endpoint query and loopback-development policies remain unchanged.
        for endpoint in [
            "https://op.example.org/token?label=hello%20world",
            "https://op.example.org/%09/%0A",
            "http://localhost:8080/token",
            "http://127.0.0.1:8080/token",
            "http://[::1]:8080/token",
        ] {
            validate_service_endpoint("token_endpoint", endpoint)
                .unwrap_or_else(|error| panic!("valid endpoint {endpoint:?}: {error}"));
        }
    }

    #[test]
    fn provider_info_rejects_controls_in_every_endpoint_field() {
        let (_, provider, _) = client_and_provider();
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ] {
            let mut contaminated = provider.clone();
            let endpoint = "https://op.example.org/path\r\nX-Test: injected".to_string();
            match field {
                "issuer" => contaminated.issuer = endpoint,
                "authorization_endpoint" => contaminated.authorization_endpoint = endpoint,
                "token_endpoint" => contaminated.token_endpoint = endpoint,
                "userinfo_endpoint" => contaminated.userinfo_endpoint = Some(endpoint),
                "jwks_uri" => contaminated.jwks_uri = Some(endpoint),
                _ => unreachable!(),
            }
            assert!(
                contaminated.validate().is_err(),
                "unsafe {field} must be rejected"
            );
        }
    }

    #[test]
    fn signed_request_object_carries_request_params_and_verifies() {
        let (client, provider, key) = client_and_provider();
        let challenge = crate::pkce::s256_challenge(&"v".repeat(43));
        let jar = signed_request_object(&provider, &client, &key, "st-1", "n-1", Some(&challenge))
            .unwrap();

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
        assert_eq!(claims.extra["code_challenge"], challenge);
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

    #[test]
    fn authorization_url_rejects_query_collisions_across_configuration_and_extras() {
        let (client, mut provider, _) = client_and_provider();
        provider.authorization_endpoint =
            "https://op.example.org/authorize?tenant=configured".into();

        let err = authorization_url(
            &provider,
            &client,
            "state",
            "nonce",
            None,
            &[("tenant", "override")],
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate authorization extra"));

        // RFC 8707 deliberately permits repeated resource indicators.
        let url = authorization_url(
            &provider,
            &client,
            "state",
            "nonce",
            None,
            &[("resource", "https://api.example.org")],
        )
        .unwrap();
        assert!(url.contains("tenant=configured"));
        assert!(url.contains("resource=https%3A%2F%2Fapi.example.org"));
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
    async fn discover_allows_http_for_ipv6_loopback() {
        // Url::host_str yields the bracketed form ("[::1]"); it must still be
        // recognized as loopback.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("http://[::1]:8080")),
            post: None,
        });
        let metadata = discover(&http, "http://[::1]:8080").await.unwrap();
        assert_eq!(metadata.issuer, "http://[::1]:8080");

        // Non-loopback IPv6 stays rejected over plain http.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: None,
        });
        assert!(discover(&http, "http://[2001:db8::1]").await.is_err());
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
        c.sub = Some("subject".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.iat = Some(now);
        let token = jwt::sign(&key, &c, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                "https://rp.example.com",
                None,
                &[JwsAlgorithm::ES256],
                &[],
            )
            .is_err(),
            "id_token without exp must be rejected"
        );

        // No iat -> rejected.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.sub = Some("subject".into());
        c.aud = Some(Audience::Single("https://rp.example.com".into()));
        c.exp = Some(now + 300);
        let token = jwt::sign(&key, &c, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                "https://rp.example.com",
                None,
                &[JwsAlgorithm::ES256],
                &[],
            )
            .is_err(),
            "id_token without iat must be rejected"
        );

        // Both present -> accepted.
        let mut c = Claims::default();
        c.iss = Some("https://op.example.org".into());
        c.sub = Some("subject".into());
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
            &[JwsAlgorithm::ES256],
            &[],
        )
        .unwrap();
    }

    #[test]
    fn verify_id_token_accepts_single_element_array_audience_without_azp() {
        let (_client, _provider, key) = client_and_provider();
        let jwks = key.to_public_jwks();
        let now = now_secs();
        let client_id = "https://rp.example.com";

        let mut claims = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Multiple(vec![client_id.into()])),
            iat: Some(now),
            exp: Some(now + 300),
            ..Default::default()
        };
        let token = jwt::sign(&key, &claims, None).unwrap();
        verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            client_id,
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .expect("a one-element aud array does not require azp");

        // An azp claim is optional for one audience, but still must identify
        // this client when the issuer includes it.
        claims.extra.insert("azp".into(), "another-client".into());
        let token = jwt::sign(&key, &claims, None).unwrap();
        assert!(
            verify_id_token(
                &jwks,
                &token,
                "https://op.example.org",
                client_id,
                None,
                &[JwsAlgorithm::ES256],
                &[],
            )
            .is_err(),
            "a supplied azp must match client_id"
        );
    }
}
