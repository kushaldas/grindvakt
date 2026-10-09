//! The relying-party (client) side of OIDC/OAuth2 — used by the OIDC backend.
//!
//! Runtime-agnostic: outbound HTTP goes through the injected
//! [`crate::HttpClient`].

use crate::error::{
    display_safe, escape_upstream_text, is_invisible_format, parse_www_authenticate_bearer,
    quotes_balanced, split_unquoted_commas, Error, Result, UpstreamHttpError,
};
use crate::http::{HttpClient, HttpFetchResponse};
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
            userinfo_endpoint: m.userinfo_endpoint,
            jwks_uri: Some(m.jwks_uri),
        }
    }
}

impl ProviderInfo {
    /// The advertised `userinfo_endpoint`, or `Error::Config` when the
    /// provider does not advertise one (it is optional in OIDC Discovery).
    pub fn require_userinfo_endpoint(&self) -> Result<&str> {
        self.userinfo_endpoint
            .as_deref()
            .ok_or_else(|| Error::Config("provider does not advertise a userinfo_endpoint".into()))
    }

    /// The advertised `jwks_uri`, or `Error::Config` when the provider does
    /// not advertise one.
    pub fn require_jwks_uri(&self) -> Result<&str> {
        self.jwks_uri
            .as_deref()
            .ok_or_else(|| Error::Config("provider does not advertise a jwks_uri".into()))
    }

    /// Validate every endpoint before it can receive requests or credentials.
    pub fn validate(&self) -> Result<()> {
        validate_issuer(&self.issuer)?;
        validate_service_endpoint_for_issuer(
            "authorization_endpoint",
            &self.authorization_endpoint,
            &self.issuer,
        )?;
        validate_authorization_endpoint_query(&self.authorization_endpoint)?;
        validate_service_endpoint_for_issuer("token_endpoint", &self.token_endpoint, &self.issuer)?;
        if let Some(endpoint) = self.userinfo_endpoint.as_deref() {
            validate_service_endpoint_for_issuer("userinfo_endpoint", endpoint, &self.issuer)?;
        }
        if let Some(endpoint) = self.jwks_uri.as_deref() {
            validate_service_endpoint_for_issuer("jwks_uri", endpoint, &self.issuer)?;
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
    validate_redirect_uri_syntax(&client.redirect_uri)?;
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
                "authorization extra parameter {} is library-controlled",
                display_safe(name)
            )));
        }
        // RFC 8707 permits repeated resource parameters. Other extension
        // parameters must remain unambiguous.
        if *name != "resource" && !seen.insert((*name).to_string()) {
            return Err(Error::BadRequest(format!(
                "duplicate authorization extra parameter: {}",
                display_safe(name)
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
    validate_redirect_uri_syntax(&client.redirect_uri)?;
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
        return Err(upstream_error(
            UpstreamKind::Metadata,
            format!(
                "discovery failed ({}) for {}",
                resp.status,
                display_safe(&url)
            ),
            &resp,
        ));
    }
    let metadata: ProviderMetadata = resp.json()?;
    if metadata.issuer != requested_issuer {
        return Err(Error::Authn(format!(
            "discovered issuer {} does not match requested issuer {}",
            display_safe(&metadata.issuer),
            display_safe(requested_issuer)
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

fn validate_endpoint(name: &str, endpoint: &str, allow_loopback_http: bool) -> Result<()> {
    // The URL parser discards some raw whitespace and control characters.
    // Reject them first because callers send or return the original string,
    // and validation must describe the same bytes that reach the sink.
    if endpoint.chars().any(|character| {
        character.is_whitespace() || character.is_control() || is_invisible_format(character)
    }) {
        return Err(Error::BadRequest(format!(
            "{name} must not contain whitespace, control, bidi or invisible formatting characters"
        )));
    }
    let parsed = url::Url::parse(endpoint).map_err(|e| {
        Error::BadRequest(format!(
            "invalid {name} URL {}: {e}",
            display_safe(endpoint)
        ))
    })?;
    let scheme_ok = parsed.scheme() == "https"
        || (allow_loopback_http
            && parsed.scheme() == "http"
            && parsed.host_str().is_some_and(is_loopback_host));
    if !scheme_ok || parsed.host_str().is_none() {
        let policy = if allow_loopback_http {
            "an absolute https URL (http allowed only for loopback hosts)"
        } else {
            "an absolute https URL"
        };
        return Err(Error::BadRequest(format!(
            "{name} must be {policy}: {}",
            display_safe(endpoint)
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::BadRequest(format!(
            "{name} must not contain userinfo: {}",
            display_safe(endpoint)
        )));
    }
    if parsed.fragment().is_some() {
        return Err(Error::BadRequest(format!(
            "{name} must not contain a fragment: {}",
            display_safe(endpoint)
        )));
    }
    Ok(())
}

/// Require an absolute HTTPS endpoint.
///
/// This context-free validator deliberately does not permit loopback HTTP: a
/// metadata-derived endpoint can only use the development exception when its
/// associated issuer or entity identifier is also a loopback HTTP origin.
pub fn validate_service_endpoint(name: &str, endpoint: &str) -> Result<()> {
    validate_endpoint(name, endpoint, false)
}

fn issuer_allows_loopback_http(issuer: &str) -> bool {
    if issuer.chars().any(|character| {
        character.is_whitespace() || character.is_control() || is_invisible_format(character)
    }) {
        return false;
    }
    url::Url::parse(issuer).is_ok_and(|parsed| {
        parsed.scheme() == "http"
            && parsed.host_str().is_some_and(is_loopback_host)
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
    })
}

/// Validate a metadata endpoint relative to its authenticated issuer/entity.
///
/// The endpoint must be an `https` URL; loopback `http` is allowed only when
/// `issuer` itself is a loopback `http` origin. `name` is used in error
/// messages. This does not validate `issuer`; call [`validate_issuer`] first.
/// It does not establish that `issuer` or the endpoint is trusted, only that
/// the endpoint's scheme is acceptable for that issuer.
pub fn validate_service_endpoint_for_issuer(
    name: &str,
    endpoint: &str,
    issuer: &str,
) -> Result<()> {
    validate_endpoint(name, endpoint, issuer_allows_loopback_http(issuer))
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
                "authorization_endpoint query parameter {} is library-controlled",
                display_safe(&name)
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

/// Validate an issuer identifier.
///
/// It must be an absolute `https` URL (`http` is accepted only for loopback
/// hosts) with no whitespace, control, bidi or invisible formatting
/// characters (zero-width characters, soft hyphen, BOM and similar, which make
/// look-alike URLs), userinfo, query or fragment. It checks syntax only: it does not establish that the issuer is
/// trusted or that discovery metadata matches it.
pub fn validate_issuer(issuer: &str) -> Result<()> {
    validate_endpoint("issuer", issuer, true)?;
    let parsed = url::Url::parse(issuer).map_err(|e| {
        Error::BadRequest(format!("invalid issuer URL {}: {e}", display_safe(issuer)))
    })?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::BadRequest(
            "issuer URL must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}

/// Check the syntax of a redirect URI.
///
/// This only checks that it parses as an absolute URL and carries no
/// fragment. The scheme is not checked, so custom/native-app schemes such as
/// `com.example.app:/cb` are accepted, and so are `http://attacker.example`,
/// `javascript:` and `file:` URIs.
///
/// It does **not** make a URI safe to register or redirect to. Do not use it
/// to vet client-registered redirect URIs on an OP: apply an https or scheme
/// allow-list and compare redirect URIs by exact match.
pub fn validate_redirect_uri_syntax(redirect_uri: &str) -> Result<()> {
    let parsed = url::Url::parse(redirect_uri).map_err(|e| {
        Error::BadRequest(format!(
            "invalid redirect_uri {}: {e}",
            display_safe(redirect_uri)
        ))
    })?;
    if parsed.fragment().is_some() {
        return Err(Error::BadRequest(
            "redirect_uri must not contain a fragment".into(),
        ));
    }
    Ok(())
}

/// Fetch a JWKS document for an associated issuer.
///
/// The issuer context is mandatory because the loopback HTTP development
/// exception applies only when the issuer itself is a loopback HTTP origin.
pub async fn fetch_jwks(
    http: &Arc<dyn HttpClient>,
    jwks_uri: &str,
    issuer: &str,
) -> Result<JwkSet> {
    fetch_jwks_response(http, jwks_uri, issuer)
        .await
        .map(|r| r.jwks)
}

/// Ceiling in seconds applied by [`JwksResponse::cache_ttl_secs`]: 24 hours.
/// Key rotation and revocation must take effect within this window no matter
/// what the upstream advertises.
pub const MAX_JWKS_CACHE_TTL_SECS: u64 = 86_400;

/// A fetched JWK Set plus the response metadata needed to cache it.
///
/// The library does no caching itself. Applications that cache the key set
/// should cap or choose their own TTLs (see [`JwksResponse::cache_ttl_secs`])
/// and must not cache error responses.
#[derive(Debug, Clone)]
pub struct JwksResponse {
    pub jwks: JwkSet,
    /// Raw `Cache-Control` header value, if any.
    pub cache_control: Option<String>,
    /// Raw `ETag` header value, if any.
    pub etag: Option<String>,
    /// Seconds the response already spent in an upstream cache (`Age` header,
    /// RFC 9111 §5.1), if present and a valid non-negative integer.
    pub age: Option<u64>,
}

impl JwksResponse {
    /// Remaining freshness in seconds, capped at [`MAX_JWKS_CACHE_TTL_SECS`]
    /// (24 hours).
    ///
    /// This is the advertised lifetime ([`JwksResponse::advertised_ttl_secs`])
    /// minus [`JwksResponse::age`], saturating at 0, and then limited to the
    /// ceiling, so an upstream cannot pin a key set (and with it a revoked
    /// signing key) for a year by advertising `max-age=31536000`. With
    /// `Age: 3000` and `Cache-Control: max-age=3600` this is 600. `Some(0)` for
    /// `no-store`/`no-cache`; `None` when `Cache-Control` gives no usable
    /// lifetime, so the caller picks its own default (and should also bound
    /// it). Use [`JwksResponse::cache_ttl_secs_max`] for a different ceiling.
    pub fn cache_ttl_secs(&self) -> Option<u64> {
        self.cache_ttl_secs_max(MAX_JWKS_CACHE_TTL_SECS)
    }

    /// Like [`JwksResponse::cache_ttl_secs`] with a caller-chosen ceiling in
    /// seconds.
    pub fn cache_ttl_secs_max(&self, ceiling: u64) -> Option<u64> {
        self.advertised_ttl_secs()
            .map(|ttl| ttl.saturating_sub(self.age.unwrap_or(0)).min(ceiling))
    }

    /// Freshness lifetime in seconds as advertised by `Cache-Control`, ignoring
    /// `Age` and **not capped**: a hostile or misconfigured upstream controls
    /// this value, so do not cache on it directly; use
    /// [`JwksResponse::cache_ttl_secs`]. A digits-only `max-age` too large for
    /// `u64` saturates to `u64::MAX` rather than being ignored.
    ///
    /// Returns `Some(0)` when `no-store` or `no-cache` is present, otherwise
    /// the `max-age` value. Directive names are case-insensitive, a quoted
    /// `max-age="N"` is tolerated and the first valid `max-age` wins.
    /// `s-maxage` is ignored because this is a private client cache. Returns
    /// `None` when the header is absent or has no usable directive. Malformed
    /// input never panics.
    pub fn advertised_ttl_secs(&self) -> Option<u64> {
        let header = self.cache_control.as_deref()?;
        // An unterminated quote hides every later directive (a `no-store` after
        // it would be swallowed): treat the field as unusable, fail closed.
        if !quotes_balanced(header) {
            return Some(0);
        }
        let mut max_age = None;
        for directive in split_unquoted_commas(header) {
            let directive = directive.trim();
            let (name, value) = match directive.split_once('=') {
                Some((n, v)) => (n.trim(), Some(v.trim())),
                None => (directive, None),
            };
            if name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache") {
                return Some(0);
            }
            if max_age.is_none() && name.eq_ignore_ascii_case("max-age") {
                max_age = value
                    .map(|v| v.trim_matches('"'))
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .map(|v| v.parse::<u64>().unwrap_or(u64::MAX));
            }
        }
        max_age
    }
}

/// Like [`fetch_jwks`] but also returns `Cache-Control` and `ETag` so callers
/// can cache the key set.
///
/// The library does no caching itself. Take lifetimes from
/// [`JwksResponse::cache_ttl_secs`], which is capped at
/// [`MAX_JWKS_CACHE_TTL_SECS`], and bound any default you pick when it returns
/// `None`: an unbounded cache stops key rotation and revocation from taking
/// effect. Do not cache error responses. This relies on the [`HttpClient`] filling
/// [`HttpFetchResponse::headers`]; without it both fields are `None`.
pub async fn fetch_jwks_response(
    http: &Arc<dyn HttpClient>,
    jwks_uri: &str,
    issuer: &str,
) -> Result<JwksResponse> {
    validate_issuer(issuer)?;
    validate_service_endpoint_for_issuer("jwks_uri", jwks_uri, issuer)?;
    let resp = http.get(jwks_uri).await?;
    if resp.status != 200 {
        return Err(upstream_error(
            UpstreamKind::Metadata,
            format!("jwks fetch failed ({})", resp.status),
            &resp,
        ));
    }
    let jwks = JwkSet::from_json(&resp.text()).map_err(Error::from)?;
    Ok(JwksResponse {
        jwks,
        cache_control: resp.cache_control(),
        etag: resp.header("etag").map(str::to_string),
        age: resp
            .header("age")
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            // A digits-only value too large for u64 means "very old": saturate
            // so no freshness remains, instead of reading it as no Age at all.
            .map(|v| v.parse::<u64>().unwrap_or(u64::MAX)),
    })
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
    validate_redirect_uri_syntax(&client.redirect_uri)?;
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
        return Err(upstream_error(
            UpstreamKind::Auth,
            format!("token endpoint returned {}", resp.status),
            &resp,
        ));
    }
    let raw: serde_json::Value = resp.json()?;
    // A broken OP can answer 200 with an RFC 6749 §5.2 error body.
    if raw.get("error").is_some_and(serde_json::Value::is_string)
        && raw.get("access_token").is_none()
    {
        return Err(upstream_error(
            UpstreamKind::Auth,
            format!(
                "token endpoint returned an error with status {}",
                resp.status
            ),
            &resp,
        ));
    }
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
            "unsupported token_type in token response: {}",
            display_safe(&token_type)
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
///
/// When `jwks` holds more than one key the id_token must carry a `kid`, as
/// OIDC Core §10.1 requires; a set with a single key needs none.
///
/// Uses jose-rs's default 60-second clock-skew leeway. See
/// [`verify_id_token_with`] to tune the leeway or to enforce `max_age`, `acr`
/// and `at_hash`.
pub fn verify_id_token(
    jwks: &JwkSet,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    allowed_algorithms: &[JwsAlgorithm],
    trusted_additional_audiences: &[&str],
) -> Result<Claims> {
    verify_id_token_with(
        jwks,
        id_token,
        issuer,
        client_id,
        expected_nonce,
        allowed_algorithms,
        trusted_additional_audiences,
        &IdTokenOptions::default().allow_unchecked_hashes(),
    )
}

/// Mirrors jose-rs `Validation::default()`'s leeway (seconds); used for the
/// `auth_time` checks when [`IdTokenOptions::leeway`] is `None`.
const DEFAULT_LEEWAY: u64 = 60;

/// Largest accepted [`IdTokenOptions::leeway`] (seconds). Skew tolerance is
/// meant to absorb clock drift, not to revive expired id_tokens; larger values
/// are rejected as a configuration error.
pub const MAX_ID_TOKEN_LEEWAY: u64 = 300;

/// Extra id_token checks for [`verify_id_token_with`].
///
/// The struct is `#[non_exhaustive]`: construct it with [`IdTokenOptions::new`]
/// and the `with_*` builders.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct IdTokenOptions<'a> {
    /// Clock-skew tolerance (seconds) for exp/nbf/iat and the future-`auth_time`
    /// check. None = jose-rs default (60s). Values above
    /// [`MAX_ID_TOKEN_LEEWAY`] are rejected with `Error::BadRequest`. It is not
    /// added to `max_age`.
    pub leeway: Option<u64>,
    /// OIDC max_age: requires numeric `auth_time` with now <= auth_time + max_age.
    /// Clock-skew leeway is deliberately not added to the session age.
    pub max_age: Option<u64>,
    /// If set, `acr` must be present (string) and in this list. Empty list = configuration error (Error::BadRequest).
    pub acr_values: Option<&'a [&'a str]>,
    /// If set and the token has `at_hash`, it must equal oidc_token_hash(header alg, access_token).
    /// A token without `at_hash` is accepted unless `require_at_hash` is set.
    pub access_token: Option<&'a str>,
    /// Fail when the id_token has no `at_hash`. Requires `access_token`; without
    /// one the options are a configuration error (`Error::BadRequest`).
    pub require_at_hash: bool,
    /// If set and the token has `c_hash`, it must equal oidc_token_hash(header alg, code).
    /// A token without `c_hash` is accepted unless `require_c_hash` is set.
    pub authorization_code: Option<&'a str>,
    /// Fail when the id_token has no `c_hash`. Requires `authorization_code`;
    /// without one the options are a configuration error (`Error::BadRequest`).
    pub require_c_hash: bool,
    /// Accept an id_token that carries `at_hash` or `c_hash` although no
    /// access token / authorization code was supplied to check it against.
    /// Default false: such a claim is an error, because the binding it exists
    /// for would otherwise be silently skipped. See
    /// [`IdTokenOptions::allow_unchecked_hashes`].
    pub allow_unchecked_hashes: bool,
}

impl<'a> IdTokenOptions<'a> {
    /// Default options. Unlike [`verify_id_token`], an id_token carrying
    /// `at_hash` or `c_hash` is refused unless the matching value is supplied
    /// or [`IdTokenOptions::allow_unchecked_hashes`] is set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the clock-skew tolerance in seconds (at most [`MAX_ID_TOKEN_LEEWAY`]).
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = Some(seconds);
        self
    }

    /// Require `auth_time` to be no older than `seconds`. Leeway is not added.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Require `acr` to be one of `values`.
    pub fn with_acr_values(mut self, values: &'a [&'a str]) -> Self {
        self.acr_values = Some(values);
        self
    }

    /// Validate `at_hash` against this access token.
    ///
    /// This only checks `at_hash` when the id_token carries it, so an id_token
    /// without `at_hash` is **not** bound to the access token. Combine with
    /// [`IdTokenOptions::with_required_at_hash`] when the binding must hold, as
    /// for implicit and hybrid flows or any flow where the OP is known to emit it.
    pub fn with_access_token(mut self, access_token: &'a str) -> Self {
        self.access_token = Some(access_token);
        self
    }

    /// Reject id_tokens that carry no `at_hash`. Needs
    /// [`IdTokenOptions::with_access_token`].
    pub fn with_required_at_hash(mut self) -> Self {
        self.require_at_hash = true;
        self
    }

    /// Validate `c_hash` against this authorization code (OIDC Core §3.3.2.11).
    ///
    /// Like [`IdTokenOptions::with_access_token`], this only checks `c_hash`
    /// when the id_token carries it. Hybrid flows (`code id_token`,
    /// `code id_token token`) must also call
    /// [`IdTokenOptions::with_required_c_hash`] to bind the front-channel
    /// id_token to the delivered code.
    pub fn with_authorization_code(mut self, code: &'a str) -> Self {
        self.authorization_code = Some(code);
        self
    }

    /// Reject id_tokens that carry no `c_hash`. Needs
    /// [`IdTokenOptions::with_authorization_code`].
    pub fn with_required_c_hash(mut self) -> Self {
        self.require_c_hash = true;
        self
    }

    /// Accept an id_token that carries `at_hash` or `c_hash` when no value was
    /// supplied to check it against.
    ///
    /// By default [`verify_id_token_with`] fails in that case, so the claim
    /// is never silently left unchecked. In the authorization code flow the
    /// RP may validate `at_hash` but need not (OIDC Core §3.1.3.7), so a flow
    /// that does not use the hash can opt out here; for implicit and hybrid
    /// flows (§3.2.2.9, §3.3.2.12) the hash must be checked, so do not opt
    /// out there. [`verify_id_token`] sets this to keep its 0.8 behaviour.
    pub fn allow_unchecked_hashes(mut self) -> Self {
        self.allow_unchecked_hashes = true;
        self
    }
}

/// Like [`verify_id_token`] with additional [`IdTokenOptions`].
///
/// When `jwks` holds more than one key the id_token must carry a `kid`
/// (OIDC Core §10.1); a set with a single key needs none.
///
/// The extra checks run after the `sub`, `aud`, `azp` and `nonce` checks.
/// `max_age` is checked against `auth_time` (not `iat`) and rejects tokens
/// without a numeric `auth_time`.
#[allow(clippy::too_many_arguments)]
pub fn verify_id_token_with(
    jwks: &JwkSet,
    id_token: &str,
    issuer: &str,
    client_id: &str,
    expected_nonce: Option<&str>,
    allowed_algorithms: &[JwsAlgorithm],
    trusted_additional_audiences: &[&str],
    options: &IdTokenOptions<'_>,
) -> Result<Claims> {
    if allowed_algorithms.is_empty() {
        return Err(Error::BadRequest(
            "at least one allowed id_token signing algorithm is required".into(),
        ));
    }
    if options.require_at_hash && options.access_token.is_none() {
        return Err(Error::BadRequest(
            "require_at_hash needs an access_token to check against".into(),
        ));
    }
    if options.require_c_hash && options.authorization_code.is_none() {
        return Err(Error::BadRequest(
            "require_c_hash needs an authorization_code to check against".into(),
        ));
    }
    if options.leeway.is_some_and(|l| l > MAX_ID_TOKEN_LEEWAY) {
        return Err(Error::BadRequest(format!(
            "id_token leeway must be at most {MAX_ID_TOKEN_LEEWAY} seconds"
        )));
    }
    if options.acr_values.is_some_and(<[&str]>::is_empty) {
        return Err(Error::BadRequest(
            "acr_values must not be empty when set".into(),
        ));
    }
    let mut validation = Validation::new()
        .with_issuer(issuer)
        .with_audience(client_id)
        .require_exp()
        .require_iat()
        .with_allowed_algorithms(allowed_algorithms.to_vec());
    if let Some(leeway) = options.leeway {
        validation = validation.with_leeway(leeway);
    }
    // OIDC Core §10.1 requires `kid` when the JWK Set has several keys. Without
    // it jose-rs tries every key, so a token signed by any key in the set would
    // verify. A single-key set needs no `kid` (it is optional in RFC 7515).
    let kid = jwt::peek_header(id_token)?.kid;
    if jwks.keys.len() > 1 {
        if kid.is_none() {
            return Err(Error::Authn(
                "id_token has no kid but the JWK Set has several keys".into(),
            ));
        }
        validation = validation.require_kid();
    }
    ensure_kid_names_key(jwks, kid.as_deref(), "id_token")?;
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
                    "id_token contains untrusted audience: {}",
                    display_safe(audience)
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

    if let Some(max_age) = options.max_age {
        let leeway = options.leeway.unwrap_or(DEFAULT_LEEWAY);
        let auth_time = claims
            .extra
            .get("auth_time")
            .ok_or_else(|| Error::Authn("id_token missing auth_time required by max_age".into()))
            .and_then(auth_time_secs)?;
        let now = now_secs();
        // Skew tolerance is not added to max_age: it is a session-age policy.
        if now > auth_time.saturating_add(max_age) {
            return Err(Error::Authn(
                "id_token auth_time is older than max_age".into(),
            ));
        }
        if auth_time > now.saturating_add(leeway) {
            return Err(Error::Authn("id_token auth_time is in the future".into()));
        }
    }

    if let Some(allowed) = options.acr_values {
        let acr = claims.extra.get("acr").and_then(|v| v.as_str());
        if !acr.is_some_and(|acr| allowed.contains(&acr)) {
            return Err(Error::Authn(
                "id_token acr missing or not in the accepted list".into(),
            ));
        }
    }

    check_token_hash(
        &claims,
        id_token,
        "at_hash",
        options.access_token,
        options.require_at_hash,
        options.allow_unchecked_hashes,
    )?;
    check_token_hash(
        &claims,
        id_token,
        "c_hash",
        options.authorization_code,
        options.require_c_hash,
        options.allow_unchecked_hashes,
    )?;
    Ok(claims)
}

/// Check an `at_hash` / `c_hash` claim against `value` using the hash for the
/// id_token's (already verified) JWS `alg`.
fn check_token_hash(
    claims: &Claims,
    id_token: &str,
    claim: &str,
    value: Option<&str>,
    required: bool,
    allow_unchecked: bool,
) -> Result<()> {
    let present = claims.extra.get(claim);
    if required && present.is_none() {
        return Err(Error::Authn(format!("id_token missing {claim}")));
    }
    if value.is_none() && present.is_some() && !allow_unchecked {
        return Err(Error::Authn(format!(
            "id_token carries {claim} but no value was supplied to verify it against; pass it, or use allow_unchecked_hashes"
        )));
    }
    if let (Some(value), Some(present)) = (value, present) {
        let claimed = present
            .as_str()
            .ok_or_else(|| Error::Authn(format!("id_token {claim} is not a string")))?;
        let alg = JwsAlgorithm::from_str(&jwt::peek_header(id_token)?.alg)?;
        let expected = jwt::oidc_token_hash(alg, value)?;
        if !crate::mac::constant_time_eq(expected.as_bytes(), claimed.as_bytes()) {
            return Err(Error::Authn(format!("id_token {claim} mismatch")));
        }
    }
    Ok(())
}

/// Read `auth_time` as seconds: any JSON number, with fractions floored.
/// Negative, non-finite and non-numeric values are rejected.
fn auth_time_secs(value: &serde_json::Value) -> Result<u64> {
    let invalid = || Error::Authn("id_token auth_time is not a valid number".into());
    let number = value.as_number().ok_or_else(invalid)?;
    if let Some(secs) = number.as_u64() {
        return Ok(secs);
    }
    match number.as_f64() {
        // `as` saturates at u64::MAX for huge values.
        Some(f) if f.is_finite() && f >= 0.0 => Ok(f.floor() as u64),
        _ => Err(invalid()),
    }
}

/// Verify a signed (`application/jwt`) UserInfo response and bind it to the
/// id_token subject (OIDC Core §5.3.2).
///
/// The JWS is verified against `jwks` with only `allowed_algorithms` accepted
/// (`none` and unlisted algorithms are rejected), `iss` must equal `issuer`,
/// `aud` must contain `client_id`, and `sub` must equal `expected_sub`. Returns
/// the verified claims as a JSON object. Rejects responses whose media type is
/// not `application/jwt`; use [`userinfo_json_claims`] for JSON. Encrypted
/// (JWE) responses are not supported.
///
/// # Context confusion and replay
///
/// OPs commonly sign UserInfo with the same key that signs id_tokens, and the
/// `iss`, `aud` and `sub` of both are identical. An id_token (or any other
/// token the OP signed for this client) could therefore be replayed as a
/// UserInfo response. The caller must say how the JWT is proven to be
/// UserInfo by choosing one of three modes in [`UserinfoJwtOptions`]:
///
/// - **[`UserinfoJwtOptions::typed`]** (safe). Requires an exact JOSE `typ`
///   header (RFC 8725 §3.11) that identifies UserInfo specifically. For OPs
///   that type their UserInfo JWTs.
/// - **[`UserinfoJwtOptions::dedicated_keys`]** (safe). The caller attests
///   that `jwks` holds only keys the OP uses to sign UserInfo responses, never
///   id_tokens, so a token that verifies cannot be an id_token. It does not
///   prove the token is UserInfo rather than another JWT signed by those keys;
///   the audience must still be exactly the client.
/// - **[`UserinfoJwtOptions::untyped_shared_key_compat`]** (compatibility
///   only). For OPs that sign UserInfo and id_tokens with the same keys and
///   set no `typ`. A fresh id_token without `nonce`, `at_hash` and `c_hash`
///   is then indistinguishable from UserInfo and will be accepted.
///
/// Two further checks apply in every mode, as defence in depth. They limit
/// replay but do not prove that a token is UserInfo:
///
/// - **Age bound.** By default the token must carry `iat` and be no older than
///   [`UserinfoJwtOptions::max_age`] (300 seconds, plus the 60 second default
///   clock-skew leeway), so a captured token cannot be replayed indefinitely
///   even if it has no `exp`. [`UserinfoJwtOptions::without_max_age`] removes
///   the bound; use it only for OPs that emit neither `iat` nor `exp`, and
///   accept that replay is then unbounded.
/// - **The token must carry a `kid`** naming a key in `jwks`, in every mode.
///   Otherwise it would be tried against every key in the set, so a token
///   signed by any key in a mixed-trust JWKS would verify. For an OP that
///   publishes a single key and sets no `kid` (conforming, since `kid` is only
///   required for multi-key sets), opt out with
///   [`UserinfoJwtOptions::allow_missing_kid`]; a multi-key set always needs it.
/// - **The audience must be exactly `client_id`** (a string, or an array with
///   that single element). Multi-audience and duplicated-audience tokens are
///   refused in every mode, unlike `jose-rs`' membership check.
/// - **id_token markers are refused.** After verification, a token whose
///   claims contain `nonce`, `at_hash` or `c_hash`, or whose `typ` header is
///   `id_token+jwt` or `at+jwt` (case-insensitive, with or without a leading
///   `application/`), is rejected as an id_token
///   or access token presented as UserInfo.
///
/// The safe path is therefore [`UserinfoJwtOptions::typed`] or
/// [`UserinfoJwtOptions::dedicated_keys`].
///
/// `exp` is checked only if present, unless
/// [`UserinfoJwtOptions::require_exp`] is set: OIDC Core §5.3.2 does not
/// require `exp` in signed UserInfo.
pub fn userinfo_signed_claims(
    jwks: &JwkSet,
    resp: &HttpFetchResponse,
    issuer: &str,
    client_id: &str,
    expected_sub: &str,
    allowed_algorithms: &[JwsAlgorithm],
    options: &UserinfoJwtOptions<'_>,
) -> Result<serde_json::Value> {
    if allowed_algorithms.is_empty() {
        return Err(Error::BadRequest(
            "at least one allowed userinfo signing algorithm is required".into(),
        ));
    }
    let content_type = resp.content_type.as_deref().or(resp.header("content-type"));
    let is_jwt = content_type.is_some_and(|ct| {
        ct.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/jwt")
    });
    if !is_jwt {
        return Err(Error::Authn(
            "signed userinfo must be served as application/jwt".into(),
        ));
    }
    let token = resp.text();
    // The token must name its key. Without `kid`, jose-rs tries every key in
    // the set, so a token signed by any key in a mixed-trust JWKS (the
    // `dedicated_keys` attestation cannot be checked) would verify. A missing
    // `kid` is only tolerated, on request, for a single-key set, where there is
    // nothing to be ambiguous about and the spec does not require it.
    let require_kid = jwks.keys.len() > 1 || !options.allow_missing_kid;
    let kid = jwt::peek_header(token.trim())?.kid;
    if require_kid && kid.is_none() {
        return Err(Error::Authn(if jwks.keys.len() > 1 {
            "signed userinfo has no kid but the JWK Set has several keys".into()
        } else {
            "signed userinfo has no kid; use UserinfoJwtOptions::allow_missing_kid for an OP that publishes a single key without kid".into()
        }));
    }
    ensure_kid_names_key(jwks, kid.as_deref(), "signed userinfo")?;
    let mut validation = Validation::new()
        .with_issuer(issuer)
        .with_audience(client_id)
        .with_allowed_algorithms(allowed_algorithms.to_vec());
    if require_kid {
        validation = validation.require_kid();
    }
    if options.require_exp {
        validation = validation.require_exp();
    }
    if let Some(max_age) = options.max_age {
        validation = validation.with_max_age(max_age);
    }
    if let UserinfoTrust::Typed(typ) = options.trust {
        if matches!(
            normalized_typ(typ).as_str(),
            "" | "jwt" | "id_token+jwt" | "at+jwt"
        ) {
            return Err(Error::BadRequest(
                "typ must identify UserInfo specifically".into(),
            ));
        }
        validation = validation.with_typ(typ);
    }
    let token = token.trim();
    let claims = jwt::verify_with_jwks(jwks, token, &validation)?;
    // OIDC Core §5.3.2: the audience of a signed UserInfo response is this
    // client. jose-rs only checks membership, so a token addressed to several
    // audiences (an API or service token with the same iss and sub) or one that
    // repeats the client would pass; require exactly the client_id.
    let audience_is_client = match claims.aud.as_ref() {
        Some(Audience::Single(aud)) => aud == client_id,
        Some(Audience::Multiple(values)) => values.len() == 1 && values[0] == client_id,
        None => false,
    };
    if !audience_is_client {
        return Err(Error::Authn(
            "signed userinfo audience must be exactly the client_id".into(),
        ));
    }
    if claims.sub.as_deref() != Some(expected_sub) {
        return Err(Error::Authn(
            "userinfo sub does not match the validated id_token subject".into(),
        ));
    }
    let typ_is_token = jwt::peek_header(token)?
        .typ
        .as_deref()
        .is_some_and(|t| matches!(normalized_typ(t).as_str(), "id_token+jwt" | "at+jwt"));
    let has_id_token_claim = ["nonce", "at_hash", "c_hash"]
        .iter()
        .any(|k| claims.extra.contains_key(*k));
    if typ_is_token || has_id_token_claim {
        return Err(Error::Authn(
            "signed userinfo carries id_token claims (nonce/at_hash/c_hash); refusing to treat an id_token as UserInfo".into(),
        ));
    }
    Ok(serde_json::to_value(&claims)?)
}

/// Normalize a JOSE `typ` value for comparison: case-insensitive, with any
/// media-type parameters and a leading `application/` removed, because RFC 7515
/// §4.1.9 treats `JWT` and `application/jwt` as the same type.
fn normalized_typ(typ: &str) -> String {
    let typ = typ
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    typ.strip_prefix("application/").unwrap_or(&typ).to_string()
}

/// Default [`UserinfoJwtOptions::max_age`] in seconds.
pub const DEFAULT_USERINFO_JWT_MAX_AGE: u64 = 300;

/// How a signed UserInfo JWT is proven to be UserInfo.
#[derive(Debug, Clone, Copy)]
enum UserinfoTrust<'a> {
    Typed(&'a str),
    DedicatedKeys,
    UntypedSharedKey,
}

/// Options for [`userinfo_signed_claims`].
///
/// There is no `Default` and no `new()`: construct it with one of
/// [`typed`](Self::typed), [`dedicated_keys`](Self::dedicated_keys) or
/// [`untyped_shared_key_compat`](Self::untyped_shared_key_compat), which
/// state how the JWT is proven to be UserInfo, then adjust with the `with_*`
/// builders. The struct is `#[non_exhaustive]`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UserinfoJwtOptions<'a> {
    /// Require `exp`. Default false (OIDC Core §5.3.2 does not require it).
    pub require_exp: bool,
    /// Maximum age of the token measured from `iat` (seconds). Default
    /// `Some(300)`. `iat` is then required. `None` disables the age bound
    /// ("allow undated"): only for OPs that emit neither `iat` nor `exp`, and
    /// then replay is unbounded.
    pub max_age: Option<u64>,
    /// Accept a token without `kid` when `jwks` holds exactly one key. Default
    /// false: the token must name its key. See
    /// [`UserinfoJwtOptions::allow_missing_kid`].
    pub allow_missing_kid: bool,
    trust: UserinfoTrust<'a>,
}

impl<'a> UserinfoJwtOptions<'a> {
    fn with_trust(trust: UserinfoTrust<'a>) -> Self {
        Self {
            require_exp: false,
            max_age: Some(DEFAULT_USERINFO_JWT_MAX_AGE),
            allow_missing_kid: false,
            trust,
        }
    }

    /// Accept a token that has no `kid`, but only when `jwks` holds exactly one
    /// key.
    ///
    /// By default the token must carry a `kid` naming a key in the set;
    /// otherwise jose-rs would try every key, so a token signed by any key in
    /// a mixed-trust set would verify. `kid` is optional in RFC 7515 and
    /// OIDC Core §10.1 only requires it when the JWK Set has more than one
    /// key, so an OP that publishes a single key and sets no `kid` is
    /// conforming; this is the compatibility switch for it. It has no effect
    /// on a set of two or more keys, where a missing `kid` stays an error
    /// because it is out of spec and ambiguous.
    pub fn allow_missing_kid(mut self) -> Self {
        self.allow_missing_kid = true;
        self
    }

    /// Require the JOSE `typ` header to equal `typ` (RFC 8725 §3.11), for OPs
    /// that set a UserInfo-specific `typ`. This is a safe mode.
    ///
    /// `typ` must identify UserInfo specifically: an empty value, `JWT`,
    /// `id_token+jwt` or `at+jwt` (case-insensitive, with or without a leading
    /// `application/`, since RFC 7515 §4.1.9 treats `JWT` and `application/jwt`
    /// alike) is refused with [`Error::BadRequest`] when
    /// [`userinfo_signed_claims`] runs.
    pub fn typed(typ: &'a str) -> Self {
        Self::with_trust(UserinfoTrust::Typed(typ))
    }

    /// The caller attests that the `jwks` passed to [`userinfo_signed_claims`]
    /// contains only keys the OP uses to sign UserInfo responses, never
    /// id_tokens. No `typ` is required. This is a safe mode, but only as safe
    /// as that attestation.
    pub fn dedicated_keys() -> Self {
        Self::with_trust(UserinfoTrust::DedicatedKeys)
    }

    /// Compatibility mode for OPs that sign UserInfo and id_tokens with the
    /// same keys and set no `typ`.
    ///
    /// **Known limitation:** an id_token that omits `nonce`, `at_hash` and
    /// `c_hash` and is fresh is indistinguishable from UserInfo and WILL be
    /// accepted for up to [`max_age`](Self::max_age). Prefer
    /// [`typed`](Self::typed) or [`dedicated_keys`](Self::dedicated_keys).
    pub fn untyped_shared_key_compat() -> Self {
        Self::with_trust(UserinfoTrust::UntypedSharedKey)
    }

    /// Reject tokens without `exp`.
    pub fn with_require_exp(mut self) -> Self {
        self.require_exp = true;
        self
    }

    /// Require `iat` and a token age of at most `seconds`.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Remove the age bound and the `iat` requirement. Replay is then
    /// unbounded unless the token has `exp`; use only for OPs that emit
    /// neither `iat` nor `exp`.
    pub fn without_max_age(mut self) -> Self {
        self.max_age = None;
        self
    }
}

/// How [`fetch_userinfo_response`] sends the UserInfo request (OIDC Core §5.3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UserinfoMethod {
    /// `POST` with an empty form body (the default).
    #[default]
    Post,
    /// `GET`. Requires [`HttpClient::get_with_headers`]. Use it only if your
    /// `HttpClient` strips `Authorization` on a cross-origin redirect (or does
    /// not follow redirects): the access token is sent as a Bearer header and
    /// the redirect target is not validated by this crate.
    Get,
}

/// Fetch UserInfo with a Bearer access token and return the raw 200 response.
///
/// Validates the issuer and endpoint exactly as [`fetch_userinfo`] does, sends
/// the request with `method`, and returns the response unchanged. Use this for
/// signed `application/jwt` UserInfo, and verify the result with
/// [`userinfo_signed_claims`]. The response is **not** bound to a subject here:
/// a caller that reads the body without going through [`userinfo_json_claims`]
/// or [`userinfo_signed_claims`] performs no `sub` check and, for a JWT, no
/// signature check. Never parse it with [`jwt::peek_claims_unverified`]. For
/// JSON responses use [`userinfo_json_claims`]. Encrypted (JWE) responses are
/// not supported.
pub async fn fetch_userinfo_response(
    http: &Arc<dyn HttpClient>,
    userinfo_endpoint: &str,
    access_token: &str,
    issuer: &str,
    method: UserinfoMethod,
) -> Result<HttpFetchResponse> {
    validate_issuer(issuer)?;
    validate_service_endpoint_for_issuer("userinfo_endpoint", userinfo_endpoint, issuer)?;
    if access_token.is_empty()
        || access_token
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace() || !c.is_ascii())
    {
        return Err(Error::BadRequest(
            "access_token contains characters not allowed in an Authorization header".into(),
        ));
    }
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {access_token}"),
    )];
    let resp = match method {
        UserinfoMethod::Post => http.post_form(userinfo_endpoint, &[], &headers).await?,
        UserinfoMethod::Get => http.get_with_headers(userinfo_endpoint, &headers).await?,
    };
    if resp.status != 200 {
        return Err(upstream_error(
            UpstreamKind::Auth,
            format!("userinfo returned {}", resp.status),
            &resp,
        ));
    }
    // A broken OP can answer 200 with an RFC 6750 style JSON error body. A real
    // UserInfo response carries `sub`; signed responses are not JSON objects, so
    // only bodies that start with `{` are parsed.
    let looks_like_object = resp.body.len() <= MAX_ERROR_JSON_BYTES
        && resp
            .body
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|b| *b == b'{');
    if looks_like_object {
        if let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice(&resp.body) {
            if obj.get("error").is_some_and(serde_json::Value::is_string)
                && !obj.contains_key("sub")
            {
                return Err(upstream_error(
                    UpstreamKind::Auth,
                    format!("userinfo returned an error with status {}", resp.status),
                    &resp,
                ));
            }
        }
    }
    Ok(resp)
}

/// Parse a JSON UserInfo response and bind it to the id_token subject.
///
/// Rejects `application/jwt` (signed UserInfo); verify those yourself using
/// [`fetch_userinfo_response`]. Other or missing content types are parsed as
/// JSON.
pub fn userinfo_json_claims(
    resp: &HttpFetchResponse,
    expected_sub: &str,
) -> Result<serde_json::Value> {
    let content_type = resp.content_type.as_deref().or(resp.header("content-type"));
    if let Some(ct) = content_type {
        let media_type = ct.split(';').next().unwrap_or("").trim();
        if media_type.eq_ignore_ascii_case("application/jwt") {
            return Err(Error::Authn(
                "userinfo is a signed JWT (application/jwt); use rp::fetch_userinfo_response and rp::userinfo_signed_claims".into(),
            ));
        }
    }
    let claims: serde_json::Value = resp.json()?;
    if claims.get("sub").and_then(|value| value.as_str()) != Some(expected_sub) {
        return Err(Error::Authn(
            "userinfo sub does not match the validated id_token subject".into(),
        ));
    }
    Ok(claims)
}

/// Fetch UserInfo with a Bearer access token for an associated issuer.
///
/// The issuer context is mandatory because the loopback HTTP development
/// exception applies only when the issuer itself is a loopback HTTP origin.
/// Uses POST and expects a JSON response. For GET, or for signed
/// `application/jwt` UserInfo, use [`fetch_userinfo_response`] with
/// [`userinfo_json_claims`].
pub async fn fetch_userinfo(
    http: &Arc<dyn HttpClient>,
    userinfo_endpoint: &str,
    access_token: &str,
    expected_sub: &str,
    issuer: &str,
) -> Result<serde_json::Value> {
    let resp = fetch_userinfo_response(
        http,
        userinfo_endpoint,
        access_token,
        issuer,
        UserinfoMethod::Post,
    )
    .await?;
    userinfo_json_claims(&resp, expected_sub)
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

/// Which kind of upstream request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamKind {
    /// Token and UserInfo requests: reported as authentication failures
    /// (0.8 returned `Error::Authn`).
    Auth,
    /// Discovery, JWKS and federation metadata fetches (0.8 returned
    /// `Error::Internal`).
    Metadata,
}

/// Build a structured [`Error::UpstreamHttp`] from a non-success response.
///
/// `error` / `error_description` come from a JSON object body with a string
/// `error` (RFC 6749 §5.2); otherwise from the `WWW-Authenticate` header.
/// `message` is the bare text; the `Display` prefix and the `auth_failure`
/// flag both derive from `kind`, so they cannot drift apart.
/// Longest `UpstreamHttpError` message, in characters, before truncation.
const MAX_UPSTREAM_MESSAGE_CHARS: usize = 1024;

/// Byte budget for extracting OAuth error fields from an upstream body. An
/// RFC 6749 error object is tiny; a larger body is not parsed at all, so a
/// hostile upstream cannot make us allocate a large JSON tree per failure.
const MAX_ERROR_JSON_BYTES: usize = 16 * 1024;

/// Byte budget for the `WWW-Authenticate` header values parsed for an error.
const MAX_ERROR_HEADER_BYTES: usize = 8 * 1024;

/// Characters kept from an upstream body excerpt.
const MAX_ERROR_BODY_CHARS: usize = 512;

pub(crate) fn upstream_error(
    kind: UpstreamKind,
    message: impl std::fmt::Display,
    resp: &HttpFetchResponse,
) -> Error {
    let (prefix, auth_failure) = match kind {
        UpstreamKind::Auth => ("authentication error: ", true),
        UpstreamKind::Metadata => ("internal error: ", false),
    };
    // Safety net: whatever the caller interpolated, the message (printed by
    // both Display and Debug) stays bounded.
    let mut message = format!("{prefix}{message}");
    if let Some((end, _)) = message.char_indices().nth(MAX_UPSTREAM_MESSAGE_CHARS) {
        message.truncate(end);
        message.push('…');
    }
    let mut error = None;
    let mut description = None;
    // Structured extraction is skipped for oversized bodies; the capped excerpt
    // and the header fallback below still apply.
    if resp.body.len() <= MAX_ERROR_JSON_BYTES {
        if let Ok(serde_json::Value::Object(obj)) =
            serde_json::from_slice::<serde_json::Value>(&resp.body)
        {
            if let Some(code) = obj.get("error").and_then(|v| v.as_str()) {
                error = Some(escape_upstream_text(code, 64));
                description = obj
                    .get("error_description")
                    .and_then(|v| v.as_str())
                    .map(|d| escape_upstream_text(d, 256));
            }
        }
    }
    if error.is_none() {
        let values = resp.header_values("www-authenticate");
        if values.iter().map(|v| v.len()).sum::<usize>() <= MAX_ERROR_HEADER_BYTES {
            if let Some((e, d)) = parse_www_authenticate_bearer(&values.join(", ")) {
                error = e.map(|e| escape_upstream_text(&e, 64));
                description = d.map(|d| escape_upstream_text(&d, 256));
            }
        }
    }
    // Decode only a prefix: at most 4 bytes per character, plus one character of
    // slack so a longer body always shows the truncation marker.
    let excerpt_bytes = (MAX_ERROR_BODY_CHARS + 1) * 4;
    let body = if resp.body.is_empty() {
        None
    } else {
        let prefix = &resp.body[..resp.body.len().min(excerpt_bytes)];
        Some(escape_upstream_text(
            &String::from_utf8_lossy(prefix),
            MAX_ERROR_BODY_CHARS,
        ))
    };
    Error::UpstreamHttp(Box::new(UpstreamHttpError::new(
        Some(resp.status),
        error,
        description,
        body,
        message,
        auth_failure,
    )))
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

/// Reject a token whose `kid` names no key in `jwks`.
///
/// jose-rs `require_kid` only checks that the header carries a `kid`. When no
/// JWK has a `kid` it still tries every key, so `kid = "nonexistent"` would
/// verify against an unlabelled key. A token without `kid` passes here; callers
/// decide whether that is allowed.
fn ensure_kid_names_key(jwks: &JwkSet, kid: Option<&str>, what: &str) -> Result<()> {
    match kid {
        Some(kid) if !jwks.keys.iter().any(|key| key.kid.as_deref() == Some(kid)) => Err(
            Error::Authn(format!("{what} kid does not name a key in the JWK Set")),
        ),
        _ => Ok(()),
    }
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

        // Encoded octets do not create a parser/use mismatch, and endpoint
        // queries remain valid.
        for endpoint in [
            "https://op.example.org/token?label=hello%20world",
            "https://op.example.org/%09/%0A",
        ] {
            validate_service_endpoint("token_endpoint", endpoint)
                .unwrap_or_else(|error| panic!("valid endpoint {endpoint:?}: {error}"));
        }

        // A context-free URL must never inherit the development exception.
        for endpoint in [
            "http://localhost:8080/token",
            "http://127.0.0.1:8080/token",
            "http://[::1]:8080/token",
        ] {
            assert!(validate_service_endpoint("token_endpoint", endpoint).is_err());
        }
    }

    #[test]
    fn loopback_http_endpoints_require_a_loopback_http_issuer() {
        let (_, provider, _) = client_and_provider();
        for field in [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ] {
            let mut contaminated = provider.clone();
            let endpoint = "http://127.0.0.1:8080/path".to_string();
            match field {
                "authorization_endpoint" => contaminated.authorization_endpoint = endpoint,
                "token_endpoint" => contaminated.token_endpoint = endpoint,
                "userinfo_endpoint" => contaminated.userinfo_endpoint = Some(endpoint),
                "jwks_uri" => contaminated.jwks_uri = Some(endpoint),
                _ => unreachable!(),
            }
            assert!(
                contaminated.validate().is_err(),
                "remote issuer must not authorize loopback HTTP {field}"
            );
        }

        let local = ProviderInfo {
            issuer: "http://localhost:8080".into(),
            authorization_endpoint: "http://localhost:8080/authorize".into(),
            token_endpoint: "http://127.0.0.1:8080/token".into(),
            userinfo_endpoint: Some("http://[::1]:8080/userinfo".into()),
            jwks_uri: Some("http://localhost:8080/jwks".into()),
        };
        local
            .validate()
            .expect("loopback issuer may use loopback HTTP endpoints");
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
            ..Default::default()
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
    async fn fetch_jwks_binds_loopback_http_exception_to_issuer() {
        let rejected_http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: None,
        });
        let error = fetch_jwks(
            &rejected_http,
            "http://127.0.0.1:8080/jwks",
            "https://remote.example",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("absolute https URL"));

        let (_, _, key) = client_and_provider();
        let local_http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse {
                status: 200,
                body: key.to_public_jwks().to_json().unwrap().into_bytes(),
                content_type: Some("application/json".into()),
                ..Default::default()
            }),
            post: None,
        });
        let fetched = fetch_jwks(
            &local_http,
            "http://127.0.0.1:8080/jwks",
            "http://localhost:8080",
        )
        .await
        .expect("loopback issuer may fetch a loopback HTTP JWKS");
        assert_eq!(fetched.keys.len(), 1);
    }

    #[tokio::test]
    async fn jwks_ttl_ignores_directives_inside_quoted_values() {
        // The quoted extension value must not be read as a max-age directive.
        let r = jwks_response_with(Some(r#"foo="x, max-age=86400", max-age=60"#)).await;
        assert_eq!(r.advertised_ttl_secs(), Some(60));
        // Nor as no-store.
        let r = jwks_response_with(Some(r#"foo="a, no-store", max-age=30"#)).await;
        assert_eq!(r.advertised_ttl_secs(), Some(30));
        // Escaped quotes do not end the quoted string early.
        let r = jwks_response_with(Some(r#"foo="a\", max-age=999", max-age=15"#)).await;
        assert_eq!(r.advertised_ttl_secs(), Some(15));
        // An unterminated quote makes the field unusable: fail closed, so a
        // `no-store` hidden after it cannot turn into a long lifetime.
        for header in [
            r#"foo="oops, max-age=500"#,
            r#"max-age=3600, x="a, no-store"#,
            r#"max-age=3600, x="a"#,
            r#"max-age=3600, x=", no-store, y=1"#,
            r#"max-age=3600, x="a\""#,
        ] {
            let r = jwks_response_with(Some(header)).await;
            assert_eq!(r.advertised_ttl_secs(), Some(0), "{header}");
            assert_eq!(r.cache_ttl_secs(), Some(0), "{header}");
        }
        // Controls: closed quotes keep working in either order.
        let r = jwks_response_with(Some(r#"max-age=3600, x="a", no-store"#)).await;
        assert_eq!(r.advertised_ttl_secs(), Some(0));
        let r = jwks_response_with(Some(r#"max-age=3600, x="a, b""#)).await;
        assert_eq!(r.advertised_ttl_secs(), Some(3600));
        // Real directives around quoted values still work.
        let r = jwks_response_with(Some(r#"max-age=20, foo="x,y""#)).await;
        assert_eq!(r.advertised_ttl_secs(), Some(20));
    }

    async fn jwks_response_with_age(cache_control: &str, age: Option<&str>) -> JwksResponse {
        let (_, _, key) = client_and_provider();
        let mut resp = crate::http::HttpFetchResponse {
            status: 200,
            body: key.to_public_jwks().to_json().unwrap().into_bytes(),
            content_type: Some("application/json".into()),
            ..Default::default()
        }
        .with_header("Cache-Control", cache_control);
        if let Some(age) = age {
            resp = resp.with_header("Age", age);
        }
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(resp),
            post: None,
        });
        fetch_jwks_response(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn jwks_ttl_is_capped_but_advertised_is_not() {
        // A year-long max-age is capped to the ceiling.
        let r = jwks_response_with_age("max-age=31536000", None).await;
        assert_eq!(r.advertised_ttl_secs(), Some(31_536_000));
        assert_eq!(r.cache_ttl_secs(), Some(MAX_JWKS_CACHE_TTL_SECS));
        // The cap applies after subtracting Age.
        let r = jwks_response_with_age("max-age=31536000", Some("100")).await;
        assert_eq!(r.cache_ttl_secs(), Some(MAX_JWKS_CACHE_TTL_SECS));
        let r = jwks_response_with_age("max-age=100000", Some("99000")).await;
        assert_eq!(r.cache_ttl_secs(), Some(1000));
        // Values below the ceiling are untouched.
        let r = jwks_response_with_age("max-age=600", None).await;
        assert_eq!(r.cache_ttl_secs(), Some(600));
        // An overflowing max-age saturates, then is capped, instead of
        // being ignored and left to the caller's default.
        let r =
            jwks_response_with_age("max-age=340282366920938463463374607431768211455", None).await;
        assert_eq!(r.advertised_ttl_secs(), Some(u64::MAX));
        assert_eq!(r.cache_ttl_secs(), Some(MAX_JWKS_CACHE_TTL_SECS));
        // A caller-chosen ceiling is honoured; zero stays zero.
        let r = jwks_response_with_age("max-age=3600", None).await;
        assert_eq!(r.cache_ttl_secs_max(60), Some(60));
        assert_eq!(r.cache_ttl_secs_max(0), Some(0));
        let r = jwks_response_with_age("no-store", None).await;
        assert_eq!(r.cache_ttl_secs(), Some(0));
    }

    #[tokio::test]
    async fn jwks_response_subtracts_age_from_ttl() {
        let r = jwks_response_with_age("max-age=3600", Some("3000")).await;
        assert_eq!(r.age, Some(3000));
        assert_eq!(r.advertised_ttl_secs(), Some(3600));
        assert_eq!(r.cache_ttl_secs(), Some(600));
        // Age beyond the lifetime saturates at zero, no underflow.
        let r = jwks_response_with_age("max-age=60", Some("99999")).await;
        assert_eq!(r.cache_ttl_secs(), Some(0));
        // A digits-only Age that overflows u64 saturates: nothing stays fresh.
        for age in ["18446744073709551616", "99999999999999999999999999"] {
            let r = jwks_response_with_age("max-age=300", Some(age)).await;
            assert_eq!(r.age, Some(u64::MAX), "{age}");
            assert_eq!(r.cache_ttl_secs(), Some(0), "{age}");
            assert_eq!(r.advertised_ttl_secs(), Some(300));
        }
        let r = jwks_response_with_age("max-age=300", Some("18446744073709551615")).await;
        assert_eq!(r.age, Some(u64::MAX));
        // Missing or invalid Age is treated as 0.
        for age in [None, Some("abc"), Some("-5"), Some("")] {
            let r = jwks_response_with_age("max-age=300", age).await;
            assert_eq!(r.age, None, "{age:?}");
            assert_eq!(r.cache_ttl_secs(), Some(300));
        }
        // No usable lifetime stays None; no-store stays 0.
        assert_eq!(
            jwks_response_with_age("public", Some("10"))
                .await
                .cache_ttl_secs(),
            None
        );
        assert_eq!(
            jwks_response_with_age("no-store", Some("10"))
                .await
                .cache_ttl_secs(),
            Some(0)
        );
    }

    async fn jwks_response_with(cache_control: Option<&str>) -> JwksResponse {
        let (_, _, key) = client_and_provider();
        let mut resp = crate::http::HttpFetchResponse {
            status: 200,
            body: key.to_public_jwks().to_json().unwrap().into_bytes(),
            content_type: Some("application/json".into()),
            ..Default::default()
        };
        if let Some(cc) = cache_control {
            resp = resp.with_header("Cache-Control", cc);
        }
        resp = resp.with_header("ETag", "\"abc\"");
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(resp),
            post: None,
        });
        fetch_jwks_response(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn jwks_response_keeps_headers_and_ttl() {
        let r = jwks_response_with(Some("public, max-age=300")).await;
        assert_eq!(r.cache_ttl_secs(), Some(300));
        assert_eq!(r.etag.as_deref(), Some("\"abc\""));
        assert_eq!(r.cache_control.as_deref(), Some("public, max-age=300"));
        assert_eq!(r.jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn jwks_response_ttl_parsing() {
        for (header, expected) in [
            ("no-store", Some(0)),
            ("no-cache, max-age=60", Some(0)),
            ("MAX-AGE=30", Some(30)),
            ("max-age=\"45\"", Some(45)),
            ("max-age=abc", None),
            ("max-age=abc, max-age=7", Some(7)),
            ("s-maxage=10", None),
            ("max-age=", None),
            (",,=,", None),
        ] {
            let r = jwks_response_with(Some(header)).await;
            assert_eq!(r.cache_ttl_secs(), expected, "{header}");
        }
        assert_eq!(jwks_response_with(None).await.cache_ttl_secs(), None);
    }

    #[tokio::test]
    async fn jwks_response_joins_multiple_cache_control_lines() {
        let (_, _, key) = client_and_provider();
        let resp = crate::http::HttpFetchResponse::new(
            200,
            key.to_public_jwks().to_json().unwrap().into_bytes(),
        )
        .with_header("Cache-Control", "max-age=3600")
        .with_header("Cache-Control", "no-store");
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(resp),
            post: None,
        });
        let r = fetch_jwks_response(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap();
        assert_eq!(r.cache_control.as_deref(), Some("max-age=3600, no-store"));
        assert_eq!(r.cache_ttl_secs(), Some(0));
    }

    #[tokio::test]
    async fn fetch_jwks_response_non_200_is_structured_error() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(503, "")),
            post: None,
        });
        let err = fetch_jwks_response(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert_eq!(err.upstream_http().expect("upstream").status, Some(503));
        assert!(err.to_string().contains("jwks fetch failed (503)"));
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

    fn json_response(body: serde_json::Value) -> crate::http::HttpFetchResponse {
        crate::http::HttpFetchResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
            content_type: Some("application/json".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn discover_accepts_metadata_without_userinfo_endpoint() {
        let issuer = "https://op.example.com";
        let mut body = ProviderMetadata::new(issuer, issuer).to_json();
        body.as_object_mut().unwrap().remove("userinfo_endpoint");
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(json_response(body)),
            post: None,
        });
        let metadata = discover(&http, issuer).await.unwrap();
        assert!(metadata.userinfo_endpoint.is_none());
        let info = ProviderInfo::from(metadata);
        assert!(info.userinfo_endpoint.is_none());
        let err = info.require_userinfo_endpoint().unwrap_err();
        assert!(err.to_string().contains("userinfo_endpoint"));
        assert!(info.require_jwks_uri().is_ok());
    }

    #[tokio::test]
    async fn discover_rejects_loopback_http_userinfo_under_remote_issuer() {
        let issuer = "https://op.example.com";
        let mut body = ProviderMetadata::new(issuer, issuer).to_json();
        body["userinfo_endpoint"] = "http://127.0.0.1:8080/userinfo".into();
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(json_response(body)),
            post: None,
        });
        assert!(discover(&http, issuer).await.is_err());
    }

    #[test]
    fn require_jwks_uri_errors_when_missing() {
        let (_, provider, _) = client_and_provider();
        let err = provider.require_jwks_uri().unwrap_err();
        assert!(err.to_string().contains("jwks_uri"));
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
                ..Default::default()
            }),
        });
        let err = exchange_code(&http, &provider, &client, "code-1", None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert_eq!(msg, "authentication error: token endpoint returned 400");
        assert!(!msg.contains("oops"), "{msg:?}");
        assert!(
            !msg.chars().any(|c| c.is_control()),
            "control characters must not appear: {msg:?}"
        );
    }

    fn mock_post(resp: crate::http::HttpFetchResponse) -> Arc<dyn HttpClient> {
        Arc::new(MockHttp {
            get: None,
            post: Some(resp),
        })
    }

    #[tokio::test]
    async fn json_error_bodies_on_200_are_structured_errors() {
        let (client, provider, _key) = client_and_provider();
        let body = r#"{"error":"invalid_grant","error_description":"code expired"}"#;
        let http = mock_post(crate::http::HttpFetchResponse::new(200, body));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        let up = err.upstream_http().expect("structured");
        assert_eq!(up.status, Some(200));
        assert_eq!(up.error.as_deref(), Some("invalid_grant"));
        assert_eq!(up.error_description.as_deref(), Some("code expired"));
        assert!(err.is_auth_failure());

        let ui = r#"{"error":"invalid_token","error_description":"expired"}"#;
        let http = mock_post(crate::http::HttpFetchResponse::new(200, ui));
        let err = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Post)
            .await
            .unwrap_err();
        assert_eq!(
            err.upstream_http().unwrap().error.as_deref(),
            Some("invalid_token")
        );

        // A real UserInfo response that also happens to carry `sub` is untouched.
        let ok = r#"{"sub":"s1","error":"not-an-error-claim"}"#;
        let http = mock_post(crate::http::HttpFetchResponse::new(200, ok));
        fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Post)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oversized_error_bodies_and_headers_are_not_parsed() {
        // A small error object is parsed.
        let small = r#"{"error":"invalid_grant","error_description":"x"}"#;
        let resp = crate::http::HttpFetchResponse::new(503, small);
        let err = upstream_error(UpstreamKind::Metadata, "m", &resp);
        assert_eq!(
            err.upstream_http().unwrap().error.as_deref(),
            Some("invalid_grant")
        );

        // The same object padded past the budget is not: no error fields, but the
        // status, the capped excerpt and the truncation marker remain.
        let pad = "z".repeat(MAX_ERROR_JSON_BYTES);
        let big = format!(r#"{{"error":"invalid_grant","pad":"{pad}"}}"#);
        let resp = crate::http::HttpFetchResponse::new(503, big);
        let err = upstream_error(UpstreamKind::Metadata, "m", &resp);
        let up = err.upstream_http().unwrap();
        assert_eq!((up.status, up.error.as_deref()), (Some(503), None));
        let body = up.body.as_deref().unwrap();
        assert_eq!(body.chars().count(), MAX_ERROR_BODY_CHARS + 1);
        assert!(body.ends_with('…'));

        // An oversized body still falls back to WWW-Authenticate.
        let resp = crate::http::HttpFetchResponse::new(401, vec![b'['; MAX_ERROR_JSON_BYTES + 1])
            .with_header("WWW-Authenticate", r#"Bearer error="invalid_token""#);
        let err = upstream_error(UpstreamKind::Auth, "m", &resp);
        assert_eq!(
            err.upstream_http().unwrap().error.as_deref(),
            Some("invalid_token")
        );

        // An oversized header is not parsed.
        let long = format!(
            r#"Bearer error="invalid_token", x="{}""#,
            "y".repeat(MAX_ERROR_HEADER_BYTES)
        );
        let resp =
            crate::http::HttpFetchResponse::new(401, "").with_header("WWW-Authenticate", long);
        let err = upstream_error(UpstreamKind::Auth, "m", &resp);
        assert_eq!(err.upstream_http().unwrap().error, None);

        // Multi-byte bodies are cut on a character boundary and marked.
        let wide = "é".repeat(5000);
        let resp = crate::http::HttpFetchResponse::new(500, wide);
        let err = upstream_error(UpstreamKind::Metadata, "m", &resp);
        let body = err.upstream_http().unwrap().body.clone().unwrap();
        assert_eq!(body.chars().count(), MAX_ERROR_BODY_CHARS + 1);
        assert!(body.ends_with('…'));
    }

    #[tokio::test]
    async fn long_issuer_urls_do_not_make_unbounded_discovery_errors() {
        let long = "p".repeat(5000);
        let issuer = format!("https://op.example.com/{long}");
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(404, "")),
            post: None,
        });
        let err = discover(&http, &issuer).await.unwrap_err();
        let shown = err.to_string();
        assert!(
            shown.starts_with("internal error: discovery failed (404) for https://op.example.com/")
        );
        assert!(shown.chars().count() < 400, "{}", shown.chars().count());
        assert!(!shown.contains(&"p".repeat(300)));
        let dbg = format!("{err:?}");
        assert!(dbg.chars().count() < 800, "{}", dbg.chars().count());
        assert_eq!(err.upstream_http().unwrap().status, Some(404));

        // The generic cap bounds any message that slips through un-sanitized.
        let resp = crate::http::HttpFetchResponse::new(500, "");
        let err = upstream_error(UpstreamKind::Metadata, "x".repeat(5000), &resp);
        let shown = err.to_string();
        assert_eq!(shown.chars().count(), MAX_UPSTREAM_MESSAGE_CHARS + 1);
        assert!(shown.ends_with('…'));
        // A short message is untouched.
        let err = upstream_error(UpstreamKind::Metadata, "short", &resp);
        assert_eq!(err.to_string(), "internal error: short");
    }

    #[tokio::test]
    async fn upstream_errors_classify_auth_failures() {
        let (client, provider, _key) = client_and_provider();
        // Token endpoint rejection: formerly Authn.
        let http = mock_post(crate::http::HttpFetchResponse::new(400, "{}"));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        assert!(err.is_auth_failure());
        assert!(!matches!(err, Error::Authn(_)));
        // UserInfo rejection: formerly Authn.
        let http = mock_post(crate::http::HttpFetchResponse::new(401, ""));
        let err = fetch_userinfo(
            &http,
            "https://op.example.org/userinfo",
            "at",
            "sub",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert!(err.is_auth_failure());
        // JWKS fetch failure: formerly Internal, not an auth failure.
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(500, "")),
            post: None,
        });
        let err = fetch_jwks(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert!(err.upstream_http().is_some());
        assert!(!err.is_auth_failure());
        // Metadata fetch failures are an upstream fault, not a login failure.
        assert_eq!(err.status_hint(), 502);
        // Plain Authn still counts.
        assert!(Error::Authn("x".into()).is_auth_failure());
        assert!(!Error::Internal("x".into()).is_auth_failure());
    }

    #[tokio::test]
    async fn error_description_is_redacted_in_debug_but_readable() {
        let (client, provider, _key) = client_and_provider();
        let body = r#"{"error":"invalid_grant","error_description":"rejected code SECRET-DESC"}"#;
        let http = mock_post(crate::http::HttpFetchResponse::new(400, body));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        let dbg = format!("{err:?}");
        assert!(!dbg.contains("SECRET-DESC"), "{dbg}");
        assert!(!err.to_string().contains("SECRET-DESC"));
        assert_eq!(
            err.upstream_http().unwrap().error_description.as_deref(),
            Some("rejected code SECRET-DESC")
        );

        // Same for a description taken from WWW-Authenticate.
        let resp = crate::http::HttpFetchResponse::new(401, "").with_header(
            "WWW-Authenticate",
            r#"Bearer error="invalid_token", error_description="rejected SECRET-HDR""#,
        );
        let http = mock_post(resp);
        let err = fetch_userinfo(
            &http,
            "https://op.example.org/userinfo",
            "tok",
            "sub",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert!(!format!("{err:?}").contains("SECRET-HDR"));
        assert_eq!(
            err.upstream_http().unwrap().error_description.as_deref(),
            Some("rejected SECRET-HDR")
        );
    }

    #[tokio::test]
    async fn token_error_is_structured_and_escaped() {
        let (client, provider, _key) = client_and_provider();
        let body = r#"{"error":"invalid_grant","error_description":"bad\u001b[31m code"}"#;
        let http = mock_post(crate::http::HttpFetchResponse::new(400, body));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        let up = err.upstream_http().expect("upstream variant");
        assert_eq!(up.status, Some(400));
        assert_eq!(up.error.as_deref(), Some("invalid_grant"));
        let d = up.error_description.as_deref().unwrap();
        assert!(d.contains("\\u{1b}"), "{d}");
        assert!(!d.chars().any(|c| c.is_control()));
        assert_eq!(
            err.to_string(),
            "authentication error: token endpoint returned 400"
        );
        // Same hint as the 0.8 `Authn`, so re-login logic keyed on it still works.
        assert_eq!(err.status_hint(), 401);
    }

    #[tokio::test]
    async fn token_error_debug_and_display_do_not_leak_body() {
        let (client, provider, _key) = client_and_provider();
        let http = mock_post(crate::http::HttpFetchResponse::new(
            400,
            r#"{"error":"invalid_grant","error_description":"x","echo":"SECRET"}"#,
        ));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        assert!(!format!("{err:?}").contains("SECRET"), "{err:?}");
        assert!(!err.to_string().contains("SECRET"));
        assert!(err
            .upstream_http()
            .unwrap()
            .body
            .as_deref()
            .unwrap()
            .contains("SECRET"));
    }

    #[tokio::test]
    async fn token_error_body_field_is_capped_and_bidi_escaped() {
        let (client, provider, _key) = client_and_provider();
        let body = format!("oops\x1b[31m\n{}\u{202E}", "x".repeat(2000));
        let http = mock_post(crate::http::HttpFetchResponse::new(400, body.clone()));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        let up = err.upstream_http().unwrap();
        let b = up.body.as_deref().unwrap();
        assert!(!b.chars().any(|c| c.is_control()));
        assert!(b.chars().count() <= 513);
        assert!(b.ends_with('…'));
        assert_eq!(up.error, None);

        let http = mock_post(crate::http::HttpFetchResponse::new(400, "a\u{202E}b"));
        let err = exchange_code(&http, &provider, &client, "c", None)
            .await
            .unwrap_err();
        assert_eq!(
            err.upstream_http().unwrap().body.as_deref(),
            Some("a\\u{202e}b")
        );
        // The Display text carries no upstream body at all.
        let shown = err.to_string();
        assert!(!shown.contains('\u{202E}'));
        assert_eq!(shown, "authentication error: token endpoint returned 400");
    }

    #[tokio::test]
    async fn userinfo_error_reads_bearer_among_multiple_challenges_and_lines() {
        // Two header lines: a Basic challenge first, the Bearer error second.
        let resp = crate::http::HttpFetchResponse::new(401, "")
            .with_header("WWW-Authenticate", r#"Basic realm="x, y""#)
            .with_header(
                "WWW-Authenticate",
                r#"Bearer error="invalid_token", error_description="expired""#,
            );
        let http = mock_post(resp);
        let err = fetch_userinfo(
            &http,
            "https://op.example.org/userinfo",
            "tok",
            "sub",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        let up = err.upstream_http().unwrap();
        assert_eq!(up.error.as_deref(), Some("invalid_token"));
        assert_eq!(up.error_description.as_deref(), Some("expired"));
    }

    #[tokio::test]
    async fn userinfo_error_parses_www_authenticate() {
        let resp = crate::http::HttpFetchResponse::new(401, "").with_header(
            "WWW-Authenticate",
            r#"Bearer error="invalid_token", error_description="expired""#,
        );
        let http = mock_post(resp);
        let err = fetch_userinfo(
            &http,
            "https://op.example.org/userinfo",
            "tok",
            "sub",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        let up = err.upstream_http().unwrap();
        assert_eq!(up.status, Some(401));
        assert_eq!(up.error.as_deref(), Some("invalid_token"));
        assert_eq!(up.error_description.as_deref(), Some("expired"));
        assert_eq!(up.body, None);
        assert_eq!(
            err.to_string(),
            "authentication error: userinfo returned 401"
        );
        assert_eq!(err.status_hint(), 401);
    }

    type RecordedCall = (String, String, Vec<(String, String)>);

    /// Records every call as `(method, url, headers)`.
    struct RecordingHttp {
        calls: std::sync::Mutex<Vec<RecordedCall>>,
        resp: crate::http::HttpFetchResponse,
        get_supported: bool,
    }

    impl RecordingHttp {
        fn new(resp: crate::http::HttpFetchResponse, get_supported: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: Default::default(),
                resp,
                get_supported,
            })
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for RecordingHttp {
        async fn get(&self, _url: &str) -> Result<crate::http::HttpFetchResponse> {
            Err(Error::Internal("unexpected GET".into()))
        }

        async fn post_form(
            &self,
            url: &str,
            _form: &[(String, String)],
            headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            self.calls
                .lock()
                .unwrap()
                .push(("POST".into(), url.into(), headers.to_vec()));
            Ok(self.resp.clone())
        }

        async fn get_with_headers(
            &self,
            url: &str,
            headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            if !self.get_supported {
                return Err(Error::Config("no get_with_headers".into()));
            }
            self.calls
                .lock()
                .unwrap()
                .push(("GET".into(), url.into(), headers.to_vec()));
            Ok(self.resp.clone())
        }
    }

    fn json_userinfo(content_type: &str) -> crate::http::HttpFetchResponse {
        crate::http::HttpFetchResponse {
            status: 200,
            body: br#"{"sub":"s1","name":"A"}"#.to_vec(),
            content_type: Some(content_type.into()),
            ..Default::default()
        }
    }

    const UI_URL: &str = "https://op.example.org/userinfo";
    const UI_ISS: &str = "https://op.example.org";

    #[tokio::test]
    async fn userinfo_get_sends_bearer_without_post() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let resp = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Get)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "GET");
        assert_eq!(calls[0].1, UI_URL);
        assert_eq!(
            calls[0].2,
            vec![("authorization".to_string(), "Bearer at".to_string())]
        );
    }

    #[tokio::test]
    async fn userinfo_get_without_client_support_errors() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), false);
        let http: Arc<dyn HttpClient> = rec.clone();
        let res = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Get).await;
        assert!(res.is_err());
        assert!(rec.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn userinfo_post_matches_fetch_userinfo() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let claims = fetch_userinfo(&http, UI_URL, "at", "s1", UI_ISS)
            .await
            .unwrap();
        assert_eq!(claims["name"], "A");
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "POST");
        assert_eq!(
            calls[0].2,
            vec![("authorization".to_string(), "Bearer at".to_string())]
        );
    }

    #[tokio::test]
    async fn userinfo_raw_jwt_returned_untouched_but_rejected_as_json() {
        let jwt_resp = crate::http::HttpFetchResponse {
            status: 200,
            body: b"a.b.c".to_vec(),
            content_type: Some("Application/JWT; charset=utf-8".into()),
            ..Default::default()
        };
        let rec = RecordingHttp::new(jwt_resp, true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let resp = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Post)
            .await
            .unwrap();
        assert_eq!(resp.body, b"a.b.c");
        let err = userinfo_json_claims(&resp, "s1").unwrap_err();
        assert!(err.to_string().contains("fetch_userinfo_response"), "{err}");
        assert!(fetch_userinfo(&http, UI_URL, "at", "s1", UI_ISS)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn userinfo_rejects_bad_access_tokens_without_http() {
        for token in ["", "a\r\nb", "a\nb", "a b", "tök", "a\tb", "a\u{7f}b"] {
            let rec = RecordingHttp::new(json_userinfo("application/json"), true);
            let http: Arc<dyn HttpClient> = rec.clone();
            let err = fetch_userinfo_response(&http, UI_URL, token, UI_ISS, UserinfoMethod::Post)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::BadRequest(_)), "{token:?}: {err}");
            assert!(!err.to_string().contains("tök"));
            assert!(rec.calls.lock().unwrap().is_empty(), "{token:?}");
        }
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        fetch_userinfo_response(&http, UI_URL, "abc-._~+/=", UI_ISS, UserinfoMethod::Post)
            .await
            .unwrap();
        assert_eq!(rec.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn userinfo_200_error_detection_only_for_json_objects() {
        // A large JWT-like body is returned untouched.
        let big = format!("eyJhbGciOiJFUzI1NiJ9.{}.sig", "A".repeat(100_000));
        let rec = RecordingHttp::new(crate::http::HttpFetchResponse::new(200, big.clone()), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        let resp = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Post)
            .await
            .unwrap();
        assert_eq!(resp.body, big.as_bytes());
        // An error object, even after leading whitespace, still errors.
        for body in [r#"{"error":"invalid_token"}"#, "\n  {\"error\":\"x\"}"] {
            let rec = RecordingHttp::new(crate::http::HttpFetchResponse::new(200, body), true);
            let http: Arc<dyn HttpClient> = rec.clone();
            let err = fetch_userinfo_response(&http, UI_URL, "at", UI_ISS, UserinfoMethod::Post)
                .await
                .unwrap_err();
            assert!(err.upstream_http().is_some(), "{body}");
        }
    }

    #[test]
    fn upstream_kind_maps_prefix_and_auth_flag() {
        let resp = crate::http::HttpFetchResponse::new(500, "");
        let auth = upstream_error(UpstreamKind::Auth, "x failed", &resp);
        assert_eq!(auth.to_string(), "authentication error: x failed");
        assert!(auth.is_auth_failure());
        let meta = upstream_error(UpstreamKind::Metadata, "y failed", &resp);
        assert_eq!(meta.to_string(), "internal error: y failed");
        assert!(!meta.is_auth_failure());
    }

    fn signed_userinfo(
        key: &SigningKey,
        tweak: impl FnOnce(&mut Claims),
    ) -> (crate::http::HttpFetchResponse, JwkSet) {
        let (token, jwks) = opts_token(key, tweak);
        let resp = crate::http::HttpFetchResponse::new(200, token)
            .with_header("Content-Type", "application/jwt; charset=utf-8");
        (resp, jwks)
    }

    #[test]
    fn userinfo_signed_claims_verifies_and_binds() {
        let (_c, _p, key) = client_and_provider();
        let es = [JwsAlgorithm::ES256];
        let o = UserinfoJwtOptions::dedicated_keys();
        let (iss, aud) = ("https://op.example.org", "https://rp.example.com");

        let (resp, jwks) = signed_userinfo(&key, |_| {});
        let v = userinfo_signed_claims(&jwks, &resp, iss, aud, "subject", &es, &o).unwrap();
        assert_eq!(v["sub"], "subject");

        // Wrong subject, issuer and audience are rejected.
        assert!(userinfo_signed_claims(&jwks, &resp, iss, aud, "other", &es, &o).is_err());
        assert!(
            userinfo_signed_claims(&jwks, &resp, "https://evil", aud, "subject", &es, &o).is_err()
        );
        assert!(userinfo_signed_claims(&jwks, &resp, iss, "other-rp", "subject", &es, &o).is_err());

        // A signature from a different key is rejected.
        let (_, _, other) = client_and_provider();
        assert!(userinfo_signed_claims(
            &other.to_public_jwks(),
            &resp,
            iss,
            aud,
            "subject",
            &es,
            &o
        )
        .is_err());

        // Algorithm allow-list is enforced; an empty list is a configuration error.
        assert!(userinfo_signed_claims(
            &jwks,
            &resp,
            iss,
            aud,
            "subject",
            &[JwsAlgorithm::RS256],
            &o
        )
        .is_err());
        let err = userinfo_signed_claims(&jwks, &resp, iss, aud, "subject", &[], &o).unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));

        // A JSON-typed response is not accepted as signed userinfo.
        let json = json_userinfo("application/json");
        assert!(userinfo_signed_claims(&jwks, &json, iss, aud, "s1", &es, &o).is_err());

        // A tampered token fails verification.
        let mut bad = resp.clone();
        let n = bad.body.len();
        bad.body[n - 3] = if bad.body[n - 3] == b'A' { b'B' } else { b'A' };
        assert!(userinfo_signed_claims(&jwks, &bad, iss, aud, "subject", &es, &o).is_err());
    }

    #[test]
    fn userinfo_signed_claims_require_exp_is_opt_in() {
        let (_c, _p, key) = client_and_provider();
        let es = [JwsAlgorithm::ES256];
        let o = UserinfoJwtOptions::dedicated_keys();
        let req = UserinfoJwtOptions::dedicated_keys().with_require_exp();
        let (iss, aud) = ("https://op.example.org", "https://rp.example.com");

        let (no_exp, jwks) = signed_userinfo(&key, |c| c.exp = None);
        userinfo_signed_claims(&jwks, &no_exp, iss, aud, "subject", &es, &o).unwrap();
        assert!(userinfo_signed_claims(&jwks, &no_exp, iss, aud, "subject", &es, &req).is_err());

        let (with_exp, jwks) = signed_userinfo(&key, |_| {});
        userinfo_signed_claims(&jwks, &with_exp, iss, aud, "subject", &es, &req).unwrap();
    }

    fn signed_userinfo_typ(
        key: &SigningKey,
        typ: Option<&str>,
        extra: &[(&str, &str)],
    ) -> (crate::http::HttpFetchResponse, JwkSet) {
        let now = now_secs();
        let mut c = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Single("https://rp.example.com".into())),
            iat: Some(now),
            ..Default::default()
        };
        for (k, v) in extra {
            c.extra.insert((*k).into(), serde_json::json!(v));
        }
        let token = jwt::sign(key, &c, typ).unwrap();
        let resp = crate::http::HttpFetchResponse::new(200, token)
            .with_header("Content-Type", "application/jwt");
        (resp, key.to_public_jwks())
    }

    const USERINFO_ISS_AUD: (&str, &str) = ("https://op.example.org", "https://rp.example.com");

    fn run_userinfo(
        resp: &crate::http::HttpFetchResponse,
        jwks: &JwkSet,
        o: &UserinfoJwtOptions<'_>,
    ) -> Result<serde_json::Value> {
        let (iss, aud) = USERINFO_ISS_AUD;
        userinfo_signed_claims(jwks, resp, iss, aud, "subject", &[JwsAlgorithm::ES256], o)
    }

    #[test]
    fn userinfo_markers_refused_in_every_mode() {
        let (_c, _p, key) = client_and_provider();
        let modes = [
            UserinfoJwtOptions::dedicated_keys(),
            UserinfoJwtOptions::untyped_shared_key_compat(),
        ];
        for o in &modes {
            let (ok, jwks) = signed_userinfo_typ(&key, None, &[("name", "A")]);
            assert_eq!(run_userinfo(&ok, &jwks, o).unwrap()["name"], "A");
            for claim in ["nonce", "at_hash", "c_hash"] {
                let (resp, jwks) = signed_userinfo_typ(&key, None, &[(claim, "x")]);
                let err = run_userinfo(&resp, &jwks, o).unwrap_err();
                assert!(err.to_string().contains("id_token"), "{claim}: {err}");
            }
            for typ in [
                "id_token+jwt",
                "ID_Token+JWT",
                "at+jwt",
                "application/id_token+jwt",
                "Application/AT+JWT",
                "application/at+jwt; charset=utf-8",
            ] {
                let (resp, jwks) = signed_userinfo_typ(&key, Some(typ), &[]);
                assert!(run_userinfo(&resp, &jwks, o).is_err(), "{typ}");
            }
        }
        // typed(): markers are refused even when the typ matches.
        let typed = UserinfoJwtOptions::typed("userinfo+jwt");
        let (resp, jwks) = signed_userinfo_typ(&key, Some("userinfo+jwt"), &[("nonce", "x")]);
        assert!(run_userinfo(&resp, &jwks, &typed).is_err());
    }

    #[test]
    fn userinfo_typed_requires_exact_typ() {
        let (_c, _p, key) = client_and_provider();
        let want = UserinfoJwtOptions::typed("userinfo+jwt");
        let (typed, jwks) = signed_userinfo_typ(&key, Some("userinfo+jwt"), &[]);
        run_userinfo(&typed, &jwks, &want).unwrap();
        let (untyped, jwks) = signed_userinfo_typ(&key, None, &[]);
        assert!(run_userinfo(&untyped, &jwks, &want).is_err());
        let (other, jwks) = signed_userinfo_typ(&key, Some("other+jwt"), &[]);
        assert!(run_userinfo(&other, &jwks, &want).is_err());
    }

    #[test]
    fn userinfo_typed_rejects_generic_typ() {
        let (_c, _p, key) = client_and_provider();
        let (resp, jwks) = signed_userinfo_typ(&key, Some("userinfo+jwt"), &[]);
        for typ in [
            "",
            "JWT",
            "jwt",
            "id_token+jwt",
            "ID_TOKEN+JWT",
            "at+jwt",
            "application/jwt",
            "Application/JWT",
            " application/jwt ",
            "application/id_token+jwt",
            "application/at+jwt",
            "application/",
            "application/jwt; charset=utf-8",
        ] {
            let err = run_userinfo(&resp, &jwks, &UserinfoJwtOptions::typed(typ)).unwrap_err();
            assert!(matches!(err, Error::BadRequest(_)), "{typ:?}: {err}");
        }
    }

    #[test]
    fn userinfo_audience_must_be_exactly_the_client() {
        let (_c, _p, key) = client_and_provider();
        let (iss, rp) = USERINFO_ISS_AUD;
        let sign_aud = |aud: Audience| {
            let c = Claims {
                iss: Some(iss.into()),
                sub: Some("subject".into()),
                aud: Some(aud),
                iat: Some(now_secs()),
                ..Default::default()
            };
            let token = jwt::sign(&key, &c, Some("userinfo+jwt")).unwrap();
            crate::http::HttpFetchResponse::new(200, token)
                .with_header("Content-Type", "application/jwt")
        };
        let jwks = key.to_public_jwks();
        let modes = [
            UserinfoJwtOptions::typed("userinfo+jwt"),
            UserinfoJwtOptions::dedicated_keys(),
            UserinfoJwtOptions::untyped_shared_key_compat(),
        ];
        for o in &modes {
            // Accepted: the client alone, as a string or a one-element array.
            run_userinfo(&sign_aud(Audience::Single(rp.into())), &jwks, o).unwrap();
            run_userinfo(&sign_aud(Audience::Multiple(vec![rp.into()])), &jwks, o).unwrap();
            // Refused: another audience (rejected by jose-rs itself) ...
            assert!(run_userinfo(
                &sign_aud(Audience::Single("https://other-service.invalid".into())),
                &jwks,
                o
            )
            .is_err());
            // ... and the client plus another, or duplicates (our check).
            for aud in [
                Audience::Multiple(vec![rp.into(), "https://other-service.invalid".into()]),
                Audience::Multiple(vec!["https://other-service.invalid".into(), rp.into()]),
                Audience::Multiple(vec![rp.into(), rp.into()]),
            ] {
                let err = run_userinfo(&sign_aud(aud), &jwks, o).unwrap_err();
                assert!(matches!(err, Error::Authn(_)), "{err}");
            }
        }
    }

    fn kidless_key_and_response() -> (SigningKey, crate::http::HttpFetchResponse) {
        // A key without a kid signs a token that names no key.
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), None).unwrap();
        let c = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Single("https://rp.example.com".into())),
            iat: Some(now_secs()),
            ..Default::default()
        };
        let token = jwt::sign(&key, &c, Some("userinfo+jwt")).unwrap();
        assert!(jwt::peek_header(&token).unwrap().kid.is_none());
        let resp = crate::http::HttpFetchResponse::new(200, token)
            .with_header("Content-Type", "application/jwt");
        (key, resp)
    }

    fn all_modes() -> Vec<UserinfoJwtOptions<'static>> {
        vec![
            UserinfoJwtOptions::typed("userinfo+jwt"),
            UserinfoJwtOptions::dedicated_keys(),
            UserinfoJwtOptions::untyped_shared_key_compat(),
        ]
    }

    #[test]
    fn userinfo_requires_kid_by_default_in_every_mode() {
        let (key, resp) = kidless_key_and_response();
        let jwks = key.to_public_jwks();
        for o in all_modes() {
            let err = run_userinfo(&resp, &jwks, &o).unwrap_err();
            assert!(err.to_string().contains("allow_missing_kid"), "{err}");
        }
        // A token that names a key is unaffected.
        let (_c, _p, trusted) = client_and_provider();
        let (ok, jwks) = signed_userinfo_typ(&trusted, None, &[]);
        run_userinfo(&ok, &jwks, &UserinfoJwtOptions::dedicated_keys()).unwrap();
    }

    #[test]
    fn userinfo_allow_missing_kid_only_for_a_single_key_set() {
        let (key, resp) = kidless_key_and_response();
        // In spec: one key, no kid. Accepted when the caller opts in, in every mode.
        let single = key.to_public_jwks();
        assert_eq!(single.keys.len(), 1);
        for o in all_modes() {
            let o = o.allow_missing_kid();
            assert_eq!(run_userinfo(&resp, &single, &o).unwrap()["sub"], "subject");
        }

        // Out of spec and ambiguous: several keys. The opt-in does not help.
        let (_c, _p, other) = client_and_provider();
        let mut mixed = other.to_public_jwks();
        mixed.keys.extend(key.to_public_jwks().keys);
        assert_eq!(mixed.keys.len(), 2);
        for o in all_modes() {
            let err = run_userinfo(&resp, &mixed, &o.allow_missing_kid()).unwrap_err();
            assert!(err.to_string().contains("several keys"), "{err}");
        }
        // Without the opt-in the single-key case is also refused (covered above),
        // and a kid that is present but unknown is refused either way.
        let (_c, _p, trusted) = client_and_provider();
        let (named, _) = signed_userinfo_typ(&trusted, None, &[]);
        let wrong_set = key.to_public_jwks();
        assert!(run_userinfo(
            &named,
            &wrong_set,
            &UserinfoJwtOptions::dedicated_keys().allow_missing_kid()
        )
        .is_err());
    }

    #[test]
    fn userinfo_dedicated_keys_accepts_untyped_token() {
        let (_c, _p, key) = client_and_provider();
        let (resp, jwks) = signed_userinfo_typ(&key, None, &[]);
        run_userinfo(&resp, &jwks, &UserinfoJwtOptions::dedicated_keys()).unwrap();
    }

    #[test]
    fn compat_mode_accepts_unmarked_fresh_token_known_limitation() {
        let (_c, _p, key) = client_and_provider();
        // id_token-shaped (iss/sub/aud/iat/exp) but without nonce/at_hash/c_hash.
        let (resp, jwks) = signed_userinfo(&key, |_| {});
        let o = UserinfoJwtOptions::untyped_shared_key_compat();
        assert_eq!(run_userinfo(&resp, &jwks, &o).unwrap()["sub"], "subject");
    }

    #[test]
    fn userinfo_builders_apply_in_every_mode() {
        let (_c, _p, key) = client_and_provider();
        let modes: [fn() -> UserinfoJwtOptions<'static>; 3] = [
            || UserinfoJwtOptions::typed("userinfo+jwt"),
            UserinfoJwtOptions::dedicated_keys,
            UserinfoJwtOptions::untyped_shared_key_compat,
        ];
        for mode in modes {
            let typ = Some("userinfo+jwt");
            let sign = |tweak: &dyn Fn(&mut Claims)| {
                let (token, jwks) = opts_token_typ(&key, typ, tweak);
                let resp = crate::http::HttpFetchResponse::new(200, token)
                    .with_header("Content-Type", "application/jwt");
                (resp, jwks)
            };
            // Age bound.
            let (old, jwks) = sign(&|c| {
                c.iat = Some(now_secs() - 3600);
                c.exp = None;
            });
            assert!(run_userinfo(&old, &jwks, &mode()).is_err());
            run_userinfo(&old, &jwks, &mode().without_max_age()).unwrap();
            let (recent, jwks) = sign(&|c| {
                c.iat = Some(now_secs() - 200);
                c.exp = None;
            });
            run_userinfo(&recent, &jwks, &mode()).unwrap();
            assert!(run_userinfo(&recent, &jwks, &mode().with_max_age(10)).is_err());
            // require_exp.
            let (no_exp, jwks) = sign(&|c| c.exp = None);
            run_userinfo(&no_exp, &jwks, &mode()).unwrap();
            assert!(run_userinfo(&no_exp, &jwks, &mode().with_require_exp()).is_err());
        }
    }

    #[test]
    fn userinfo_signed_claims_age_bound() {
        let (_c, _p, key) = client_and_provider();
        let es = [JwsAlgorithm::ES256];
        let o = UserinfoJwtOptions::dedicated_keys();
        let undated = UserinfoJwtOptions::dedicated_keys().without_max_age();
        let (iss, aud) = ("https://op.example.org", "https://rp.example.com");
        let run =
            |resp: &crate::http::HttpFetchResponse, jwks: &JwkSet, o: &UserinfoJwtOptions<'_>| {
                userinfo_signed_claims(jwks, resp, iss, aud, "subject", &es, o)
            };

        // Old iat, no exp: rejected by default, accepted without the bound.
        let (old, jwks) = signed_userinfo(&key, |c| {
            c.iat = Some(now_secs() - 3600);
            c.exp = None;
        });
        assert!(run(&old, &jwks, &o).is_err());
        run(&old, &jwks, &undated).unwrap();

        // Missing iat: rejected by default, accepted without the bound.
        let (no_iat, jwks) = signed_userinfo(&key, |c| {
            c.iat = None;
            c.exp = None;
        });
        assert!(run(&no_iat, &jwks, &o).is_err());
        run(&no_iat, &jwks, &undated).unwrap();

        // A custom bound applies.
        let (recent, jwks) = signed_userinfo(&key, |c| {
            c.iat = Some(now_secs() - 200);
            c.exp = None;
        });
        run(&recent, &jwks, &o).unwrap();
        assert!(run(
            &recent,
            &jwks,
            &UserinfoJwtOptions::dedicated_keys().with_max_age(10)
        )
        .is_err());
    }

    #[test]
    fn userinfo_json_claims_accepts_charset_and_binds_sub() {
        let resp = json_userinfo("application/json; charset=utf-8");
        assert_eq!(userinfo_json_claims(&resp, "s1").unwrap()["sub"], "s1");
        let err = userinfo_json_claims(&resp, "other").unwrap_err();
        assert!(err.to_string().contains("userinfo sub does not match"));
    }

    #[tokio::test]
    async fn userinfo_loopback_endpoint_under_remote_issuer_rejected_before_http() {
        let rec = RecordingHttp::new(json_userinfo("application/json"), true);
        let http: Arc<dyn HttpClient> = rec.clone();
        for method in [UserinfoMethod::Get, UserinfoMethod::Post] {
            let res = fetch_userinfo_response(
                &http,
                "http://127.0.0.1:8080/userinfo",
                "at",
                UI_ISS,
                method,
            )
            .await;
            assert!(res.is_err());
        }
        assert!(rec.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn discover_and_jwks_failures_are_upstream_http() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(404, "nope")),
            post: None,
        });
        let err = discover(&http, "https://op.example.com").await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "internal error: discovery failed (404) for https://op.example.com/.well-known/openid-configuration"
        );
        assert_eq!(err.upstream_http().unwrap().status, Some(404));

        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(crate::http::HttpFetchResponse::new(500, "")),
            post: None,
        });
        let err = fetch_jwks(
            &http,
            "https://op.example.org/jwks",
            "https://op.example.org",
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "internal error: jwks fetch failed (500)");
        assert_eq!(err.upstream_http().unwrap().body, None);
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

    fn opts_token(key: &SigningKey, tweak: impl FnOnce(&mut Claims)) -> (String, JwkSet) {
        opts_token_typ(key, None, tweak)
    }

    fn opts_token_typ(
        key: &SigningKey,
        typ: Option<&str>,
        tweak: impl FnOnce(&mut Claims),
    ) -> (String, JwkSet) {
        let now = now_secs();
        let mut c = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Single("https://rp.example.com".into())),
            iat: Some(now),
            exp: Some(now + 300),
            ..Default::default()
        };
        tweak(&mut c);
        (jwt::sign(key, &c, typ).unwrap(), key.to_public_jwks())
    }

    fn verify_with(
        jwks: &JwkSet,
        token: &str,
        alg: JwsAlgorithm,
        options: &IdTokenOptions<'_>,
    ) -> Result<Claims> {
        verify_id_token_with(
            jwks,
            token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[alg],
            &[],
            options,
        )
    }

    #[test]
    fn id_token_kid_must_name_a_key_in_the_set() {
        // Signer labels the token "nonexistent"; the published keys carry no kid.
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let forger =
            signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some("nonexistent"))
                .unwrap();
        let (token, mut single) = opts_token(&forger, |_| {});
        assert_eq!(
            jwt::peek_header(&token).unwrap().kid.as_deref(),
            Some("nonexistent")
        );
        for k in &mut single.keys {
            k.kid = None;
        }
        let es = JwsAlgorithm::ES256;
        let err = verify_with(&single, &token, es, &IdTokenOptions::new()).unwrap_err();
        assert!(err.to_string().contains("does not name a key"), "{err}");

        let (_c, _p, other) = client_and_provider();
        let mut mixed = other.to_public_jwks();
        mixed.keys.extend(single.keys.clone());
        let err = verify_with(&mixed, &token, es, &IdTokenOptions::new()).unwrap_err();
        assert!(err.to_string().contains("does not name a key"), "{err}");
    }

    #[test]
    fn userinfo_kid_must_name_a_key_in_the_set() {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let forger =
            signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some("nonexistent"))
                .unwrap();
        let c = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Single("https://rp.example.com".into())),
            iat: Some(now_secs()),
            ..Default::default()
        };
        let token = jwt::sign(&forger, &c, Some("userinfo+jwt")).unwrap();
        let resp = crate::http::HttpFetchResponse::new(200, token)
            .with_header("Content-Type", "application/jwt");
        let mut single = forger.to_public_jwks();
        for k in &mut single.keys {
            k.kid = None;
        }
        let (_c, _p, other) = client_and_provider();
        let mut mixed = other.to_public_jwks();
        mixed.keys.extend(single.keys.clone());
        for jwks in [&single, &mixed] {
            for o in all_modes() {
                let err = run_userinfo(&resp, jwks, &o).unwrap_err();
                assert!(err.to_string().contains("does not name a key"), "{err}");
            }
            // Opting out of the kid requirement does not skip the match.
            let o = UserinfoJwtOptions::dedicated_keys().allow_missing_kid();
            assert!(run_userinfo(&resp, jwks, &o).is_err());
        }
    }

    #[test]
    fn default_leeway_constant_matches_jose() {
        assert_eq!(Validation::default().leeway, DEFAULT_LEEWAY);
    }

    #[test]
    fn id_token_kid_required_only_for_multi_key_sets() {
        // One key without a kid, and a second unrelated key.
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let kidless =
            signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), None).unwrap();
        let (_c, _p, other) = client_and_provider();
        let es = JwsAlgorithm::ES256;

        let (token, single) = opts_token(&kidless, |_| {});
        assert!(jwt::peek_header(&token).unwrap().kid.is_none());
        // In spec: a single-key set needs no kid, for the wrapper and the options API.
        verify_with(&single, &token, es, &IdTokenOptions::new()).unwrap();
        verify_id_token(
            &single,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[es],
            &[],
        )
        .unwrap();

        // Several keys: a kid-less token is refused, through both entry points.
        let mut mixed = other.to_public_jwks();
        mixed.keys.extend(single.keys.clone());
        assert_eq!(mixed.keys.len(), 2);
        let err = verify_with(&mixed, &token, es, &IdTokenOptions::new()).unwrap_err();
        assert!(err.to_string().contains("several keys"), "{err}");
        assert!(verify_id_token(
            &mixed,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[es],
            &[],
        )
        .is_err());

        // A token that names its key still verifies against the same multi-key set.
        let (named, _) = opts_token(&other, |_| {});
        assert!(jwt::peek_header(&named).unwrap().kid.is_some());
        verify_with(&mixed, &named, es, &IdTokenOptions::new()).unwrap();
    }

    #[test]
    fn id_token_options_leeway() {
        let (_c, _p, key) = client_and_provider();
        let now = now_secs();
        let (token, jwks) = opts_token(&key, |c| c.exp = Some(now - 30));
        let es = JwsAlgorithm::ES256;
        verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[es],
            &[],
        )
        .unwrap();
        assert!(verify_with(&jwks, &token, es, &IdTokenOptions::new().with_leeway(0)).is_err());
        verify_with(&jwks, &token, es, &IdTokenOptions::new().with_leeway(60)).unwrap();
    }

    #[test]
    fn id_token_options_leeway_is_bounded_and_not_added_to_max_age() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let now = now_secs();

        // A leeway above the cap is a configuration error, even for a valid token.
        let (token, jwks) = opts_token(&key, |_| {});
        let err = verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(MAX_ID_TOKEN_LEEWAY + 1),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
        assert!(verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(u64::MAX)
        )
        .is_err());
        verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(MAX_ID_TOKEN_LEEWAY),
        )
        .unwrap();

        // An expired token is not revived by a huge leeway.
        let (token, jwks) = opts_token(&key, |c| c.exp = Some(now - 86_400 * 365));
        assert!(verify_with(
            &jwks,
            &token,
            es,
            &IdTokenOptions::new().with_leeway(u64::MAX)
        )
        .is_err());

        // Leeway does not stretch max_age: 100s old with max_age 60 fails
        // even with the maximum leeway.
        let (token, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now - 100).into());
        });
        let opts = IdTokenOptions::new()
            .with_max_age(60)
            .with_leeway(MAX_ID_TOKEN_LEEWAY);
        assert!(verify_with(&jwks, &token, es, &opts).is_err());
        let opts = IdTokenOptions::new().with_max_age(120);
        verify_with(&jwks, &token, es, &opts).unwrap();
    }

    #[test]
    fn id_token_options_default_equals_verify_id_token() {
        let (_c, _p, key) = client_and_provider();
        let (token, jwks) = opts_token(&key, |_| {});
        let a = verify_with(
            &jwks,
            &token,
            JwsAlgorithm::ES256,
            &IdTokenOptions::default(),
        )
        .unwrap();
        let b = verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .unwrap();
        assert_eq!(a.sub, b.sub);
        assert_eq!(a.exp, b.exp);
    }

    #[test]
    fn id_token_options_max_age() {
        let (_c, _p, key) = client_and_provider();
        let now = now_secs();
        let es = JwsAlgorithm::ES256;
        let opts = IdTokenOptions::new().with_max_age(300);

        let (t, jwks) = opts_token(&key, |_| {});
        let err = verify_with(&jwks, &t, es, &opts).unwrap_err();
        assert!(err.to_string().contains("auth_time"), "{err}");

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now - 1000).into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now - 10).into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), (now + 3600).into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), "123".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), 1.5.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        // Float auth_time values are accepted as numbers (fraction floored).
        let (t, jwks) = opts_token(&key, |c| {
            c.extra
                .insert("auth_time".into(), serde_json::json!((now - 10) as f64));
        });
        verify_with(&jwks, &t, es, &opts).unwrap();

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("auth_time".into(), serde_json::json!(1.0e9));
        });
        let err = verify_with(&jwks, &t, es, &opts).unwrap_err();
        assert!(err.to_string().contains("older than max_age"), "{err}");

        // Non-numbers and negative values are invalid, not "missing".
        for bad in [
            serde_json::json!("123"),
            serde_json::json!(-5),
            serde_json::json!(-5.5),
            serde_json::json!(null),
        ] {
            let (t, jwks) = opts_token(&key, |c| {
                c.extra.insert("auth_time".into(), bad.clone());
            });
            let err = verify_with(&jwks, &t, es, &opts).unwrap_err();
            assert!(
                err.to_string().contains("auth_time is not a valid number"),
                "{bad}: {err}"
            );
        }

        // Old iat (still within exp) but recent auth_time: max_age is not iat-based.
        let (t, jwks) = opts_token(&key, |c| {
            c.iat = Some(now - 5000);
            c.exp = Some(now + 300);
            c.extra.insert("auth_time".into(), (now - 10).into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();
    }

    #[test]
    fn id_token_options_acr() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let allowed = ["urn:acr:high", "urn:acr:mid"];
        let opts = IdTokenOptions::new().with_acr_values(&allowed);

        let (t, jwks) = opts_token(&key, |_| {});
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("acr".into(), "urn:acr:low".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("acr".into(), 2.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("acr".into(), "urn:acr:mid".into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();

        let empty: [&str; 0] = [];
        let err = verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().with_acr_values(&empty),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn id_token_options_at_hash() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let at = "access-token-value";
        let opts = IdTokenOptions::new().with_access_token(at);

        let good = jwt::oidc_token_hash(es, at).unwrap();
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();
        // Present but nothing supplied to check it against: refused by default,
        // accepted only on request (and by the 0.8-compatible wrapper).
        let err = verify_with(&jwks, &t, es, &IdTokenOptions::new()).unwrap_err();
        assert!(err.to_string().contains("at_hash"), "{err}");
        verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().allow_unchecked_hashes(),
        )
        .unwrap();
        verify_id_token(
            &jwks,
            &t,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[es],
            &[],
        )
        .unwrap();
        // Different access token: mismatch.
        assert!(verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().with_access_token("other")
        )
        .is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), "AAAA".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), 5.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        // Absent at_hash is accepted unless explicitly required.
        let (t, jwks) = opts_token(&key, |_| {});
        verify_with(&jwks, &t, es, &opts).unwrap();
        let required = IdTokenOptions::new()
            .with_access_token(at)
            .with_required_at_hash();
        assert!(verify_with(&jwks, &t, es, &required).is_err());
        // Required and present and matching passes.
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es, &required).unwrap();
        // Requiring at_hash without an access token is a configuration error.
        let err = verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions {
                require_at_hash: true,
                ..IdTokenOptions::new()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn id_token_options_c_hash() {
        let (_c, _p, key) = client_and_provider();
        let es = JwsAlgorithm::ES256;
        let code = "authorization-code-value";
        let opts = IdTokenOptions::new().with_authorization_code(code);
        let required = IdTokenOptions::new()
            .with_authorization_code(code)
            .with_required_c_hash();

        let good = jwt::oidc_token_hash(es, code).unwrap();
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("c_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es, &opts).unwrap();
        verify_with(&jwks, &t, es, &required).unwrap();
        // Present but nothing supplied to check it against: refused by default.
        let err = verify_with(&jwks, &t, es, &IdTokenOptions::new()).unwrap_err();
        assert!(err.to_string().contains("c_hash"), "{err}");
        verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().allow_unchecked_hashes(),
        )
        .unwrap();
        // A different code does not match.
        assert!(verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new().with_authorization_code("other")
        )
        .is_err());
        // c_hash does not satisfy at_hash and vice versa.
        assert!(verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions::new()
                .with_access_token(code)
                .with_required_at_hash()
        )
        .is_err());

        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("c_hash".into(), "AAAA".into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("c_hash".into(), 5.into());
        });
        assert!(verify_with(&jwks, &t, es, &opts).is_err());

        // Absent c_hash is accepted unless required.
        let (t, jwks) = opts_token(&key, |_| {});
        verify_with(&jwks, &t, es, &opts).unwrap();
        let err = verify_with(&jwks, &t, es, &required).unwrap_err();
        assert!(err.to_string().contains("missing c_hash"));
        // Requiring c_hash without a code is a configuration error.
        let err = verify_with(
            &jwks,
            &t,
            es,
            &IdTokenOptions {
                require_c_hash: true,
                ..IdTokenOptions::new()
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn id_token_options_at_hash_uses_header_alg() {
        let mut jwk = jose_rs::jwk::generate_ec("P-384").unwrap();
        jwk.alg = Some("ES384".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES384"), Some("k384"))
            .unwrap();
        let at = "access-token-value";
        let opts = IdTokenOptions::new().with_access_token(at);
        let es384 = JwsAlgorithm::ES384;

        let good = jwt::oidc_token_hash(es384, at).unwrap();
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), good.clone().into());
        });
        verify_with(&jwks, &t, es384, &opts).unwrap();

        let sha256 = jwt::oidc_token_hash(JwsAlgorithm::ES256, at).unwrap();
        assert_ne!(sha256, good);
        let (t, jwks) = opts_token(&key, |c| {
            c.extra.insert("at_hash".into(), sha256.clone().into());
        });
        assert!(verify_with(&jwks, &t, es384, &opts).is_err());
    }

    #[test]
    fn public_validators_enforce_documented_rules() {
        assert!(validate_issuer("https://op/?q").is_err());
        assert!(validate_issuer("https://op/#f").is_err());
        assert!(validate_issuer("http://op.example").is_err());
        assert!(validate_issuer("http://localhost:8080").is_ok());
        assert!(validate_redirect_uri_syntax("https://rp.example/cb#frag").is_err());
        assert!(validate_redirect_uri_syntax("com.example.app:/cb").is_ok());
        // Syntax only: these pass and must never be treated as vetted.
        for uri in [
            "http://attacker.example/cb",
            "javascript:alert(1)",
            "file:///x",
        ] {
            assert!(validate_redirect_uri_syntax(uri).is_ok(), "{uri}");
        }
    }

    #[tokio::test]
    async fn discover_issuer_mismatch_escapes_bidi_characters() {
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: Some(metadata_response("https://evil.example.com/\u{202E}x")),
            post: None,
        });
        let text = discover(&http, "https://op.example.com")
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[tokio::test]
    async fn unsupported_token_type_escapes_bidi_characters() {
        let (client, provider, _key) = client_and_provider();
        let http: Arc<dyn HttpClient> = Arc::new(MockHttp {
            get: None,
            post: Some(crate::http::HttpFetchResponse {
                status: 200,
                body: serde_json::json!({
                    "access_token": "a",
                    "id_token": "i",
                    "token_type": "x\u{202E}y",
                })
                .to_string()
                .into_bytes(),
                content_type: Some("application/json".into()),
                ..Default::default()
            }),
        });
        let text = exchange_code(&http, &provider, &client, "code-1", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[test]
    fn untrusted_audience_escapes_bidi_characters() {
        let (_client, _provider, key) = client_and_provider();
        let jwks = key.to_public_jwks();
        let now = now_secs();
        let claims = Claims {
            iss: Some("https://op.example.org".into()),
            sub: Some("subject".into()),
            aud: Some(Audience::Multiple(vec![
                "https://rp.example.com".into(),
                "evil\u{202E}".into(),
            ])),
            iat: Some(now),
            exp: Some(now + 300),
            ..Default::default()
        };
        let token = jwt::sign(&key, &claims, None).unwrap();
        let text = verify_id_token(
            &jwks,
            &token,
            "https://op.example.org",
            "https://rp.example.com",
            None,
            &[JwsAlgorithm::ES256],
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[test]
    fn endpoint_validation_rejects_bidi_formatting_characters() {
        let err = validate_issuer("https://op.example.com/\u{202E}x").unwrap_err();
        assert!(err.to_string().contains("bidi"), "{err}");
        assert!(validate_service_endpoint("jwks_uri", "https://op.example.com/\u{200F}").is_err());
        assert!(!issuer_allows_loopback_http("http://localhost/\u{202E}"));
        for c in [
            '\u{061C}',
            '\u{2028}',
            '\u{2029}',
            '\u{200B}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{3164}',
            '\u{E0001}',
            '\u{FE0F}',
            '\u{180B}',
            '\u{180C}',
            '\u{180D}',
            '\u{180E}',
            '\u{180F}',
            '\u{2065}',
            '\u{E0100}',
        ] {
            // In the path, and in the host (the look-alike issuer case).
            for issuer in [
                format!("https://op.example.com/{c}x"),
                format!("https://op.example.com{c}.evil.invalid"),
                format!("https://{c}op.example.com"),
                format!("https://op.exa{c}mple.com"),
            ] {
                assert!(validate_issuer(&issuer).is_err(), "{c:?} {issuer:?}");
                assert!(
                    validate_service_endpoint("jwks_uri", &issuer).is_err(),
                    "{c:?} {issuer:?}"
                );
                assert!(!issuer_allows_loopback_http(&issuer));
            }
            let issuer = format!("https://op.example.com/{c}x");
            assert!(validate_issuer(&issuer).is_err(), "{c:?}");
            assert!(
                validate_service_endpoint("jwks_uri", &issuer).is_err(),
                "{c:?}"
            );
        }
    }
}
