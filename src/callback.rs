//! Authorization response (callback) parsing, including JARM.
//!
//! [`parse_authorization_response`] and its siblings turn the parameters of an
//! authorization callback (query string, fragment or `form_post` body) into a
//! shape-checked [`AuthorizationResponse`], failing closed. Nothing in the
//! result is trusted: the caller must still check `state` with
//! [`AuthorizationResponse::matches_state`] and `iss` with
//! [`AuthorizationResponse::matches_iss`] (RFC 9207) before exchanging the code.
//!
//! JARM (JWT Secured Authorization Response Mode): a callback carrying a
//! single `response` parameter parses into an unverified stub. Pass it to
//! [`AuthorizationResponse::verify_jarm`] to check the signature and claims
//! and obtain the inner response. Encrypted (JWE) JARM is not supported.

use crate::error::{display_safe, escape_upstream_text, is_invisible_format, Error, Result};
use crate::http::HttpRequestData;
use crate::jwt;
use crate::oauth_error::OAuthErrorCode;
use crate::rp::{ensure_kid_names_key, is_loopback_host, MAX_ID_TOKEN_LEEWAY};
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Audience, Validation};
use std::collections::BTreeMap;

/// Parameters this parser owns; each may appear at most once, and none may
/// ride in the other channel of a GET / POST callback.
const RESPONSE_PARAMS: [&str; 7] = [
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
    "response",
];

/// Every `error` code [`AuthorizationResponse::error_known`] treats as known:
/// RFC 6749 sections 4.1.2.1 and 5.2, OIDC Core 1.0 section 3.1.2.6, the JAR /
/// registration codes and RFC 9449. A superset of [`OAuthErrorCode`].
const KNOWN_ERROR_CODES: [&str; 20] = [
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
    "invalid_scope",
    "access_denied",
    "server_error",
    "temporarily_unavailable",
    "login_required",
    "interaction_required",
    "account_selection_required",
    "consent_required",
    "invalid_request_uri",
    "invalid_request_object",
    "request_not_supported",
    "request_uri_not_supported",
    "registration_not_supported",
    "invalid_dpop_proof",
];

/// Cap (characters) of `code`, `state`, `iss` and the raw `error_uri`.
const RESPONSE_VALUE_MAX: usize = 2048;
/// Cap (characters) of the JARM `response` JWT.
const RESPONSE_JARM_MAX: usize = 32768;
/// Cap (characters) of `error_description_safe`.
const ERROR_DESCRIPTION_SAFE_MAX: usize = 256;

/// How an authorization response was delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResponseMode {
    /// Parameters in the redirect query string.
    ///
    /// The string entry point [`parse_authorization_response_str`] decodes
    /// `application/x-www-form-urlencoded` (as the OAuth specs define for
    /// authorization parameters), so a literal `+` becomes a space. Callers
    /// whose OP sends a raw `+` should percent-decode themselves and use
    /// [`parse_authorization_response`] with pairs.
    Query,
    /// Parameters in the redirect fragment (decoded like [`Self::Query`]).
    Fragment,
    /// Parameters in an auto-submitted POST form.
    FormPost,
    /// JARM: a single signed `response` JWT (over any transport).
    Jwt,
}

/// Options for the `parse_authorization_response*` functions.
///
/// `#[non_exhaustive]`: build with [`AuthorizationResponseOptions::new`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AuthorizationResponseOptions {
    mode: Option<ResponseMode>,
    accept_unverified_jarm: bool,
}

impl AuthorizationResponseOptions {
    /// Default options: mode inferred, JARM `response` rejected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Label the response with the mode it arrived by. Without it, pairs /
    /// strings / multi-maps are [`ResponseMode::Query`] (a string starting
    /// with `#` is [`ResponseMode::Fragment`]) and a request takes its mode
    /// from its method. For a request, a mode that contradicts the method is
    /// `Error::Config`. [`ResponseMode::Jwt`] additionally declares that a
    /// JARM `response` is expected (and permitted) and makes a response
    /// without one a `BadRequest`.
    pub fn with_response_mode(mut self, mode: ResponseMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Permit a JARM `response` parameter. The result is an UNVERIFIED stub
    /// with no code or error; call [`AuthorizationResponse::verify_jarm`] on
    /// it. Without this (or [`ResponseMode::Jwt`]) a `response` is rejected.
    pub fn accept_unverified_jarm(mut self) -> Self {
        self.accept_unverified_jarm = true;
        self
    }
}

/// The callback of an authorization request, parsed and shape-checked.
///
/// Built by the `parse_authorization_response*` functions or
/// [`verify_jarm`](Self::verify_jarm); there is no public constructor.
/// `Debug` never prints `code`, `state` or the JARM `response`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizationResponse {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description_safe: Option<String>,
    error_uri: Option<String>,
    iss: Option<String>,
    jarm_response: Option<String>,
    jarm_verified: bool,
    response_mode: ResponseMode,
}

impl std::fmt::Debug for AuthorizationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let set = |v: &Option<String>| if v.is_some() { "<set>" } else { "None" };
        f.debug_struct("AuthorizationResponse")
            .field("is_error", &self.error.is_some())
            .field("error", &self.error.as_deref().map(display_safe))
            .field("code", &set(&self.code))
            .field("state", &set(&self.state))
            .field("iss", &self.iss.as_deref().map(display_safe))
            .field("response", &set(&self.jarm_response))
            .field("jarm_verified", &self.jarm_verified)
            .field("response_mode", &self.response_mode)
            .finish()
    }
}

impl AuthorizationResponse {
    /// The authorization code, verbatim, or `None` for an error response.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
    /// The `state` echoed by the OP, verbatim. Check it with
    /// [`matches_state`](Self::matches_state).
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
    /// The OAuth error code (RFC 6749 charset, at most 64 characters).
    /// Unknown codes are kept; see [`error_known`](Self::error_known).
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    /// The error code as an [`OAuthErrorCode`], when it is one of its codes.
    pub fn error_code(&self) -> Option<OAuthErrorCode> {
        self.error.as_deref().and_then(|e| e.parse().ok())
    }
    /// True when `error` is in the wider list of codes this crate knows
    /// (RFC 6749, OIDC Core, JAR, DPoP). Wider than [`OAuthErrorCode`].
    pub fn error_known(&self) -> bool {
        self.error
            .as_deref()
            .is_some_and(|e| KNOWN_ERROR_CODES.contains(&e))
    }
    /// True when the response carries an OAuth `error`.
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
    /// `error_description` escaped and capped at 256 characters. The raw
    /// value is not exposed.
    pub fn error_description_safe(&self) -> Option<&str> {
        self.error_description_safe.as_deref()
    }
    /// `error_uri` if it is an absolute https URL (http only for loopback
    /// hosts) without userinfo, in normalised form; otherwise `None`.
    /// Untrusted: never follow it without your own validation.
    pub fn error_uri(&self) -> Option<&str> {
        self.error_uri.as_deref()
    }
    /// The RFC 9207 `iss` parameter (for verified JARM: the JWT `iss`).
    pub fn iss(&self) -> Option<&str> {
        self.iss.as_deref()
    }
    /// The raw JARM `response` JWT, if the callback was JARM. Untrusted
    /// unless [`jarm_verified`](Self::jarm_verified).
    pub fn jarm_response(&self) -> Option<&str> {
        self.jarm_response.as_deref()
    }
    /// True for the result of a successful [`verify_jarm`](Self::verify_jarm).
    pub fn jarm_verified(&self) -> bool {
        self.jarm_verified
    }
    /// How the response arrived.
    pub fn response_mode(&self) -> ResponseMode {
        self.response_mode
    }

    /// `state` check, fail closed: constant-time comparison with `expected`
    /// (the value in the session). A response without `state` yields
    /// `!required`. An empty `expected` always yields false, as does an
    /// unverified JARM stub (call [`verify_jarm`](Self::verify_jarm) first).
    pub fn matches_state(&self, expected: &str, required: bool) -> bool {
        if expected.is_empty() || (self.jarm_response.is_some() && !self.jarm_verified) {
            return false;
        }
        match self.state.as_deref() {
            Some(s) => crate::mac::constant_time_eq(s.as_bytes(), expected.as_bytes()),
            None => !required,
        }
    }

    /// RFC 9207 issuer check, fail closed: exact comparison of `iss` with
    /// `expected`. A response without `iss` yields `!required`. An empty
    /// `expected` always yields false, as does an unverified JARM stub (call
    /// [`verify_jarm`](Self::verify_jarm) first).
    pub fn matches_iss(&self, expected: &str, required: bool) -> bool {
        if expected.is_empty() || (self.jarm_response.is_some() && !self.jarm_verified) {
            return false;
        }
        match self.iss.as_deref() {
            Some(iss) => iss == expected,
            None => !required,
        }
    }

    /// Verify a JARM response and return the inner authorization response
    /// (mode [`ResponseMode::Jwt`], [`jarm_verified`](Self::jarm_verified)).
    ///
    /// # Token substitution
    ///
    /// A JARM response is a JWT signed with the OP's keys, and those keys
    /// often also sign ID tokens (and other JWTs). Without a purpose check, an
    /// attacker holding any such token with matching `iss`/`aud`/`exp` and
    /// string `code`/`state`/`error` claims could pass it off as an
    /// authorization response. The JOSE `typ` header (RFC 8725 §3.11) is what
    /// separates them, so by default the response must carry
    /// [`JarmOptions::with_expected_typ`] (default `oauth-authz-resp+jwt`,
    /// compared case-insensitively, with or without the `application/`
    /// prefix). A present `typ` that differs (`at+jwt`, `id_token+jwt`, ...)
    /// is always `Error::Authn`, and so is a missing one unless you opted in
    /// with [`JarmOptions::with_dedicated_keys`] (the keys sign only JARM) or
    /// [`JarmOptions::allow_untyped_shared_keys`] (compatibility with OPs that
    /// send no `typ`; weaker, since an untyped ID token is then
    /// indistinguishable). With either opt-in a `typ` of exactly `JWT` is
    /// also tolerated.
    ///
    /// Requires a signed JWT (JWE is `BadRequest`), a non-empty algorithm
    /// list, the `typ` rule above, a `kid` naming a key when the set has
    /// several, `iss` equal to
    /// `opts` issuer, `aud` exactly the client id (a string or a one-element array; a multi-valued `aud` is
    /// rejected) and `exp`. The inner parameters must be strings and pass
    /// the same shape rules as a plain callback. Signature / claim failures
    /// are `Error::Authn`; shape failures `Error::BadRequest`.
    ///
    /// Use [`JARM_ASYMMETRIC_ALGORITHMS`] as the allow-list unless you
    /// deliberately sign JARM with the client secret. The algorithm list is
    /// not restricted here, so allowing `HS*` lets anyone holding the shared
    /// secret forge a response; never pass [`crate::JWS_ALGORITHMS`] directly.
    pub fn verify_jarm(
        &self,
        jwks: &JwkSet,
        opts: &JarmOptions<'_>,
    ) -> Result<AuthorizationResponse> {
        let token = match (&self.jarm_response, self.jarm_verified) {
            (Some(t), false) => t.as_str(),
            (Some(_), true) => return Err(bad("JARM response is already verified")),
            (None, _) => return Err(bad("response is not a JARM response")),
        };
        if opts.allowed_algorithms.is_empty() {
            return Err(bad(
                "at least one allowed JARM signing algorithm is required",
            ));
        }
        if opts.issuer.is_empty() || opts.client_id.is_empty() {
            return Err(bad("JARM issuer and client_id must not be empty"));
        }
        if opts.leeway.is_some_and(|l| l > MAX_ID_TOKEN_LEEWAY) {
            return Err(bad(format!(
                "JARM leeway must be at most {MAX_ID_TOKEN_LEEWAY} seconds"
            )));
        }
        match token.split('.').count() {
            3 => {}
            5 => return Err(bad("encrypted JARM not supported")),
            _ => return Err(bad("JARM response is not a compact JWT")),
        }
        let header =
            jwt::peek_header(token).map_err(|_| bad("JARM response header is malformed"))?;
        // Purpose check first and independent of claims: fail closed.
        check_jarm_typ(header.typ.as_deref(), opts)?;
        let mut validation = Validation::new()
            .with_issuer(opts.issuer)
            .with_audience(opts.client_id)
            .require_exp()
            .with_allowed_algorithms(opts.allowed_algorithms.to_vec());
        if let Some(l) = opts.leeway {
            validation = validation.with_leeway(l);
        }
        if jwks.keys.len() > 1 {
            if header.kid.is_none() {
                return Err(Error::Authn(
                    "JARM response has no kid but the JWK Set has several keys".into(),
                ));
            }
            validation = validation.require_kid();
        }
        ensure_kid_names_key(jwks, header.kid.as_deref(), "JARM response")?;
        let claims = jwt::verify_with_jwks(jwks, token, &validation)
            .map_err(|e| Error::Authn(format!("JARM response verification failed: {e}")))?;
        let audience_is_client = match claims.aud.as_ref() {
            Some(Audience::Single(a)) => a == opts.client_id,
            Some(Audience::Multiple(values)) => values.len() == 1 && values[0] == opts.client_id,
            None => false,
        };
        if !audience_is_client {
            return Err(Error::Authn(
                "JARM aud must be exactly the client id".into(),
            ));
        }
        if claims.iss.as_deref() != Some(opts.issuer) {
            return Err(Error::Authn("JARM iss mismatch".into()));
        }
        let string_claim = |name: &str| -> Result<Option<String>> {
            match claims.extra.get(name) {
                None => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(bad(format!("JARM claim {name} must be a string"))),
            }
        };
        let fields = Fields {
            code: string_claim("code")?,
            state: string_claim("state")?,
            error: string_claim("error")?,
            description: string_claim("error_description")?,
            uri: string_claim("error_uri")?,
            iss: claims.iss.clone(),
        };
        let mut out = fields.validate()?;
        out.jarm_response = Some(token.to_string());
        out.jarm_verified = true;
        out.response_mode = ResponseMode::Jwt;
        Ok(out)
    }
}

/// Recommended `allowed_algorithms` for [`JarmOptions::new`]: the asymmetric
/// JWS algorithms (`RS*`, `PS*`, `ES256/384/512`, `EdDSA`).
///
/// This is [`crate::JWS_ALGORITHMS`] without the `HS*` family (shared-secret
/// algorithms let any holder of the secret forge a response) and without
/// `ES256K`, which cannot be verified.
pub const JARM_ASYMMETRIC_ALGORITHMS: &[JwsAlgorithm] = &[
    JwsAlgorithm::RS256,
    JwsAlgorithm::RS384,
    JwsAlgorithm::RS512,
    JwsAlgorithm::PS256,
    JwsAlgorithm::PS384,
    JwsAlgorithm::PS512,
    JwsAlgorithm::ES256,
    JwsAlgorithm::ES384,
    JwsAlgorithm::ES512,
    JwsAlgorithm::EdDSA,
];

/// Default JOSE `typ` required of a JARM response (see
/// [`JarmOptions::with_expected_typ`]): the short form of the JARM media
/// type `application/oauth-authz-resp+jwt`. Both forms are accepted.
pub const JARM_TYP: &str = "oauth-authz-resp+jwt";

/// Normalize a `typ` for comparison: case-insensitive, leading
/// `application/` removed (RFC 7515 §4.1.9).
fn norm_typ(typ: &str) -> String {
    let t = typ.to_ascii_lowercase();
    t.strip_prefix("application/").unwrap_or(&t).to_string()
}

/// The JARM `typ` rule; see [`AuthorizationResponse::verify_jarm`].
fn check_jarm_typ(typ: Option<&str>, opts: &JarmOptions<'_>) -> Result<()> {
    match typ {
        Some(t) => {
            let t = norm_typ(t);
            if t == norm_typ(opts.expected_typ) || (opts.allow_missing_typ && t == "jwt") {
                Ok(())
            } else {
                Err(Error::Authn(
                    "JARM response typ header does not identify a JARM response".into(),
                ))
            }
        }
        None if opts.allow_missing_typ => Ok(()),
        None => Err(Error::Authn(
            "JARM response has no typ header (see JarmOptions::with_dedicated_keys / \
             allow_untyped_shared_keys)"
                .into(),
        )),
    }
}

/// Options for [`AuthorizationResponse::verify_jarm`].
///
/// `#[non_exhaustive]`: build with [`JarmOptions::new`]. By default the
/// response must carry the JOSE `typ` [`JARM_TYP`] (`oauth-authz-resp+jwt`),
/// which stops other JWTs signed by the same OP keys (ID tokens, access
/// tokens) being replayed as an authorization response. See
/// [`AuthorizationResponse::verify_jarm`] for the threat and the rules.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JarmOptions<'a> {
    issuer: &'a str,
    client_id: &'a str,
    allowed_algorithms: &'a [JwsAlgorithm],
    leeway: Option<u64>,
    expected_typ: &'a str,
    allow_missing_typ: bool,
}

impl<'a> JarmOptions<'a> {
    /// Expected issuer, own client id (the exact audience) and the allowed
    /// signing algorithms (must not be empty).
    pub fn new(
        issuer: &'a str,
        client_id: &'a str,
        allowed_algorithms: &'a [JwsAlgorithm],
    ) -> Self {
        Self {
            issuer,
            client_id,
            allowed_algorithms,
            leeway: None,
            expected_typ: JARM_TYP,
            allow_missing_typ: false,
        }
    }

    /// Required JOSE `typ` (default [`JARM_TYP`]). Compared
    /// case-insensitively; the `application/` prefix form is accepted.
    pub fn with_expected_typ(mut self, typ: &'a str) -> Self {
        self.expected_typ = typ;
        self
    }

    /// Assert that the keys in the `JwkSet` sign only JARM responses, so a
    /// token that verifies cannot be another kind of JWT. Permits a MISSING
    /// `typ` (and `typ` `JWT`); any other mismatching `typ` is still
    /// rejected. Only use this when you truly control or know the key usage.
    pub fn with_dedicated_keys(mut self) -> Self {
        self.allow_missing_typ = true;
        self
    }

    /// Compatibility opt-in for OPs that send no `typ` while sharing keys
    /// with ID tokens. Permits a MISSING `typ` (and `typ` `JWT`); any other
    /// mismatching `typ` (`at+jwt`, `id_token+jwt`, ...) is still rejected.
    /// WEAKER: an untyped ID token with string `code`/`state` claims is
    /// accepted, so prefer the default.
    pub fn allow_untyped_shared_keys(mut self) -> Self {
        self.allow_missing_typ = true;
        self
    }

    /// Clock-skew tolerance in seconds (at most [`MAX_ID_TOKEN_LEEWAY`];
    /// more is `Error::BadRequest` at verification).
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = Some(seconds);
        self
    }
}

fn bad(msg: impl Into<String>) -> Error {
    Error::BadRequest(msg.into())
}

/// Raw, not yet validated callback values (from pairs or from JARM claims).
struct Fields {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    description: Option<String>,
    uri: Option<String>,
    iss: Option<String>,
}

impl Fields {
    /// The shared shape rules. Never echoes a value.
    fn validate(self) -> Result<AuthorizationResponse> {
        if self.code.is_some() && self.error.is_some() {
            return Err(bad("code and error must not both be present"));
        }
        if self.code.is_none() && self.error.is_none() {
            return Err(bad("response has neither code nor error"));
        }
        for (name, v) in [
            ("code", &self.code),
            ("state", &self.state),
            ("error", &self.error),
            ("iss", &self.iss),
        ] {
            if v.as_deref() == Some("") {
                return Err(bad(format!("{name} must not be empty")));
            }
        }
        for (name, v) in [
            ("code", &self.code),
            ("state", &self.state),
            ("iss", &self.iss),
        ] {
            if let Some(v) = v {
                check_value(name, v)?;
            }
        }
        if let Some(e) = &self.error {
            check_error_code(e)?;
        }
        Ok(AuthorizationResponse {
            code: self.code,
            state: self.state,
            error: self.error,
            error_description_safe: self
                .description
                .map(|d| escape_upstream_text(&d, ERROR_DESCRIPTION_SAFE_MAX)),
            error_uri: self.uri.and_then(|u| safe_error_uri(&u)),
            iss: self.iss,
            jarm_response: None,
            jarm_verified: false,
            response_mode: ResponseMode::Query,
        })
    }
}

fn check_value(name: &str, v: &str) -> Result<()> {
    if v.chars().count() > RESPONSE_VALUE_MAX {
        return Err(bad(format!(
            "{name} must be at most {RESPONSE_VALUE_MAX} characters"
        )));
    }
    if v.chars()
        .any(|c| c.is_control() || c == '\\' || is_invisible_format(c))
    {
        return Err(bad(format!(
            "{name} must not contain control, bidi or invisible formatting characters or backslashes"
        )));
    }
    Ok(())
}

/// RFC 6749 section 5.2: `error` is %x20-21 / %x23-5B / %x5D-7E, max 64.
fn check_error_code(v: &str) -> Result<()> {
    if v.chars().count() > 64
        || !v
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E))
    {
        return Err(bad(
            "error must be at most 64 characters from the RFC 6749 section 5.2 set",
        ));
    }
    Ok(())
}

/// `error_uri` survives only as a safe absolute https URL (http for loopback),
/// returned normalised so what the caller sees is what was validated.
fn safe_error_uri(uri: &str) -> Option<String> {
    if uri.chars().count() > RESPONSE_VALUE_MAX
        || uri
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\' || is_invisible_format(c))
    {
        return None;
    }
    let u = url::Url::parse(uri).ok()?;
    let host = u.host_str()?;
    let scheme_ok = u.scheme() == "https" || (u.scheme() == "http" && is_loopback_host(host));
    (scheme_ok && u.username().is_empty() && u.password().is_none()).then(|| u.as_str().to_string())
}

fn mode_for_response(opts: &AuthorizationResponseOptions, default: ResponseMode) -> ResponseMode {
    opts.mode.unwrap_or(default)
}

/// Core: owned pairs plus the transport mode.
fn parse_pairs<K: AsRef<str>, V: AsRef<str>>(
    pairs: &[(K, V)],
    opts: &AuthorizationResponseOptions,
    mode: ResponseMode,
) -> Result<AuthorizationResponse> {
    let mut found: BTreeMap<&'static str, String> = BTreeMap::new();
    for (k, v) in pairs {
        if let Some(name) = RESPONSE_PARAMS.iter().find(|n| **n == k.as_ref()) {
            if found.insert(name, v.as_ref().to_string()).is_some() {
                return Err(bad(format!("{name} must not be repeated")));
            }
        }
    }
    let mut take = |n: &str| found.remove(n);
    let fields = Fields {
        code: take("code"),
        state: take("state"),
        error: take("error"),
        description: take("error_description"),
        uri: take("error_uri"),
        iss: take("iss"),
    };
    let response = take("response");
    let jarm_expected = opts.mode == Some(ResponseMode::Jwt);

    if let Some(response) = response {
        if !(opts.accept_unverified_jarm || jarm_expected) {
            return Err(bad(
                "JARM response parameter is not accepted: enable accept_unverified_jarm and verify it",
            ));
        }
        if [
            &fields.code,
            &fields.state,
            &fields.error,
            &fields.description,
            &fields.uri,
            &fields.iss,
        ]
        .iter()
        .any(|v| v.is_some())
        {
            return Err(bad(
                "a JARM response carries every parameter inside the JWT: no other protocol parameter may appear alongside response",
            ));
        }
        if response.is_empty() {
            return Err(bad("response must not be empty"));
        }
        if response.chars().count() > RESPONSE_JARM_MAX {
            return Err(bad(format!(
                "response must be at most {RESPONSE_JARM_MAX} characters"
            )));
        }
        return Ok(AuthorizationResponse {
            code: None,
            state: None,
            error: None,
            error_description_safe: None,
            error_uri: None,
            iss: None,
            jarm_response: Some(response),
            jarm_verified: false,
            response_mode: ResponseMode::Jwt,
        });
    }
    if jarm_expected {
        return Err(bad("expected a JARM response parameter"));
    }
    let mut out = fields.validate()?;
    out.response_mode = mode;
    Ok(out)
}

/// Parse an authorization response from ordered `(name, value)` pairs.
///
/// Fails closed with `Error::BadRequest` on: a repeated parameter, both or
/// neither of `code` and `error`, an empty `code` / `state` / `error` /
/// `iss`, control, bidi / invisible or backslash characters or more than
/// 2048 characters in `code` / `state` / `iss`, an `error` outside RFC 6749
/// section 5.2 (or over 64 characters), and a JARM `response` unless
/// permitted by the options (then it must be the only protocol parameter and
/// at most 32768 characters). Unknown error codes are kept.
pub fn parse_authorization_response<K: AsRef<str>, V: AsRef<str>>(
    pairs: &[(K, V)],
    opts: &AuthorizationResponseOptions,
) -> Result<AuthorizationResponse> {
    parse_pairs(pairs, opts, mode_for_response(opts, ResponseMode::Query))
}

/// Parse a form-urlencoded string (a query string, fragment or form body).
/// One leading `?` or `#` is stripped; a leading `#` defaults the mode to
/// [`ResponseMode::Fragment`].
pub fn parse_authorization_response_str(
    encoded: &str,
    opts: &AuthorizationResponseOptions,
) -> Result<AuthorizationResponse> {
    let (body, default) = match encoded.as_bytes().first() {
        Some(b'?') => (&encoded[1..], ResponseMode::Query),
        Some(b'#') => (&encoded[1..], ResponseMode::Fragment),
        _ => (encoded, ResponseMode::Query),
    };
    let pairs: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parse_pairs(&pairs, opts, mode_for_response(opts, default))
}

/// Parse a multi-map (`name -> values`, like `parse_qs`); repeated values
/// become duplicates and are rejected.
pub fn parse_authorization_response_multi<M, K, Vs, V>(
    map: M,
    opts: &AuthorizationResponseOptions,
) -> Result<AuthorizationResponse>
where
    M: IntoIterator<Item = (K, Vs)>,
    K: AsRef<str>,
    Vs: AsRef<[V]>,
    V: AsRef<str>,
{
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (k, vs) in map {
        for v in vs.as_ref() {
            pairs.push((k.as_ref().to_string(), v.as_ref().to_string()));
        }
    }
    parse_pairs(&pairs, opts, mode_for_response(opts, ResponseMode::Query))
}

/// Parse the callback of an inbound [`HttpRequestData`]: GET reads
/// `query_pairs` (mode query), POST reads `form_pairs` (mode form_post).
///
/// A protocol parameter in the other channel (body of a GET, query of a
/// POST), any other method, or an empty POST form is `Error::BadRequest`.
/// A [`ResponseMode`] option that contradicts the method is `Error::Config`
/// (`Jwt` fits both; `Fragment` never reaches a server).
pub fn parse_authorization_response_request(
    request: &HttpRequestData,
    opts: &AuthorizationResponseOptions,
) -> Result<AuthorizationResponse> {
    let has_protocol =
        |v: &[(String, String)]| v.iter().any(|(k, _)| RESPONSE_PARAMS.contains(&k.as_str()));
    let (pairs, mode) = if request.method.eq_ignore_ascii_case("GET") {
        if has_protocol(&request.form_pairs) {
            return Err(bad(
                "authorization response parameters must not appear in the body of a query callback",
            ));
        }
        (&request.query_pairs, ResponseMode::Query)
    } else if request.method.eq_ignore_ascii_case("POST") {
        if has_protocol(&request.query_pairs) {
            return Err(bad(
                "authorization response parameters must not appear in the query string of a form_post callback",
            ));
        }
        if request.form_pairs.is_empty() {
            return Err(bad("a form_post callback needs a non-empty form body"));
        }
        (&request.form_pairs, ResponseMode::FormPost)
    } else {
        return Err(bad("an authorization response arrives by GET or POST"));
    };
    if let Some(m) = opts.mode {
        if m != mode && m != ResponseMode::Jwt {
            return Err(Error::Config(format!(
                "response mode {m:?} does not match the request method (expected {mode:?})"
            )));
        }
    }
    parse_pairs(pairs, opts, mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{signing_key_from_jwk_json, SigningKey};
    use crate::util::now_secs;
    use jose_rs::jwt::Claims;

    const ISS: &str = "https://op.example.org";
    const CLIENT: &str = "https://rp.example.com";
    const TYP: &str = JARM_TYP;
    const ES: [JwsAlgorithm; 1] = [JwsAlgorithm::ES256];

    fn p(pairs: &[(&str, &str)]) -> Result<AuthorizationResponse> {
        parse_authorization_response(pairs, &AuthorizationResponseOptions::new())
    }

    fn is_bad<T: std::fmt::Debug>(r: Result<T>) {
        assert!(matches!(r, Err(Error::BadRequest(_))), "{r:?}");
    }

    #[test]
    fn success_and_error_responses() {
        let r = p(&[("code", "abc"), ("state", "st"), ("iss", ISS)]).unwrap();
        assert_eq!(r.code(), Some("abc"));
        assert_eq!(r.state(), Some("st"));
        assert_eq!(r.iss(), Some(ISS));
        assert!(!r.is_error());
        assert_eq!(r.response_mode(), ResponseMode::Query);
        let e = p(&[("error", "access_denied"), ("state", "st")]).unwrap();
        assert!(e.is_error() && e.error_known());
        assert_eq!(e.error_code(), Some(OAuthErrorCode::AccessDenied));
        let c = p(&[("error", "consent_required")]).unwrap();
        assert!(c.error_known());
        assert_eq!(c.error_code(), None);
        let u = p(&[("error", "weird_thing")]).unwrap();
        assert!(!u.error_known());
        assert_eq!(u.error(), Some("weird_thing"));
    }

    #[test]
    fn duplicate_parameters_rejected() {
        for name in RESPONSE_PARAMS {
            let pairs = [(name, "x"), ("code", "c"), (name, "y")];
            is_bad(p(&pairs));
        }
        is_bad(p(&[("code", "a"), ("code", "a")]));
    }

    #[test]
    fn exactly_one_of_code_or_error() {
        is_bad(p(&[("code", "a"), ("error", "access_denied")]));
        is_bad(p(&[("state", "s")]));
    }

    #[test]
    fn empty_values_rejected() {
        is_bad(p(&[("code", "")]));
        is_bad(p(&[("code", "a"), ("state", "")]));
        is_bad(p(&[("error", "")]));
        is_bad(p(&[("code", "a"), ("iss", "")]));
    }

    #[test]
    fn hostile_characters_rejected_without_echo() {
        for bad_val in [
            "a\nb",
            "a\u{0}b",
            "a\\b",
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{7f}b",
        ] {
            for name in ["code", "state", "iss"] {
                let mut pairs = vec![("code", "ok")];
                pairs.retain(|(k, _)| *k != name);
                pairs.push((name, bad_val));
                let err = p(&pairs).unwrap_err();
                assert!(matches!(err, Error::BadRequest(_)));
                let msg = err.to_string();
                assert!(!msg.contains(bad_val), "echoed: {msg:?}");
            }
        }
    }

    #[test]
    fn length_caps() {
        let ok = "x".repeat(2048);
        let long = "x".repeat(2049);
        assert!(p(&[("code", &ok), ("state", &ok), ("iss", &ok)]).is_ok());
        for name in ["code", "state", "iss"] {
            let mut pairs = vec![("code", "c")];
            if name == "code" {
                pairs = vec![];
            }
            pairs.push((name, &long));
            is_bad(p(&pairs));
        }
    }

    #[test]
    fn error_code_charset_and_length() {
        assert!(p(&[("error", &"e".repeat(64))]).is_ok());
        is_bad(p(&[("error", &"e".repeat(65))]));
        for bad_val in ["a\"b", "a\\b", "é", "a\tb", "a\u{7f}"] {
            is_bad(p(&[("error", bad_val)]));
        }
        assert!(p(&[("error", "a b!~")]).is_ok());
    }

    #[test]
    fn error_description_is_escaped_and_capped() {
        let r = p(&[
            ("error", "access_denied"),
            ("error_description", "bad\u{1b}[31m\u{202E}"),
        ])
        .unwrap();
        let d = r.error_description_safe().unwrap();
        assert!(!d.contains('\u{1b}') && !d.contains('\u{202E}'));
        assert!(d.contains("\\u{1b}"));
        let long = "d".repeat(1000);
        let r = p(&[("error", "access_denied"), ("error_description", &long)]).unwrap();
        assert_eq!(r.error_description_safe().unwrap().chars().count(), 257);
    }

    #[test]
    fn error_uri_only_when_safe() {
        let uri = |u: &str| {
            p(&[("error", "access_denied"), ("error_uri", u)])
                .unwrap()
                .error_uri()
                .map(str::to_string)
        };
        assert_eq!(
            uri("https://op.example.org/err").as_deref(),
            Some("https://op.example.org/err")
        );
        assert_eq!(
            uri("https:evil.example/x").as_deref(),
            Some("https://evil.example/x")
        );
        assert!(uri("http://localhost:8080/e").is_some());
        assert!(uri("http://[::1]/e").is_some());
        for bad_uri in [
            "http://op.example.org/e",
            "javascript:alert(1)",
            "https://user:pw@op.example.org/e",
            "https://user@op.example.org/e",
            "https://op.example.org/e f",
            "https://op.example.org/e\\x",
            "https://op.example.org/e\n",
            "/relative",
            "ftp://op.example.org/e",
            &format!("https://op.example.org/{}", "a".repeat(2100)),
        ] {
            assert_eq!(uri(bad_uri), None, "{bad_uri}");
        }
    }

    #[test]
    fn matches_state_and_iss() {
        let r = p(&[("code", "c"), ("state", "st"), ("iss", ISS)]).unwrap();
        assert!(r.matches_state("st", true));
        assert!(!r.matches_state("other", true));
        assert!(!r.matches_state("", true) && !r.matches_state("", false));
        assert!(r.matches_iss(ISS, true));
        assert!(!r.matches_iss("https://op.example.org/", true));
        assert!(!r.matches_iss("", true) && !r.matches_iss("", false));
        let n = p(&[("code", "c")]).unwrap();
        assert!(!n.matches_state("st", true) && n.matches_state("st", false));
        assert!(!n.matches_iss(ISS, true) && n.matches_iss(ISS, false));
    }

    #[test]
    fn debug_hides_secrets() {
        let r = p(&[("code", "SECRETCODE"), ("state", "SECRETSTATE")]).unwrap();
        let d = format!("{r:?}");
        assert!(
            !d.contains("SECRETCODE") && !d.contains("SECRETSTATE"),
            "{d}"
        );
        let j = p(&[("response", "SECRETJWT")]);
        is_bad(j);
        let j = parse_authorization_response(
            &[("response", "SECRETJWT")],
            &AuthorizationResponseOptions::new().accept_unverified_jarm(),
        )
        .unwrap();
        assert!(!format!("{j:?}").contains("SECRETJWT"));
    }

    #[test]
    fn jarm_asymmetric_algorithms_are_the_catalogue_minus_hs_and_es256k() {
        let expected: Vec<_> = crate::JWS_ALGORITHMS
            .iter()
            .filter(|a| !crate::is_symmetric_jws_algorithm(a) && **a != JwsAlgorithm::ES256K)
            .collect();
        let got: Vec<_> = JARM_ASYMMETRIC_ALGORITHMS.iter().collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn jarm_param_rules() {
        let opts = AuthorizationResponseOptions::new().accept_unverified_jarm();
        let r = parse_authorization_response(&[("response", "a.b.c")], &opts).unwrap();
        assert_eq!(r.response_mode(), ResponseMode::Jwt);
        assert_eq!(r.jarm_response(), Some("a.b.c"));
        assert!(r.code().is_none() && !r.jarm_verified());
        // An unverified stub never satisfies state/iss checks, even if optional.
        assert!(!r.matches_state("s", false) && !r.matches_iss(ISS, false));
        for extra in RESPONSE_PARAMS.iter().filter(|n| **n != "response") {
            is_bad(parse_authorization_response(
                &[("response", "a.b.c"), (extra, "x")],
                &opts,
            ));
        }
        is_bad(parse_authorization_response(
            &[("response", "a"), ("response", "b")],
            &opts,
        ));
        let big = "x".repeat(32769);
        is_bad(parse_authorization_response(&[("response", &big)], &opts));
        let jwt_mode = AuthorizationResponseOptions::new().with_response_mode(ResponseMode::Jwt);
        assert!(parse_authorization_response(&[("response", "a.b.c")], &jwt_mode).is_ok());
        is_bad(parse_authorization_response(&[("code", "c")], &jwt_mode));
    }

    #[test]
    fn input_shapes_agree() {
        let o = AuthorizationResponseOptions::new();
        let a = p(&[("code", "c"), ("state", "s"), ("iss", ISS)]).unwrap();
        let s = parse_authorization_response_str(
            &format!("?code=c&state=s&iss={}", "https%3A%2F%2Fop.example.org"),
            &o,
        )
        .unwrap();
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        m.insert("code".into(), vec!["c".into()]);
        m.insert("state".into(), vec!["s".into()]);
        m.insert("iss".into(), vec![ISS.into()]);
        let mu = parse_authorization_response_multi(&m, &o).unwrap();
        let mut req = HttpRequestData::default();
        req.method = "GET".into();
        req.query_pairs = vec![
            ("code".into(), "c".into()),
            ("state".into(), "s".into()),
            ("iss".into(), ISS.into()),
        ];
        let rq = parse_authorization_response_request(&req, &o).unwrap();
        assert_eq!(a, s);
        assert_eq!(a, mu);
        assert_eq!(a, rq);
        // Duplicates are rejected through every shape.
        is_bad(parse_authorization_response_str("code=a&code=b", &o));
        m.insert("code".into(), vec!["c".into(), "d".into()]);
        is_bad(parse_authorization_response_multi(&m, &o));
        // Fragment prefix.
        let f = parse_authorization_response_str("#code=c", &o).unwrap();
        assert_eq!(f.response_mode(), ResponseMode::Fragment);
        assert_eq!(f.code(), Some("c"));
    }

    #[test]
    fn request_channel_rules() {
        let o = AuthorizationResponseOptions::new();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        // Protocol param in the form of a GET.
        let mut get = HttpRequestData::default();
        get.method = "GET".into();
        get.query_pairs = vec![pair("code", "c")];
        get.form_pairs = vec![pair("state", "s")];
        is_bad(parse_authorization_response_request(&get, &o));
        // Protocol param in the query of a POST.
        let mut post = HttpRequestData::default();
        post.method = "POST".into();
        post.form_pairs = vec![pair("code", "c")];
        post.query_pairs = vec![pair("state", "s")];
        is_bad(parse_authorization_response_request(&post, &o));
        // Unrelated query params on a POST are fine.
        post.query_pairs = vec![pair("tenant", "t")];
        let r = parse_authorization_response_request(&post, &o).unwrap();
        assert_eq!(r.response_mode(), ResponseMode::FormPost);
        // Empty POST form.
        post.form_pairs.clear();
        is_bad(parse_authorization_response_request(&post, &o));
        // Other methods.
        let mut put = HttpRequestData::default();
        put.method = "PUT".into();
        put.query_pairs = vec![pair("code", "c")];
        is_bad(parse_authorization_response_request(&put, &o));
        // Mode contradicting method.
        post.form_pairs = vec![pair("code", "c")];
        let q = AuthorizationResponseOptions::new().with_response_mode(ResponseMode::Query);
        assert!(matches!(
            parse_authorization_response_request(&post, &q),
            Err(Error::Config(_))
        ));
        let fp = AuthorizationResponseOptions::new().with_response_mode(ResponseMode::FormPost);
        get.form_pairs.clear();
        assert!(matches!(
            parse_authorization_response_request(&get, &fp),
            Err(Error::Config(_))
        ));
    }

    // ---- JARM ----

    fn key(kid: Option<&str>) -> SigningKey {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), kid).unwrap()
    }

    fn jarm_claims(tweak: impl FnOnce(&mut Claims)) -> Claims {
        let mut c = Claims {
            iss: Some(ISS.into()),
            aud: Some(Audience::Single(CLIENT.into())),
            exp: Some((now_secs() + 300).into()),
            ..Default::default()
        };
        c.extra.insert("code".into(), "the-code".into());
        c.extra.insert("state".into(), "st".into());
        tweak(&mut c);
        c
    }

    fn stub(token: &str) -> Result<AuthorizationResponse> {
        parse_authorization_response(
            &[("response", token)],
            &AuthorizationResponseOptions::new().accept_unverified_jarm(),
        )
    }

    fn verify(token: &str, jwks: &JwkSet, algs: &[JwsAlgorithm]) -> Result<AuthorizationResponse> {
        stub(token)?.verify_jarm(jwks, &JarmOptions::new(ISS, CLIENT, algs))
    }

    fn authn<T: std::fmt::Debug>(r: Result<T>) {
        assert!(matches!(r, Err(Error::Authn(_))), "{r:?}");
    }

    #[test]
    fn jarm_valid() {
        let k = key(Some("k1"));
        let t = jwt::sign(&k, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        let r = verify(&t, &k.to_public_jwks(), &ES).unwrap();
        assert_eq!(r.code(), Some("the-code"));
        assert_eq!(r.iss(), Some(ISS));
        assert!(r.matches_state("st", true) && r.matches_iss(ISS, true));
        assert_eq!(r.response_mode(), ResponseMode::Jwt);
        assert!(r.jarm_verified());
        // Error response inside JARM.
        let t = jwt::sign(
            &k,
            &jarm_claims(|c| {
                c.extra.remove("code");
                c.extra.insert("error".into(), "access_denied".into());
                c.extra
                    .insert("error_description".into(), "no\u{1b}".into());
            }),
            Some(TYP),
        )
        .unwrap();
        let r = verify(&t, &k.to_public_jwks(), &ES).unwrap();
        assert!(r.is_error());
        assert!(!r.error_description_safe().unwrap().contains('\u{1b}'));
        // verify on a non-JARM response is a BadRequest.
        is_bad(
            p(&[("code", "c")])
                .unwrap()
                .verify_jarm(&k.to_public_jwks(), &JarmOptions::new(ISS, CLIENT, &ES)),
        );
    }

    #[test]
    fn jarm_wrong_issuer() {
        let k = key(Some("k1"));
        let t = jwt::sign(
            &k,
            &jarm_claims(|c| c.iss = Some("https://evil".into())),
            Some(TYP),
        )
        .unwrap();
        authn(verify(&t, &k.to_public_jwks(), &ES));
    }

    #[test]
    fn jarm_wrong_audience() {
        let k = key(Some("k1"));
        let t = jwt::sign(
            &k,
            &jarm_claims(|c| c.aud = Some(Audience::Single("other".into()))),
            Some(TYP),
        )
        .unwrap();
        authn(verify(&t, &k.to_public_jwks(), &ES));
    }

    #[test]
    fn jarm_multiple_audiences_rejected() {
        let k = key(Some("k1"));
        let t = jwt::sign(
            &k,
            &jarm_claims(|c| c.aud = Some(Audience::Multiple(vec![CLIENT.into(), "other".into()]))),
            Some(TYP),
        )
        .unwrap();
        authn(verify(&t, &k.to_public_jwks(), &ES));
        let t = jwt::sign(
            &k,
            &jarm_claims(|c| c.aud = Some(Audience::Multiple(vec![CLIENT.into()]))),
            Some(TYP),
        )
        .unwrap();
        // A singleton array is the client alone, as some OPs serialise `aud`.
        assert!(verify(&t, &k.to_public_jwks(), &ES).is_ok());
        // Repeating the client, or a singleton naming someone else, is refused.
        for aud in [vec![CLIENT, CLIENT], vec!["other"], vec![]] {
            let t = jwt::sign(
                &k,
                &jarm_claims(|c| {
                    c.aud = Some(Audience::Multiple(
                        aud.iter().map(|a| a.to_string()).collect(),
                    ))
                }),
                Some(TYP),
            )
            .unwrap();
            authn(verify(&t, &k.to_public_jwks(), &ES));
        }
    }

    #[test]
    fn jarm_expired_and_missing_exp() {
        let k = key(Some("k1"));
        let t = jwt::sign(
            &k,
            &jarm_claims(|c| c.exp = Some((now_secs() - 3600).into())),
            Some(TYP),
        )
        .unwrap();
        authn(verify(&t, &k.to_public_jwks(), &ES));
        let t = jwt::sign(&k, &jarm_claims(|c| c.exp = None), Some(TYP)).unwrap();
        authn(verify(&t, &k.to_public_jwks(), &ES));
    }

    #[test]
    fn jarm_leeway_bounded() {
        let k = key(Some("k1"));
        let t = jwt::sign(&k, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        let j = k.to_public_jwks();
        let s = stub(&t).unwrap();
        is_bad(s.verify_jarm(
            &j,
            &JarmOptions::new(ISS, CLIENT, &ES).with_leeway(MAX_ID_TOKEN_LEEWAY + 1),
        ));
        assert!(s
            .verify_jarm(
                &j,
                &JarmOptions::new(ISS, CLIENT, &ES).with_leeway(MAX_ID_TOKEN_LEEWAY)
            )
            .is_ok());
    }

    #[test]
    fn jarm_algorithm_rules() {
        let k = key(Some("k1"));
        let t = jwt::sign(&k, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        authn(verify(&t, &k.to_public_jwks(), &[JwsAlgorithm::RS256]));
        is_bad(verify(&t, &k.to_public_jwks(), &[]));
    }

    #[test]
    fn jarm_empty_issuer_or_client_rejected() {
        let k = key(Some("k1"));
        let t = jwt::sign(&k, &jarm_claims(|c| c.iss = Some(String::new())), Some(TYP)).unwrap();
        let j = k.to_public_jwks();
        let s = stub(&t).unwrap();
        is_bad(s.verify_jarm(&j, &JarmOptions::new("", CLIENT, &ES)));
        is_bad(s.verify_jarm(&j, &JarmOptions::new(ISS, "", &ES)));
    }

    #[test]
    fn jarm_kid_rule() {
        let k1 = key(None);
        let k2 = key(Some("k2"));
        let mut both = k1.to_public_jwks();
        both.keys.extend(k2.to_public_jwks().keys);
        // No kid, two keys.
        let t = jwt::sign(&k1, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        authn(verify(&t, &both, &ES));
        // kid that names no key.
        let ghost = key(Some("ghost"));
        let t = jwt::sign(&ghost, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        authn(verify(&t, &both, &ES));
        // Single unlabelled key, no kid: fine.
        let t = jwt::sign(&k1, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        assert!(verify(&t, &k1.to_public_jwks(), &ES).is_ok());
        // Correct kid among two keys: fine.
        let t = jwt::sign(&k2, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        assert!(verify(&t, &both, &ES).is_ok());
    }

    #[test]
    fn jarm_wrong_key() {
        let k = key(Some("k1"));
        let other = key(Some("k1"));
        let t = jwt::sign(&k, &jarm_claims(|_| {}), Some(TYP)).unwrap();
        authn(verify(&t, &other.to_public_jwks(), &ES));
    }

    #[test]
    fn jarm_inner_claims_must_be_strings_and_valid() {
        let k = key(Some("k1"));
        let j = k.to_public_jwks();
        let sign = |tweak: Box<dyn FnOnce(&mut Claims)>| {
            jwt::sign(&k, &jarm_claims(tweak), Some(TYP)).unwrap()
        };
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.insert("code".into(), 123.into());
            })),
            &j,
            &ES,
        ));
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.insert("state".into(), serde_json::json!(["a"]));
            })),
            &j,
            &ES,
        ));
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.insert("error_uri".into(), serde_json::json!({}));
            })),
            &j,
            &ES,
        ));
        // Same shared rules.
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.insert("code".into(), "a\nb".into());
            })),
            &j,
            &ES,
        ));
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.insert("state".into(), "".into());
            })),
            &j,
            &ES,
        ));
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.insert("error".into(), "access_denied".into());
            })),
            &j,
            &ES,
        ));
        is_bad(verify(
            &sign(Box::new(|c| {
                c.extra.remove("code");
            })),
            &j,
            &ES,
        ));
    }

    #[test]
    fn jarm_jwe_rejected() {
        let k = key(Some("k1"));
        let err = verify("a.b.c.d.e", &k.to_public_jwks(), &ES).unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
        assert!(err.to_string().contains("encrypted JARM not supported"));
        is_bad(verify("a.b", &k.to_public_jwks(), &ES));
    }

    #[test]
    fn jarm_oversized_rejected() {
        let big = format!("{}.b.c", "x".repeat(RESPONSE_JARM_MAX));
        is_bad(stub(&big));
    }

    #[test]
    fn id_token_is_not_jarm() {
        let k = key(Some("k1"));
        let mut c = jarm_claims(|c| {
            c.extra.clear();
        });
        c.sub = Some("subject".into());
        c.iat = Some(now_secs().into());
        let t = jwt::sign(&k, &c, Some(TYP)).unwrap();
        is_bad(verify(&t, &k.to_public_jwks(), &ES));
    }

    /// Verify with the given option tweak.
    fn verify_with(
        token: &str,
        k: &SigningKey,
        f: impl FnOnce(JarmOptions<'static>) -> JarmOptions<'static>,
    ) -> Result<AuthorizationResponse> {
        stub(token)?.verify_jarm(&k.to_public_jwks(), &f(JarmOptions::new(ISS, CLIENT, &ES)))
    }

    fn error_claims() -> Claims {
        jarm_claims(|c| {
            c.extra.remove("code");
            c.extra.insert("error".into(), "access_denied".into());
        })
    }

    /// Tokens whose shape is a valid callback but whose purpose may differ.
    fn both_shapes() -> [Claims; 2] {
        [jarm_claims(|_| {}), error_claims()]
    }

    #[test]
    fn jarm_id_token_shaped_substitution_rejected_by_default() {
        let k = key(Some("k1"));
        for mut c in both_shapes() {
            c.sub = Some("subject".into());
            c.iat = Some(now_secs().into());
            for typ in [None, Some("JWT"), Some("at+jwt"), Some("id_token+jwt")] {
                let t = jwt::sign(&k, &c, typ).unwrap();
                authn(verify_with(&t, &k, |o| o));
            }
        }
    }

    #[test]
    fn jarm_incompatible_typ_rejected_even_with_opt_in() {
        let k = key(Some("k1"));
        for c in both_shapes() {
            for typ in [
                "at+jwt",
                "id_token+jwt",
                "application/at+jwt",
                "dpop+jwt",
                "",
            ] {
                let t = jwt::sign(&k, &c, Some(typ)).unwrap();
                authn(verify_with(&t, &k, |o| o.with_dedicated_keys()));
                authn(verify_with(&t, &k, |o| o.allow_untyped_shared_keys()));
                authn(verify_with(&t, &k, |o| o));
            }
        }
    }

    #[test]
    fn jarm_correct_typ_accepted() {
        let k = key(Some("k1"));
        for c in both_shapes() {
            for typ in [
                "oauth-authz-resp+jwt",
                "OAuth-Authz-Resp+JWT",
                "application/oauth-authz-resp+jwt",
            ] {
                let t = jwt::sign(&k, &c, Some(typ)).unwrap();
                verify_with(&t, &k, |o| o).unwrap();
                verify_with(&t, &k, |o| o.with_dedicated_keys()).unwrap();
                verify_with(&t, &k, |o| o.allow_untyped_shared_keys()).unwrap();
            }
        }
    }

    #[test]
    fn jarm_bare_oauth_authz_resp_is_not_the_jarm_typ() {
        let k = key(Some("k1"));
        for c in both_shapes() {
            for typ in ["oauth-authz-resp", "application/oauth-authz-resp"] {
                let t = jwt::sign(&k, &c, Some(typ)).unwrap();
                assert!(matches!(
                    verify_with(&t, &k, |o| o.with_dedicated_keys()),
                    Err(Error::Authn(_))
                ));
            }
        }
    }

    #[test]
    fn jarm_custom_expected_typ() {
        let k = key(Some("k1"));
        let c = jarm_claims(|_| {});
        let t = jwt::sign(&k, &c, Some("my-jarm")).unwrap();
        verify_with(&t, &k, |o| o.with_expected_typ("My-JARM")).unwrap();
        authn(verify_with(&t, &k, |o| o));
        let t = jwt::sign(&k, &c, Some(TYP)).unwrap();
        authn(verify_with(&t, &k, |o| o.with_expected_typ("my-jarm")));
    }

    #[test]
    fn jarm_missing_typ_only_with_opt_in() {
        let k = key(Some("k1"));
        for c in both_shapes() {
            let t = jwt::sign(&k, &c, None).unwrap();
            authn(verify_with(&t, &k, |o| o));
            verify_with(&t, &k, |o| o.with_dedicated_keys()).unwrap();
            verify_with(&t, &k, |o| o.allow_untyped_shared_keys()).unwrap();
        }
    }

    #[test]
    fn jarm_typ_jwt_only_with_opt_in() {
        let k = key(Some("k1"));
        for c in both_shapes() {
            for typ in ["JWT", "jwt", "application/jwt"] {
                let t = jwt::sign(&k, &c, Some(typ)).unwrap();
                authn(verify_with(&t, &k, |o| o));
                verify_with(&t, &k, |o| o.with_dedicated_keys()).unwrap();
                verify_with(&t, &k, |o| o.allow_untyped_shared_keys()).unwrap();
            }
        }
    }
}
