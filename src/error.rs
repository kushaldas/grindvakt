//! Error types for the tunnelbana core framework.

use thiserror::Error;

/// The result type used throughout the proxy.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type. Carries enough structure to be mapped onto an HTTP
/// response by the binary layer (see [`Error::status_hint`]).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// No registered endpoint matched the request path.
    #[error("no endpoint bound to path: {0}")]
    NoBoundEndpoint(String),

    /// A referenced frontend/backend/microservice name does not exist.
    #[error("unknown module: {0}")]
    UnknownModule(String),

    /// The request was malformed (missing params, bad encoding, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Authentication failed somewhere in the flow.
    #[error("authentication error: {0}")]
    Authn(String),

    /// State cookie could not be sealed/unsealed.
    #[error("state error: {0}")]
    State(String),

    /// Configuration is invalid or could not be loaded.
    #[error("configuration error: {0}")]
    Config(String),

    /// Cryptographic / key-material failure.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Attribute mapping failure.
    #[error("attribute mapping error: {0}")]
    Attribute(String),

    /// Wrapper around the JOSE library errors.
    #[error("jose error: {0}")]
    Jose(#[from] jose_rs::JoseError),

    /// JSON (de)serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Any other internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// An upstream HTTP exchange (token, UserInfo, JWKS, discovery, federation
    /// fetch) failed.
    ///
    /// **Migration from 0.8:** these failures used to be [`Error::Authn`]
    /// (token and UserInfo) or [`Error::Internal`] (the rest). `Authn` still
    /// exists, so code such as `matches!(e, Error::Authn(_))` compiles but no
    /// longer fires for them. Use [`Error::is_auth_failure`] where `Authn`
    /// meant "authentication failed", and [`Error::upstream_http`] for the
    /// status and OAuth error. [`Error::status_hint`] keeps 401 for token and
    /// UserInfo failures.
    #[error("{0}")]
    UpstreamHttp(Box<UpstreamHttpError>),
}

/// Details of a failed upstream HTTP exchange.
///
/// All text fields are sanitized: control and bidirectional-format characters
/// are escaped (for example `\u{1b}`) and lengths are capped, so the values
/// cannot inject terminal or log escapes.
///
/// Sanitizing does not make [`UpstreamHttpError::body`] or
/// [`UpstreamHttpError::error_description`] safe to log verbatim: upstream
/// errors can echo submitted values (codes, `state`, PKCE verifiers) or carry
/// personal data. The `Debug` implementation therefore redacts both and prints
/// only their length; the fields stay readable. Do not copy them into logs or
/// into any HTTP, JSON or other serialized error surface. `error` (the OAuth
/// error code, capped at 64 characters) is not redacted.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpstreamHttpError {
    /// HTTP status code of the upstream response.
    pub status: Option<u16>,
    /// OAuth `error` code, from the JSON body or `WWW-Authenticate` header.
    pub error: Option<String>,
    /// OAuth `error_description`, from the JSON body or `WWW-Authenticate`.
    /// Free text from the upstream that may echo secrets: never log it
    /// verbatim or return it to end users.
    pub error_description: Option<String>,
    /// Response body, escaped and length capped. May contain echoed secrets or
    /// personal data: never log it verbatim or return it to end users.
    pub body: Option<String>,
    message: String,
    auth_failure: bool,
}

impl UpstreamHttpError {
    pub(crate) fn new(
        status: Option<u16>,
        error: Option<String>,
        error_description: Option<String>,
        body: Option<String>,
        message: String,
        auth_failure: bool,
    ) -> Self {
        Self {
            status,
            error,
            error_description,
            body,
            message,
            auth_failure,
        }
    }

    /// Whether the failed exchange was an authentication step (token or
    /// UserInfo request) as opposed to metadata retrieval (discovery, JWKS).
    /// Before 0.9 such failures were reported as [`Error::Authn`].
    pub fn is_auth_failure(&self) -> bool {
        self.auth_failure
    }

    /// The human-readable message (also the `Display` text).
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Debug for UpstreamHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let body = self
            .body
            .as_ref()
            .map(|b| format!("<redacted, {} chars>", b.chars().count()));
        let description = self
            .error_description
            .as_ref()
            .map(|d| format!("<redacted, {} chars>", d.chars().count()));
        f.debug_struct("UpstreamHttpError")
            .field("status", &self.status)
            .field("error", &self.error)
            .field("error_description", &description)
            .field("body", &body)
            .field("message", &self.message)
            .field("auth_failure", &self.auth_failure)
            .finish()
    }
}

impl std::fmt::Display for UpstreamHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Whether `c` is a bidirectional control, line/paragraph separator or other
/// invisible formatting character: one that renders as nothing, or reorders
/// or splits surrounding text, so it can make a URL or log line look like
/// something it is not. `char::is_control` does not cover these (they are
/// category Cf, not Cc). Hand-maintained from Unicode general category Cf and
/// Default_Ignorable_Code_Point, without pulling in a Unicode crate.
pub(crate) fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        // Bidirectional controls and Unicode line/paragraph separators.
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{2028}' | '\u{2029}'
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            // Zero-width and other invisible format characters (general
            // category Cf and Default_Ignorable_Code_Point): soft hyphen,
            // number-sign prefixes, Mongolian vowel separator, zero-width
            // space/joiners, word joiner and invisible operators, deprecated
            // formatting, BOM, interlinear annotation, and similar.
            | '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}'
            | '\u{2065}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF0}'..='\u{FFFB}'
            | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
            // Invisible fillers and variation selectors.
            | '\u{034F}' | '\u{115F}'..='\u{1160}' | '\u{17B4}'..='\u{17B5}'
            | '\u{3164}' | '\u{FFA0}' | '\u{FE00}'..='\u{FE0F}'
            // Tag characters (invisible, able to carry hidden data), the
            // variation selectors supplement and the unassigned
            // default-ignorable code points around them.
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Make an attacker-controlled value safe to interpolate into an error
/// message: escapes control and bidi formatting characters and caps length.
pub(crate) fn display_safe(s: &str) -> String {
    escape_upstream_text(s, 256)
}

/// Escape control and bidi/format characters in untrusted upstream text and
/// cap the output at `max_chars` characters (appending `…` when truncated).
pub(crate) fn escape_upstream_text(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    for c in s.chars() {
        let piece: String = if c.is_control() || is_invisible_format(c) {
            c.escape_unicode().to_string()
        } else {
            c.to_string()
        };
        let n = piece.chars().count();
        if count + n > max_chars {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
        count += n;
    }
    out
}

/// Split `value` at commas that are outside quoted strings, honouring
/// backslash escapes inside quotes (RFC 9110 §5.6.4), so quoted text cannot
/// introduce list elements.
pub(crate) fn split_unquoted_commas(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut in_quotes, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == ',' && !in_quotes {
            out.push(&value[start..i]);
            start = i + 1;
        }
    }
    out.push(&value[start..]);
    out
}

/// Whether every quoted string in `value` is closed, scanning exactly as
/// [`split_unquoted_commas`] does (backslash escapes inside quotes). An
/// unterminated quote makes everything after it a single opaque element, so a
/// caller that makes a security decision on list elements must treat the value
/// as unusable.
pub(crate) fn quotes_balanced(value: &str) -> bool {
    let (mut in_quotes, mut escaped) = (false, false);
    for c in value.chars() {
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        }
    }
    !in_quotes
}

/// One `name=value` auth-param (RFC 9110 §11.2). `None` if malformed, for
/// example an unterminated or trailing-garbage quoted string.
fn parse_auth_param(item: &str) -> Option<(String, String)> {
    let item = item.trim();
    let name_end = item.find(|c: char| c == '=' || c.is_ascii_whitespace())?;
    let name = &item[..name_end];
    let rest = item[name_end..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    if name.is_empty() {
        return None;
    }
    let value = if let Some(quoted) = rest.strip_prefix('"') {
        let mut val = String::new();
        let mut chars = quoted.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' => val.push(chars.next()?),
                '"' => {
                    closed = true;
                    break;
                }
                _ => val.push(c),
            }
        }
        if !closed || !chars.as_str().trim().is_empty() {
            return None;
        }
        val
    } else {
        let token = rest.split_ascii_whitespace().next()?;
        token.to_string()
    };
    Some((name.to_string(), value))
}

/// Parse `error` and `error_description` out of a `WWW-Authenticate` header
/// value (a comma-separated list of challenges, RFC 9110 §11.6.1) by selecting
/// the first well-formed `Bearer` or `DPoP` challenge that carries them, so
/// other challenges (`Basic realm="x", Bearer error="invalid_token"`) in either
/// order do not hide the OAuth error. Lenient; `None` when no such challenge
/// exists or the Bearer/DPoP challenge is malformed.
pub(crate) fn parse_www_authenticate_bearer(
    value: &str,
) -> Option<(Option<String>, Option<String>)> {
    struct Challenge {
        scheme: String,
        params: Vec<(String, String)>,
        malformed: bool,
    }
    let mut challenges: Vec<Challenge> = Vec::new();
    for item in split_unquoted_commas(value) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let first_end = item
            .find(|c: char| c == '=' || c.is_ascii_whitespace())
            .unwrap_or(item.len());
        let after_first = item[first_end..].trim_start();
        if after_first.starts_with('=') {
            // `name=value`: a further parameter of the current challenge.
            if let Some(current) = challenges.last_mut() {
                match parse_auth_param(item) {
                    Some(param) => current.params.push(param),
                    None => current.malformed = true,
                }
            }
        } else {
            // `scheme` or `scheme param`: a new challenge.
            let mut challenge = Challenge {
                scheme: item[..first_end].to_string(),
                params: Vec::new(),
                malformed: false,
            };
            if after_first.contains('=') {
                match parse_auth_param(after_first) {
                    Some(param) => challenge.params.push(param),
                    None => challenge.malformed = true,
                }
            }
            challenges.push(challenge);
        }
    }
    for challenge in challenges {
        if challenge.malformed
            || !(challenge.scheme.eq_ignore_ascii_case("bearer")
                || challenge.scheme.eq_ignore_ascii_case("dpop"))
        {
            continue;
        }
        let find = |key: &str| {
            challenge
                .params
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.clone())
        };
        let (error, description) = (find("error"), find("error_description"));
        if error.is_some() || description.is_some() {
            return Some((error, description));
        }
    }
    None
}

impl Error {
    /// The structured upstream HTTP failure details, if this is one.
    pub fn upstream_http(&self) -> Option<&UpstreamHttpError> {
        match self {
            Error::UpstreamHttp(e) => Some(e),
            _ => None,
        }
    }

    /// Whether this error is an authentication failure: [`Error::Authn`], or an
    /// [`Error::UpstreamHttp`] from a token or UserInfo request (which 0.8
    /// reported as `Authn`). Prefer this to matching variant identity at
    /// re-authentication, session-teardown and alerting decision points.
    pub fn is_auth_failure(&self) -> bool {
        match self {
            Error::Authn(_) => true,
            Error::UpstreamHttp(e) => e.is_auth_failure(),
            _ => false,
        }
    }

    /// Suggested HTTP status code for surfacing this error to a client.
    pub fn status_hint(&self) -> u16 {
        match self {
            // Token and UserInfo failures keep the 401 they had as `Authn`, so
            // re-login logic keyed on it still fires; metadata fetches (discovery,
            // JWKS, federation) are an upstream fault: 502, a 5xx like the 500
            // they had as `Internal`.
            Error::UpstreamHttp(e) if e.is_auth_failure() => 401,
            Error::UpstreamHttp(_) => 502,
            Error::NoBoundEndpoint(_) => 404,
            Error::BadRequest(_) => 400,
            Error::UnknownModule(_) => 404,
            Error::Authn(_) => 401,
            Error::Config(_) | Error::Crypto(_) | Error::State(_) => 500,
            _ => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn upstream_http_error_debug_redacts_body() {
        let e = super::UpstreamHttpError::new(
            Some(400),
            Some("invalid_grant".into()),
            Some("rejected code SECRET-DESC".into()),
            Some("code=SECRET-CODE verifier=SECRET".into()),
            "authentication error: token endpoint returned 400".into(),
            true,
        );
        let dbg = format!(
            "{e:?} {:?}",
            super::Error::UpstreamHttp(Box::new(e.clone()))
        );
        assert!(!dbg.contains("SECRET"), "{dbg}");
        assert!(dbg.contains("redacted"), "{dbg}");
        assert!(dbg.contains("invalid_grant"));
        // The body stays available to callers that ask for it.
        assert!(e.body.as_deref().unwrap().contains("SECRET-CODE"));
        assert_eq!(
            e.error_description.as_deref(),
            Some("rejected code SECRET-DESC")
        );
    }

    use super::*;

    #[test]
    fn escape_controls_and_bidi() {
        assert_eq!(escape_upstream_text("a\x1bb", 64), "a\\u{1b}b");
        assert_eq!(escape_upstream_text("x\u{202E}y", 64), "x\\u{202e}y");
        assert_eq!(escape_upstream_text("åäö", 64), "åäö");
        assert_eq!(escape_upstream_text("a\u{61c}b", 64), "a\\u{61c}b");
        assert_eq!(escape_upstream_text("a\u{2028}b", 64), "a\\u{2028}b");
        assert_eq!(escape_upstream_text("a\u{2029}b", 64), "a\\u{2029}b");
    }

    #[test]
    fn invisible_format_characters_are_escaped_and_ordinary_text_is_not() {
        for c in [
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{2060}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{034F}',
            '\u{180B}',
            '\u{180C}',
            '\u{180D}',
            '\u{180E}',
            '\u{180F}',
            '\u{2065}',
            '\u{FFF0}',
            '\u{FE0F}',
            '\u{E0001}',
            '\u{E0041}',
            '\u{E007F}',
            '\u{E0100}',
            '\u{E0FFF}',
            '\u{206A}',
        ] {
            let escaped = escape_upstream_text(&format!("a{c}b"), 64);
            assert!(!escaped.contains(c), "{c:?} not escaped: {escaped}");
            assert!(escaped.contains("\\u{"), "{c:?}: {escaped}");
        }
        // Ordinary text, including non-ASCII letters, digits and an emoji, is kept.
        assert_eq!(
            escape_upstream_text("åäö ü 日本語 ✓ 😀", 64),
            "åäö ü 日本語 ✓ 😀"
        );
    }

    #[test]
    fn escape_truncates_without_splitting_escape() {
        // "\u{1b}" is 6 chars; with a cap of 5 after "ab" it must not split.
        let out = escape_upstream_text("ab\x1bcd", 5);
        assert_eq!(out, "ab…");
        assert_eq!(escape_upstream_text("abcdef", 3), "abc…");
        assert_eq!(escape_upstream_text("abc", 3), "abc");
    }

    #[test]
    fn parse_bearer_basic_and_escapes() {
        let p = parse_www_authenticate_bearer(
            r#"Bearer realm="x", error="invalid_token", error_description="say \"hi\" \\ ok""#,
        )
        .unwrap();
        assert_eq!(p.0.as_deref(), Some("invalid_token"));
        assert_eq!(p.1.as_deref(), Some(r#"say "hi" \ ok"#));
        let p = parse_www_authenticate_bearer(r#"DPoP error="use_dpop_nonce""#).unwrap();
        assert_eq!(p.0.as_deref(), Some("use_dpop_nonce"));
        assert_eq!(p.1, None);
        let p = parse_www_authenticate_bearer("Bearer error=invalid_request").unwrap();
        assert_eq!(p.0.as_deref(), Some("invalid_request"));
    }

    #[test]
    fn parse_bearer_malformed_is_none() {
        assert!(parse_www_authenticate_bearer("").is_none());
        assert!(parse_www_authenticate_bearer("Basic realm=\"x\"").is_none());
        assert!(parse_www_authenticate_bearer("Bearer").is_none());
        assert!(parse_www_authenticate_bearer("Bearer error=\"unterminated").is_none());
        assert!(parse_www_authenticate_bearer("Bearer garbage").is_none());
        assert!(parse_www_authenticate_bearer("Bearer error=\"a\\").is_none());
    }

    #[test]
    fn quotes_balanced_detects_unterminated_quotes() {
        assert!(quotes_balanced(""));
        assert!(quotes_balanced(r#"a="x, y", b=2"#));
        assert!(quotes_balanced(r#"a="x\"y""#));
        assert!(!quotes_balanced(r#"a="x"#));
        assert!(!quotes_balanced(r#"a="x\""#));
        assert!(!quotes_balanced(r#"a="x", b=""#));
    }

    #[test]
    fn parse_bearer_among_multiple_challenges() {
        let want = |p: Option<(Option<String>, Option<String>)>| {
            let p = p.expect("bearer challenge found");
            assert_eq!(p.0.as_deref(), Some("invalid_token"));
            assert_eq!(p.1.as_deref(), Some("expired, really"));
        };
        // Bearer after another challenge, and before it.
        want(parse_www_authenticate_bearer(
            r#"Basic realm="x", Bearer error="invalid_token", error_description="expired, really""#,
        ));
        want(parse_www_authenticate_bearer(
            r#"Bearer error="invalid_token", error_description="expired, really", Basic realm="x""#,
        ));
        // Quoted commas and a quoted "Bearer ..." inside another challenge's value.
        want(parse_www_authenticate_bearer(
            r#"Basic realm="a, Bearer error=nope", Bearer error=invalid_token, error_description="expired, really""#,
        ));
        // DPoP among others, scheme case-insensitive, extra whitespace.
        let p = parse_www_authenticate_bearer(
            r#"Basic realm="x" ,  dpop algs="ES256", error="use_dpop_nonce""#,
        )
        .unwrap();
        assert_eq!(p.0.as_deref(), Some("use_dpop_nonce"));
        // Parameters of a non-Bearer challenge are never attributed to Bearer.
        assert!(
            parse_www_authenticate_bearer(r#"Basic error="not-oauth", Bearer realm="x""#).is_none()
        );
        // A malformed Bearer challenge yields nothing.
        assert!(
            parse_www_authenticate_bearer(r#"Basic realm="x", Bearer error="unterminated"#)
                .is_none()
        );
        // No Bearer/DPoP challenge at all.
        assert!(parse_www_authenticate_bearer(r#"Basic realm="x", Negotiate abc=="#).is_none());
    }
}
