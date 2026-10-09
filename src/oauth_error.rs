//! OAuth 2.0 / OIDC standard error responses (RFC 6749 §5.2, §4.1.2.1).

use crate::http::Response;
use serde::Serialize;

/// A standard OAuth2 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    AccessDenied,
    LoginRequired,
    ServerError,
    TemporarilyUnavailable,
    /// RFC 9449 §5.2 / §7.1 — a presented DPoP proof was malformed or invalid.
    InvalidDpopProof,
}

impl OAuthErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidDpopProof => "invalid_dpop_proof",
        }
    }

    /// HTTP status code conventionally returned with this error at the token
    /// endpoint.
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidClient => 401,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

/// Longest `error_description` put on the wire, in characters.
const MAX_WIRE_DESCRIPTION_CHARS: usize = 256;

/// Normalize a description to the `error_description` character set of RFC
/// 6749 §§4.1.2.1 and 5.2 (`%x20-21 / %x23-5B / %x5D-7E`: printable ASCII
/// without `"` and `\`). Every other character becomes `?` and the result is
/// capped, with no truncation marker, so the decoded wire value stays inside
/// that set. This is deliberately separate from log escaping
/// ([`crate::error::display_safe`]), which introduces backslashes.
pub(crate) fn wire_description(description: &str) -> String {
    description
        .chars()
        .take(MAX_WIRE_DESCRIPTION_CHARS)
        .map(|c| {
            if matches!(c, '\u{20}' | '\u{21}' | '\u{23}'..='\u{5B}' | '\u{5D}'..='\u{7E}') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Longest `state` value accepted or echoed, in characters. RFC 6749 sets no
/// limit; this bounds the `Location` header and JSON body an unauthenticated
/// request can make the OP produce.
pub(crate) const MAX_STATE_CHARS: usize = 1024;

/// Whether `state` can be accepted and echoed: at most [`MAX_STATE_CHARS`]
/// characters, all from the RFC 6749 §A.5 `VSCHAR` set (`%x20-7E`). This
/// excludes controls, bidi and line-separator characters, and non-ASCII text.
pub(crate) fn is_valid_state(state: &str) -> bool {
    state.chars().count() <= MAX_STATE_CHARS
        && state.chars().all(|c| matches!(c, '\u{20}'..='\u{7E}'))
}

/// An OAuth2 error with an optional human-readable description.
///
/// `description` holds the raw text. It is normalized to the RFC 6749
/// character set when serialized by [`OAuthError::to_response`] and
/// [`OAuthError::to_redirect`], and escaped for logs by `Display`.
#[derive(Debug, Clone)]
pub struct OAuthError {
    pub code: OAuthErrorCode,
    pub description: Option<String>,
    pub state: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
}

impl OAuthError {
    pub fn new(code: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
            state: None,
        }
    }

    pub fn bare(code: OAuthErrorCode) -> Self {
        Self {
            code,
            description: None,
            state: None,
        }
    }

    pub fn with_state(mut self, state: Option<String>) -> Self {
        self.state = state;
        self
    }

    /// The `state` to echo: omitted when it could not have been accepted
    /// ([`is_valid_state`]), so a hostile value never reaches the wire.
    fn wire_state(&self) -> Option<&str> {
        self.state.as_deref().filter(|s| is_valid_state(s))
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidRequest, msg)
    }
    pub fn invalid_client(msg: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidClient, msg)
    }
    pub fn invalid_grant(msg: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidGrant, msg)
    }
    pub fn invalid_dpop_proof(msg: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidDpopProof, msg)
    }

    /// Render a direct JSON error response (token/userinfo endpoints).
    pub fn to_response(&self) -> Response {
        let body = ErrorBody {
            error: self.code.as_str(),
            error_description: self.description.as_deref().map(wire_description),
            state: self.wire_state(),
        };
        let json = serde_json::to_vec(&body).unwrap_or_default();
        let mut r = Response::new(self.code.http_status())
            .with_header("content-type", "application/json")
            .with_header("cache-control", "no-store")
            .with_body(json);
        if self.code == OAuthErrorCode::InvalidClient {
            r = r.with_header("www-authenticate", "Basic");
        }
        r
    }

    /// Render an authorization error using an explicitly selected, validated
    /// response mode. `fragment` must come from the validated authorization
    /// request and must match the corresponding successful response mode.
    pub fn to_redirect(&self, redirect_uri: &str, fragment: bool) -> Response {
        let description = self.description.as_deref().map(wire_description);
        let mut params = vec![("error", self.code.as_str())];
        if let Some(desc) = description.as_deref() {
            params.push(("error_description", desc));
        }
        if let Some(state) = self.wire_state() {
            params.push(("state", state));
        }
        let encoded = params
            .iter()
            .map(|(name, value)| format!("{}={}", urlencode(name), urlencode(value)))
            .collect::<Vec<_>>()
            .join("&");

        if fragment {
            let separator = if redirect_uri.contains('#') { '&' } else { '#' };
            return Response::redirect(format!("{redirect_uri}{separator}{encoded}"));
        }

        // Insert the query before an existing fragment rather than appending
        // protocol parameters after it.
        let (base, fragment_suffix) = redirect_uri
            .split_once('#')
            .map_or((redirect_uri, String::new()), |(base, value)| {
                (base, format!("#{value}"))
            });
        let separator = if base.contains('?') { '&' } else { '?' };
        Response::redirect(format!("{base}{separator}{encoded}{fragment_suffix}"))
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(d) = &self.description {
            write!(f, ": {}", crate::error::display_safe(d))?;
        }
        Ok(())
    }
}

impl std::error::Error for OAuthError {}

pub(crate) fn urlencode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    fn rfc6749_ok(s: &str) -> bool {
        s.chars()
            .all(|c| matches!(c, '\u{20}' | '\u{21}' | '\u{23}'..='\u{5B}' | '\u{5D}'..='\u{7E}'))
    }

    #[test]
    fn wire_description_stays_in_rfc6749_character_set() {
        // Long ASCII input is capped without a truncation marker.
        let long = wire_description(&"a".repeat(1000));
        assert_eq!(long.chars().count(), MAX_WIRE_DESCRIPTION_CHARS);
        assert!(rfc6749_ok(&long) && !long.contains('\u{2026}'));
        // Quote, backslash, controls, bidi and non-ASCII are all replaced.
        let dirty = wire_description("a\"b\\c\n\u{1b}d\u{202E}e\u{e5}f");
        assert!(rfc6749_ok(&dirty), "{dirty:?}");
        assert!(!dirty.contains('\\') && !dirty.contains('"'));
        assert_eq!(dirty, "a?b?c??d?e?f");
        // Clean text is unchanged.
        assert_eq!(wire_description("bad request: x=1"), "bad request: x=1");
    }

    #[test]
    fn wire_responses_omit_states_that_could_not_have_been_accepted() {
        let hostile = [
            format!("st\u{202E}ate{}", "x".repeat(4000)),
            "a\u{2028}b\u{2029}c".to_string(),
            "s".repeat(MAX_STATE_CHARS + 1),
            "a\nb".to_string(),
        ];
        for state in hostile {
            let err = OAuthError::invalid_request("d").with_state(Some(state.clone()));
            let body = err.to_response().body;
            let text = String::from_utf8(body.clone()).unwrap();
            assert!(!text.contains("state"), "{text}");
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(json.get("state").is_none());
            for fragment in [false, true] {
                let resp = err.to_redirect("https://rp.example/cb", fragment);
                let loc = resp
                    .headers
                    .iter()
                    .find(|(n, _)| n == "location")
                    .map(|(_, v)| v.as_str())
                    .unwrap();
                assert!(!loc.contains("state="), "{loc}");
                assert!(loc.len() < 512, "{}", loc.len());
            }
        }
        // A valid state is echoed unchanged.
        let ok = OAuthError::invalid_request("d").with_state(Some("a b~!".into()));
        let json: serde_json::Value = serde_json::from_slice(&ok.to_response().body).unwrap();
        assert_eq!(json["state"], "a b~!");
        let max = "s".repeat(MAX_STATE_CHARS);
        let ok = OAuthError::invalid_request("d").with_state(Some(max.clone()));
        let json: serde_json::Value = serde_json::from_slice(&ok.to_response().body).unwrap();
        assert_eq!(json["state"], max.as_str());
    }

    #[test]
    fn wire_responses_normalize_descriptions_but_display_escapes() {
        let raw = format!("unsupported grant_type: {}\u{202E}\\\n\"", "g".repeat(400));
        let err = OAuthError::invalid_request(raw.clone());
        // JSON body: decoded error_description is inside the RFC 6749 set.
        let body: serde_json::Value = serde_json::from_slice(&err.to_response().body).unwrap();
        let desc = body["error_description"].as_str().unwrap();
        assert!(rfc6749_ok(desc), "{desc:?}");
        assert!(desc.chars().count() <= MAX_WIRE_DESCRIPTION_CHARS);
        // Redirect (query and fragment): decode the parameter and check it.
        for fragment in [false, true] {
            let resp = err.to_redirect("https://rp.example/cb", fragment);
            let location = resp
                .headers
                .iter()
                .find(|(n, _)| n == "location")
                .map(|(_, v)| v.clone())
                .unwrap();
            let encoded = location.split(['?', '#']).nth(1).unwrap();
            let decoded = form_urlencoded::parse(encoded.as_bytes())
                .find(|(k, _)| k == "error_description")
                .map(|(_, v)| v.into_owned())
                .unwrap();
            assert!(rfc6749_ok(&decoded), "{decoded:?}");
            assert!(decoded.chars().count() <= MAX_WIRE_DESCRIPTION_CHARS);
        }
        // The field keeps the raw text; Display escapes it for logs.
        assert_eq!(err.description.as_deref(), Some(raw.as_str()));
        let shown = err.to_string();
        assert!(!shown.contains('\u{202E}') && !shown.contains('\n'));
    }

    use super::*;

    fn location(response: &Response) -> &str {
        response
            .headers
            .iter()
            .find(|(name, _)| name == "location")
            .map(|(_, value)| value.as_str())
            .unwrap()
    }

    #[test]
    fn authorization_errors_preserve_validated_response_mode() {
        let error = OAuthError::invalid_request("bad request").with_state(Some("s".into()));
        let query = error.to_redirect("https://rp.example/cb#existing", false);
        assert_eq!(
            location(&query),
            "https://rp.example/cb?error=invalid_request&error_description=bad+request&state=s#existing"
        );

        let fragment = error.to_redirect("https://rp.example/cb", true);
        assert_eq!(
            location(&fragment),
            "https://rp.example/cb#error=invalid_request&error_description=bad+request&state=s"
        );
    }
}
