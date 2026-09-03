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

/// An OAuth2 error with an optional human-readable description.
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
    error_description: Option<&'a str>,
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
            error_description: self.description.as_deref(),
            state: self.state.as_deref(),
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

    /// Render an error as a redirect back to the client (authorization endpoint).
    pub fn to_redirect(&self, redirect_uri: &str) -> Response {
        self.to_redirect_with_fragment(redirect_uri, false)
    }

    /// Render an authorization error using the validated response mode.
    /// Fragment mode is required whenever the corresponding successful
    /// response would have used the fragment.
    pub fn to_redirect_with_fragment(&self, redirect_uri: &str, fragment: bool) -> Response {
        let mut params = vec![("error", self.code.as_str())];
        if let Some(desc) = self.description.as_deref() {
            params.push(("error_description", desc));
        }
        if let Some(state) = self.state.as_deref() {
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
            write!(f, ": {d}")?;
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
        let query = error.to_redirect_with_fragment("https://rp.example/cb#existing", false);
        assert_eq!(
            location(&query),
            "https://rp.example/cb?error=invalid_request&error_description=bad+request&state=s#existing"
        );

        let fragment = error.to_redirect_with_fragment("https://rp.example/cb", true);
        assert_eq!(
            location(&fragment),
            "https://rp.example/cb#error=invalid_request&error_description=bad+request&state=s"
        );
    }
}
