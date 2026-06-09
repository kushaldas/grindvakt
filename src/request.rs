//! Parsing and validation of OIDC authorization requests.

use crate::oauth_error::{OAuthError, OAuthErrorCode};
use std::collections::BTreeMap;

/// A parsed OIDC authorization request.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<serde_json::Value>,
    /// The raw `request` parameter (RFC 9101 request object JWT), if present.
    pub request_object: Option<String>,
    /// Other parameters preserved verbatim.
    pub extra: BTreeMap<String, String>,
}

impl AuthorizationRequest {
    /// Parse from a flat parameter map (query string or merged request object).
    pub fn from_params(params: &BTreeMap<String, String>) -> Result<Self, OAuthError> {
        let get = |k: &str| params.get(k).cloned();

        let client_id = get("client_id")
            .ok_or_else(|| OAuthError::invalid_request("missing client_id"))?;
        let response_type = get("response_type")
            .ok_or_else(|| OAuthError::invalid_request("missing response_type"))?;
        let redirect_uri = get("redirect_uri")
            .ok_or_else(|| OAuthError::invalid_request("missing redirect_uri"))?;
        let scope = get("scope").unwrap_or_default();

        let claims = match get("claims") {
            Some(s) => Some(
                serde_json::from_str(&s)
                    .map_err(|_| OAuthError::invalid_request("invalid claims parameter"))?,
            ),
            None => None,
        };

        let known = [
            "client_id",
            "response_type",
            "redirect_uri",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
            "response_mode",
            "prompt",
            "acr_values",
            "claims",
            "request",
        ];
        let extra = params
            .iter()
            .filter(|(k, _)| !known.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(Self {
            client_id,
            redirect_uri,
            response_type,
            scope,
            state: get("state"),
            nonce: get("nonce"),
            code_challenge: get("code_challenge"),
            code_challenge_method: get("code_challenge_method"),
            response_mode: get("response_mode"),
            prompt: get("prompt"),
            acr_values: get("acr_values"),
            claims,
            request_object: get("request"),
            extra,
        })
    }

    /// The scopes as a vector.
    pub fn scopes(&self) -> Vec<&str> {
        self.scope.split_whitespace().collect()
    }

    /// True if this is an OIDC request (scope contains `openid`).
    pub fn is_oidc(&self) -> bool {
        self.scopes().contains(&"openid")
    }

    /// True if the response_type requests an authorization code.
    pub fn wants_code(&self) -> bool {
        self.response_type
            .split_whitespace()
            .any(|t| t == "code")
    }

    /// True if the response_type requests an id_token directly (implicit/hybrid).
    pub fn wants_id_token(&self) -> bool {
        self.response_type
            .split_whitespace()
            .any(|t| t == "id_token")
    }

    /// Whether the response should be returned in the fragment.
    pub fn use_fragment(&self) -> bool {
        match self.response_mode.as_deref() {
            Some("fragment") => true,
            Some("query") => false,
            // Default: code flow uses query, implicit/hybrid use fragment.
            _ => self.wants_id_token() && !self.wants_code(),
        }
    }

    /// Validate the response_type is one we support.
    pub fn validate_response_type(&self) -> Result<(), OAuthError> {
        let supported = matches!(
            self.response_type.as_str(),
            "code" | "id_token" | "id_token token" | "code id_token"
        );
        if supported {
            Ok(())
        } else {
            Err(OAuthError::new(
                OAuthErrorCode::UnsupportedResponseType,
                format!("unsupported response_type: {}", self.response_type),
            )
            .with_state(self.state.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_code_flow_request() {
        let p = params(&[
            ("client_id", "c1"),
            ("response_type", "code"),
            ("redirect_uri", "https://rp/cb"),
            ("scope", "openid email"),
            ("state", "xyz"),
            ("nonce", "n1"),
            ("code_challenge", "ch"),
            ("code_challenge_method", "S256"),
            ("custom", "v"),
        ]);
        let req = AuthorizationRequest::from_params(&p).unwrap();
        assert_eq!(req.client_id, "c1");
        assert!(req.is_oidc());
        assert!(req.wants_code());
        assert!(!req.wants_id_token());
        assert_eq!(req.extra.get("custom").map(|s| s.as_str()), Some("v"));
        req.validate_response_type().unwrap();
    }

    #[test]
    fn missing_client_id_errors() {
        let p = params(&[("response_type", "code"), ("redirect_uri", "https://rp/cb")]);
        assert!(AuthorizationRequest::from_params(&p).is_err());
    }
}
