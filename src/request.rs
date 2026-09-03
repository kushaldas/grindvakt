//! Parsing and validation of OIDC authorization requests.

use crate::oauth_error::{OAuthError, OAuthErrorCode};
use std::collections::{BTreeMap, BTreeSet};

/// Compare OAuth `response_type` values as space-delimited sets.
///
/// RFC 6749 section 3.1.1 makes ordering insignificant. Empty members and
/// duplicate values are rejected so alternate spellings cannot create an
/// ambiguous authorization policy decision.
pub(crate) fn response_type_eq(left: &str, right: &str) -> bool {
    fn values(input: &str) -> Option<BTreeSet<&str>> {
        let mut result = BTreeSet::new();
        for value in input.split(' ') {
            if value.is_empty() || !result.insert(value) {
                return None;
            }
        }
        (!result.is_empty()).then_some(result)
    }

    matches!((values(left), values(right)), (Some(a), Some(b)) if a == b)
}

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
    /// Parse an ordered parameter list, rejecting duplicate protocol fields
    /// before converting it to the single-valued internal representation.
    pub fn from_pairs(params: &[(String, String)]) -> Result<Self, OAuthError> {
        let mut unique = BTreeMap::new();
        for (name, value) in params {
            if unique.insert(name.clone(), value.clone()).is_some() {
                return Err(OAuthError::invalid_request(format!(
                    "duplicate authorization parameter: {name}"
                )));
            }
        }
        Self::from_params(&unique)
    }

    /// Parse from a flat parameter map (query string or merged request object).
    pub fn from_params(params: &BTreeMap<String, String>) -> Result<Self, OAuthError> {
        let get = |k: &str| params.get(k).cloned();

        let client_id =
            get("client_id").ok_or_else(|| OAuthError::invalid_request("missing client_id"))?;
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

    /// Return whether `prompt` contains the exact, case-sensitive value.
    ///
    /// OpenID Connect defines `prompt` as a space-delimited list. Unknown
    /// values are intentionally left to the caller: OIDC Core allows an OP to
    /// ignore prompt values it does not understand.
    pub fn has_prompt(&self, expected: &str) -> bool {
        self.prompt.as_deref().is_some_and(|prompt| {
            prompt
                .split(' ')
                .filter(|value| !value.is_empty())
                .any(|value| value == expected)
        })
    }

    /// Validate the combinations constrained by OIDC Core for `prompt`.
    ///
    /// `none` must be the sole list entry because it forbids UI while every
    /// other standard value requests some form of interaction.
    pub fn validate_prompt(&self) -> Result<(), OAuthError> {
        let Some(prompt) = self.prompt.as_deref() else {
            return Ok(());
        };
        let mut value_count = 0;
        let mut has_none = false;
        for value in prompt.split(' ').filter(|value| !value.is_empty()) {
            value_count += 1;
            has_none |= value == "none";
        }
        if has_none && value_count != 1 {
            return Err(
                OAuthError::invalid_request("prompt=none must be the sole prompt value")
                    .with_state(self.state.clone()),
            );
        }
        Ok(())
    }

    /// True if the response_type requests an authorization code.
    pub fn wants_code(&self) -> bool {
        self.response_type.split_whitespace().any(|t| t == "code")
    }

    /// True if the response_type requests an id_token directly (implicit/hybrid).
    pub fn wants_id_token(&self) -> bool {
        self.response_type
            .split_whitespace()
            .any(|t| t == "id_token")
    }

    /// True if the response_type requests an access token directly.
    pub fn wants_access_token(&self) -> bool {
        self.response_type.split_whitespace().any(|t| t == "token")
    }

    /// Whether the response should be returned in the fragment.
    pub fn use_fragment(&self) -> bool {
        match self.response_mode.as_deref() {
            Some("fragment") => true,
            Some("query") => false,
            // Default: the pure code flow uses query; any response type that
            // returns an id_token from the authorization endpoint (implicit
            // and hybrid, OIDC Core §3.2.2.5 / §3.3.2.5) uses the fragment, so
            // the id_token never leaks into the URL (logs, Referer, history).
            _ => self.wants_id_token() || self.wants_access_token(),
        }
    }

    /// Validate the response_type is one we support.
    pub fn validate_response_type(&self) -> Result<(), OAuthError> {
        let supported = [
            "code",
            "id_token",
            "id_token token",
            "code id_token",
            "code token",
            "code id_token token",
        ]
        .iter()
        .any(|supported| response_type_eq(&self.response_type, supported));
        if !supported {
            return Err(OAuthError::new(
                OAuthErrorCode::UnsupportedResponseType,
                format!("unsupported response_type: {}", self.response_type),
            )
            .with_state(self.state.clone()));
        }
        if self.wants_id_token() && !self.is_oidc() {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidScope,
                "response_type containing id_token requires the openid scope",
            )
            .with_state(self.state.clone()));
        }
        Ok(())
    }

    /// Validate response-mode syntax and prevent tokens from entering URL
    /// queries, where they are exposed to logs, history, and referrers.
    pub fn validate_response_mode(&self) -> Result<(), OAuthError> {
        match self.response_mode.as_deref() {
            None | Some("fragment") => Ok(()),
            Some("query") if !self.wants_id_token() && !self.wants_access_token() => Ok(()),
            Some("query") => Err(OAuthError::invalid_request(
                "response_mode=query is not allowed for token-bearing responses",
            )
            .with_state(self.state.clone())),
            Some(other) => Err(OAuthError::invalid_request(format!(
                "unsupported response_mode: {other}"
            ))
            .with_state(self.state.clone())),
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

    #[test]
    fn id_token_flows_default_to_fragment_response_mode() {
        // Hybrid: the default is fragment, so the id_token is never in the URL
        // query (OIDC Core §3.3.2.5).
        let hybrid = AuthorizationRequest {
            response_type: "code id_token".into(),
            ..Default::default()
        };
        assert!(hybrid.use_fragment());

        // A front-channel access token also defaults to the fragment, even
        // when the response has no ID token.
        let code_token = AuthorizationRequest {
            response_type: "code token".into(),
            ..Default::default()
        };
        assert!(code_token.use_fragment());

        // Pure code flow keeps the query default.
        let code = AuthorizationRequest {
            response_type: "code".into(),
            ..Default::default()
        };
        assert!(!code.use_fragment());

        // An explicit unsafe response_mode is represented here, but request
        // validation rejects it before response construction.
        let explicit = AuthorizationRequest {
            response_type: "code id_token".into(),
            response_mode: Some("query".into()),
            ..Default::default()
        };
        assert!(!explicit.use_fragment());
        assert!(explicit.validate_response_mode().is_err());
    }

    #[test]
    fn rejects_duplicate_parameters_before_flattening() {
        let pairs = vec![
            ("client_id".into(), "first".into()),
            ("client_id".into(), "second".into()),
            ("response_type".into(), "code".into()),
            ("redirect_uri".into(), "https://rp/cb".into()),
        ];
        let err = AuthorizationRequest::from_pairs(&pairs).unwrap_err();
        assert_eq!(err.code, OAuthErrorCode::InvalidRequest);
    }

    #[test]
    fn validates_standard_response_types_and_modes() {
        for response_type in [
            "code",
            "id_token",
            "id_token token",
            "code id_token",
            "code token",
            "code id_token token",
        ] {
            let req = AuthorizationRequest {
                response_type: response_type.into(),
                scope: "openid".into(),
                ..Default::default()
            };
            req.validate_response_type().unwrap();
            req.validate_response_mode().unwrap();
        }

        let reordered = AuthorizationRequest {
            response_type: "token code id_token".into(),
            scope: "openid".into(),
            ..Default::default()
        };
        reordered.validate_response_type().unwrap();

        let duplicate = AuthorizationRequest {
            response_type: "code code".into(),
            scope: "openid".into(),
            ..Default::default()
        };
        assert_eq!(
            duplicate.validate_response_type().unwrap_err().code,
            OAuthErrorCode::UnsupportedResponseType
        );

        // RFC 6749's response-type grammar allows exactly one SP between
        // non-empty response names. Do not normalize malformed spellings.
        for response_type in [" code", "code ", "code  id_token"] {
            let malformed = AuthorizationRequest {
                response_type: response_type.into(),
                scope: "openid".into(),
                ..Default::default()
            };
            assert_eq!(
                malformed.validate_response_type().unwrap_err().code,
                OAuthErrorCode::UnsupportedResponseType,
                "malformed response_type must be rejected: {response_type:?}"
            );
        }

        let missing_openid = AuthorizationRequest {
            response_type: "id_token".into(),
            ..Default::default()
        };
        assert_eq!(
            missing_openid.validate_response_type().unwrap_err().code,
            OAuthErrorCode::InvalidScope
        );

        let unknown_mode = AuthorizationRequest {
            response_type: "code".into(),
            scope: "openid".into(),
            response_mode: Some("unknown".into()),
            ..Default::default()
        };
        assert!(unknown_mode.validate_response_mode().is_err());
    }

    #[test]
    fn prompt_values_are_exact_and_case_sensitive() {
        let req = AuthorizationRequest {
            prompt: Some(" login  consent ".into()),
            ..Default::default()
        };
        assert!(req.has_prompt("login"));
        assert!(req.has_prompt("consent"));
        assert!(!req.has_prompt(""));
        assert!(!req.has_prompt("none"));
        assert!(!req.has_prompt("Login"));
        assert!(!req.has_prompt("log"));
    }

    #[test]
    fn prompt_none_must_be_the_only_list_entry() {
        for prompt in ["login none", "none none"] {
            let req = AuthorizationRequest {
                state: Some("state-1".into()),
                prompt: Some(prompt.into()),
                ..Default::default()
            };
            let err = req.validate_prompt().unwrap_err();
            assert_eq!(err.code, OAuthErrorCode::InvalidRequest, "prompt={prompt}");
            assert_eq!(err.state.as_deref(), Some("state-1"));
        }
    }
}
