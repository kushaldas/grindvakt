//! The OpenID Provider engine — pure protocol logic for the OP (frontend) side.
//!
//! Stateless: authorization codes and access tokens carry their own state
//! (sealed via [`crate::tokens::TokenCodec`]); id_tokens are signed JWTs. No
//! server-side session store is consulted at the token or userinfo endpoints.

use crate::client::{Client, ClientStore, AUTH_NONE, AUTH_PRIVATE_KEY_JWT};
use crate::jwt;
use crate::keys::SigningKey;
use crate::metadata::ProviderMetadata;
use crate::oauth_error::{OAuthError, OAuthErrorCode};
use crate::pkce;
use crate::request::AuthorizationRequest;
use crate::tokens::{AccessTokenPayload, AuthCodePayload, RefreshTokenPayload, TokenCodec};
use crate::util::now_secs;
use base64::Engine;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Claims, Validation};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The JWT-bearer client assertion type (RFC 7523).
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Configuration knobs for token lifetimes.
#[derive(Debug, Clone)]
pub struct TokenLifetimes {
    pub code_ttl: u64,
    pub access_token_ttl: u64,
    pub id_token_ttl: u64,
    /// Lifetime of an issued refresh token (RFC 6749 §6). Refresh tokens are
    /// rotated on each use, so this is a sliding window from the last refresh.
    pub refresh_token_ttl: u64,
}

impl Default for TokenLifetimes {
    fn default() -> Self {
        Self {
            code_ttl: 600,
            access_token_ttl: 3600,
            id_token_ttl: 3600,
            refresh_token_ttl: 2_592_000, // 30 days
        }
    }
}

/// The OpenID Provider engine.
pub struct Provider {
    pub metadata: ProviderMetadata,
    pub signing_key: SigningKey,
    pub clients: Arc<dyn ClientStore>,
    pub codec: TokenCodec,
    pub lifetimes: TokenLifetimes,
}

/// The token endpoint success response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl Provider {
    pub fn new(
        metadata: ProviderMetadata,
        signing_key: SigningKey,
        clients: Arc<dyn ClientStore>,
        codec: TokenCodec,
        lifetimes: TokenLifetimes,
    ) -> Self {
        Self {
            metadata,
            signing_key,
            clients,
            codec,
            lifetimes,
        }
    }

    /// The `.well-known/openid-configuration` document.
    pub fn discovery_document(&self) -> serde_json::Value {
        self.metadata.to_json()
    }

    /// The public JWKS for the `jwks` endpoint.
    pub fn jwks_document(&self) -> JwkSet {
        self.signing_key.to_public_jwks()
    }

    // ── Authorization endpoint ──────────────────────────────────────────

    /// Validate an authorization request against the registered client.
    /// Returns the client so the caller can proceed to authenticate the user.
    pub async fn validate_authorization_request(
        &self,
        req: &AuthorizationRequest,
    ) -> Result<Client, OAuthError> {
        let client = self
            .clients
            .get(&req.client_id)
            .await
            .ok_or_else(|| OAuthError::invalid_request("unknown client_id"))?;

        if !client.allows_redirect(&req.redirect_uri) {
            return Err(OAuthError::invalid_request("redirect_uri not registered"));
        }
        req.validate_response_type()?;
        if !client.allows_response_type(&req.response_type) {
            return Err(OAuthError::new(
                OAuthErrorCode::UnauthorizedClient,
                "response_type not allowed for client",
            )
            .with_state(req.state.clone()));
        }
        Ok(client)
    }

    /// Build the authorization response (a redirect carrying `code` and/or
    /// `id_token`) after the user has authenticated and claims were released.
    pub fn authorization_redirect(
        &self,
        req: &AuthorizationRequest,
        sub: &str,
        external_claims: &BTreeMap<String, Vec<String>>,
        acr: Option<String>,
    ) -> Result<crate::http::Response, OAuthError> {
        let claims = flatten_claims(external_claims);
        let auth_time = now_secs();
        let mut out: Vec<(String, String)> = Vec::new();

        if req.wants_code() {
            let payload = AuthCodePayload {
                client_id: req.client_id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                scope: req.scope.clone(),
                sub: sub.to_string(),
                nonce: req.nonce.clone(),
                code_challenge: req.code_challenge.clone(),
                code_challenge_method: req.code_challenge_method.clone(),
                claims: claims.clone(),
                auth_time,
                exp: now_secs() + self.lifetimes.code_ttl,
                acr: acr.clone(),
            };
            let code = self
                .codec
                .seal_code(&payload)
                .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;
            out.push(("code".to_string(), code));
        }

        if req.wants_id_token() {
            // Implicit / hybrid: mint an id_token directly.
            let id_token = self
                .build_id_token(
                    &req.client_id,
                    sub,
                    req.nonce.as_deref(),
                    &claims,
                    acr.as_deref(),
                    auth_time,
                )
                .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;
            out.push(("id_token".to_string(), id_token));
        }

        if let Some(state) = &req.state {
            out.push(("state".to_string(), state.clone()));
        }

        Ok(redirect_with(&req.redirect_uri, &out, req.use_fragment()))
    }

    // ── Token endpoint ──────────────────────────────────────────────────

    /// Handle a token request. `auth_header` is the raw Authorization header
    /// value; `token_url` is this endpoint's absolute URL (for `private_key_jwt`
    /// audience checking).
    ///
    /// `dpop` is an already-validated DPoP proof (RFC 9449) for this request, if
    /// the client presented one — validate it in the web layer with
    /// [`crate::dpop::validate_proof`] and thread the result here. When present
    /// the issued access token is sender-constrained (`token_type: DPoP`,
    /// `cnf.jkt` bound to the proof key).
    pub async fn handle_token_request(
        &self,
        form: &BTreeMap<String, String>,
        auth_header: Option<&str>,
        token_url: &str,
        dpop: Option<&crate::dpop::DpopProof>,
    ) -> Result<TokenResponse, OAuthError> {
        let grant_type = form
            .get("grant_type")
            .map(|s| s.as_str())
            .ok_or_else(|| OAuthError::invalid_request("missing grant_type"))?;
        match grant_type {
            "authorization_code" => {
                self.handle_authorization_code(form, auth_header, token_url, dpop)
                    .await
            }
            "client_credentials" => {
                self.handle_client_credentials(form, auth_header, token_url, dpop)
                    .await
            }
            "refresh_token" => {
                self.handle_refresh_token(form, auth_header, token_url, dpop)
                    .await
            }
            other => Err(OAuthError::new(
                OAuthErrorCode::UnsupportedGrantType,
                format!("unsupported grant_type: {other}"),
            )),
        }
    }

    /// "DPoP" when the request was DPoP-bound, else "Bearer".
    fn token_type(dpop: Option<&crate::dpop::DpopProof>) -> &'static str {
        if dpop.is_some() {
            "DPoP"
        } else {
            "Bearer"
        }
    }

    async fn handle_authorization_code(
        &self,
        form: &BTreeMap<String, String>,
        auth_header: Option<&str>,
        token_url: &str,
        dpop: Option<&crate::dpop::DpopProof>,
    ) -> Result<TokenResponse, OAuthError> {
        let client = self
            .authenticate_client(form, auth_header, token_url)
            .await?;

        let code = form
            .get("code")
            .ok_or_else(|| OAuthError::invalid_request("missing code"))?;
        let payload = self
            .codec
            .open_code(code)
            .map_err(|_| OAuthError::invalid_grant("invalid or expired code"))?;

        // The code is bound to the authenticating client.
        if payload.client_id != client.client_id {
            return Err(OAuthError::invalid_grant(
                "code was issued to another client",
            ));
        }

        // redirect_uri must match the one used at the authorization endpoint.
        if let Some(redirect_uri) = form.get("redirect_uri") {
            if redirect_uri != &payload.redirect_uri {
                return Err(OAuthError::invalid_grant("redirect_uri mismatch"));
            }
        }

        // PKCE.
        if let Some(challenge) = &payload.code_challenge {
            let verifier = form
                .get("code_verifier")
                .ok_or_else(|| OAuthError::invalid_grant("missing code_verifier"))?;
            if !pkce::verify(
                verifier,
                challenge,
                payload.code_challenge_method.as_deref(),
            ) {
                return Err(OAuthError::invalid_grant("PKCE verification failed"));
            }
        }

        // Mint access token + id_token.
        let access_payload = AccessTokenPayload {
            client_id: client.client_id.clone(),
            sub: payload.sub.clone(),
            scope: payload.scope.clone(),
            claims: payload.claims.clone(),
            exp: now_secs() + self.lifetimes.access_token_ttl,
            cnf_jkt: dpop.map(|d| d.jkt.clone()),
        };
        let access_token = self
            .codec
            .seal_access_token(&access_payload)
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        let id_token = self
            .build_id_token(
                &client.client_id,
                &payload.sub,
                payload.nonce.as_deref(),
                &payload.claims,
                payload.acr.as_deref(),
                payload.auth_time,
            )
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        // Issue a refresh token only when the client is registered for the grant
        // (RFC 6749 §6). It carries the original auth_time/nonce/acr so refreshed
        // id_tokens stay faithful to the initial authentication.
        let refresh_token = if client_allows_refresh(&client) {
            let rt = RefreshTokenPayload {
                client_id: client.client_id.clone(),
                sub: payload.sub.clone(),
                scope: payload.scope.clone(),
                nonce: payload.nonce.clone(),
                claims: payload.claims.clone(),
                auth_time: payload.auth_time,
                exp: now_secs() + self.lifetimes.refresh_token_ttl,
                acr: payload.acr.clone(),
                cnf_jkt: dpop.map(|d| d.jkt.clone()),
            };
            Some(
                self.codec
                    .seal_refresh_token(&rt)
                    .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?,
            )
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: Self::token_type(dpop).to_string(),
            expires_in: self.lifetimes.access_token_ttl,
            id_token: Some(id_token),
            scope: Some(payload.scope),
            refresh_token,
        })
    }

    /// The `client_credentials` grant (RFC 6749 §4.4): service-to-service
    /// tokens. Authenticates the client, requires the grant to be allowed for
    /// it, intersects requested ∩ allowed scopes, and mints a sealed access
    /// token (no id_token — there is no end user). DPoP binding applies.
    async fn handle_client_credentials(
        &self,
        form: &BTreeMap<String, String>,
        auth_header: Option<&str>,
        token_url: &str,
        dpop: Option<&crate::dpop::DpopProof>,
    ) -> Result<TokenResponse, OAuthError> {
        let client = self
            .authenticate_client(form, auth_header, token_url)
            .await?;

        // RFC 6749 §4.4: client_credentials is for confidential clients only. A
        // public ("none"-auth) client proves no possession of a secret, so issuing
        // it a token would let anyone who knows the client_id mint tokens. Refuse
        // it regardless of the registered grant list.
        if client.token_endpoint_auth_method == AUTH_NONE {
            return Err(OAuthError::invalid_client(
                "client_credentials requires confidential client authentication",
            ));
        }

        if !client.grant_types.iter().any(|g| g == "client_credentials") {
            return Err(OAuthError::invalid_grant(
                "client_credentials grant not allowed for client",
            ));
        }

        // Intersect requested scopes with the client's allowed scopes. With no
        // `scope` parameter, grant the client's full registered scope set.
        let allowed: Vec<String> = client
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let granted: Vec<String> = match form.get("scope") {
            Some(requested) => requested
                .split_whitespace()
                .filter(|s| allowed.iter().any(|a| a == s))
                .map(str::to_string)
                .collect(),
            None => allowed.clone(),
        };
        if granted.is_empty() {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidScope,
                "no valid scopes requested",
            ));
        }
        let scope = granted.join(" ");

        // Subject is the client itself for client_credentials.
        let access_payload = AccessTokenPayload {
            client_id: client.client_id.clone(),
            sub: client.client_id.clone(),
            scope: scope.clone(),
            claims: BTreeMap::new(),
            exp: now_secs() + self.lifetimes.access_token_ttl,
            cnf_jkt: dpop.map(|d| d.jkt.clone()),
        };
        let access_token = self
            .codec
            .seal_access_token(&access_payload)
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        Ok(TokenResponse {
            access_token,
            token_type: Self::token_type(dpop).to_string(),
            expires_in: self.lifetimes.access_token_ttl,
            id_token: None,
            scope: Some(scope),
            refresh_token: None,
        })
    }

    /// The `refresh_token` grant (RFC 6749 §6): exchange a refresh token for a
    /// fresh access token and id_token, optionally narrowing scope. The refresh
    /// token is a stateless sealed [`RefreshTokenPayload`]; it is rotated on each
    /// use (a new one is returned) but, with no server-side store, cannot be
    /// revoked before its own expiry. DPoP binding applies to the new access
    /// token when a proof is presented.
    async fn handle_refresh_token(
        &self,
        form: &BTreeMap<String, String>,
        auth_header: Option<&str>,
        token_url: &str,
        dpop: Option<&crate::dpop::DpopProof>,
    ) -> Result<TokenResponse, OAuthError> {
        let client = self
            .authenticate_client(form, auth_header, token_url)
            .await?;

        if !client_allows_refresh(&client) {
            return Err(OAuthError::invalid_grant(
                "refresh_token grant not allowed for client",
            ));
        }

        let token = form
            .get("refresh_token")
            .ok_or_else(|| OAuthError::invalid_request("missing refresh_token"))?;
        let rt = self
            .codec
            .open_refresh_token(token)
            .map_err(|_| OAuthError::invalid_grant("invalid or expired refresh_token"))?;

        // The refresh token is bound to the authenticating client.
        if rt.client_id != client.client_id {
            return Err(OAuthError::invalid_grant(
                "refresh token was issued to another client",
            ));
        }

        let cnf_jkt = match rt.cnf_jkt.as_deref() {
            Some(bound_jkt) => match dpop {
                Some(proof) if proof.jkt == bound_jkt => Some(bound_jkt.to_string()),
                Some(_) => {
                    return Err(OAuthError::invalid_dpop_proof(
                        "DPoP proof key does not match the refresh token's cnf.jkt",
                    ));
                }
                None => {
                    return Err(OAuthError::invalid_dpop_proof(
                        "refresh token is DPoP-bound; a matching DPoP proof is required",
                    ));
                }
            },
            None => dpop.map(|proof| proof.jkt.clone()),
        };

        // Scope may only be narrowed (RFC 6749 §6): a requested scope must be a
        // subset of what was originally granted. Absent, the full grant carries.
        let scope = match form.get("scope") {
            Some(requested) => {
                let requested_scopes: Vec<&str> = requested.split_whitespace().collect();
                let original_scopes: Vec<&str> = rt.scope.split_whitespace().collect();
                if requested_scopes.is_empty()
                    || requested_scopes
                        .iter()
                        .any(|scope| !original_scopes.iter().any(|original| original == scope))
                {
                    return Err(OAuthError::new(
                        OAuthErrorCode::InvalidScope,
                        "requested scope exceeds original grant",
                    ));
                }
                requested_scopes.join(" ")
            }
            None => rt.scope.clone(),
        };

        let now = now_secs();
        let access_payload = AccessTokenPayload {
            client_id: client.client_id.clone(),
            sub: rt.sub.clone(),
            scope: scope.clone(),
            claims: rt.claims.clone(),
            exp: now + self.lifetimes.access_token_ttl,
            cnf_jkt: cnf_jkt.clone(),
        };
        let access_token = self
            .codec
            .seal_access_token(&access_payload)
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        let id_token = self
            .build_id_token(
                &client.client_id,
                &rt.sub,
                rt.nonce.as_deref(),
                &rt.claims,
                rt.acr.as_deref(),
                rt.auth_time,
            )
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        // Rotate the refresh token (sliding expiry), carrying the narrowed scope.
        let new_refresh = RefreshTokenPayload {
            client_id: client.client_id.clone(),
            sub: rt.sub.clone(),
            scope: scope.clone(),
            nonce: rt.nonce.clone(),
            claims: rt.claims.clone(),
            auth_time: rt.auth_time,
            exp: now + self.lifetimes.refresh_token_ttl,
            acr: rt.acr.clone(),
            cnf_jkt,
        };
        let refresh_token = self
            .codec
            .seal_refresh_token(&new_refresh)
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        Ok(TokenResponse {
            access_token,
            token_type: Self::token_type(dpop).to_string(),
            expires_in: self.lifetimes.access_token_ttl,
            id_token: Some(id_token),
            scope: Some(scope),
            refresh_token: Some(refresh_token),
        })
    }

    // ── UserInfo endpoint ───────────────────────────────────────────────

    /// Return the userinfo claims for a presented access token.
    ///
    /// `presented_jkt` is the JWK thumbprint of a DPoP proof the caller validated
    /// for this request (or `None` for a plain Bearer presentation). When the
    /// access token is DPoP-bound (`cnf.jkt` sealed in), the binding is enforced
    /// here per RFC 9449 §7.1: the proof key must match, and a bound token
    /// presented without a proof (i.e. as plain Bearer) is rejected.
    pub async fn userinfo(
        &self,
        access_token: &str,
        presented_jkt: Option<&str>,
    ) -> Result<serde_json::Value, OAuthError> {
        let payload = self
            .codec
            .open_access_token(access_token)
            .map_err(|_| OAuthError::new(OAuthErrorCode::AccessDenied, "invalid access token"))?;

        if let Some(bound_jkt) = payload.cnf_jkt.as_deref() {
            match presented_jkt {
                Some(jkt) if jkt == bound_jkt => {}
                Some(_) => {
                    return Err(OAuthError::invalid_dpop_proof(
                        "DPoP proof key does not match the access token's cnf.jkt",
                    ));
                }
                None => {
                    return Err(OAuthError::invalid_dpop_proof(
                        "access token is DPoP-bound; a matching DPoP proof is required",
                    ));
                }
            }
        }

        let mut map = serde_json::Map::new();
        for (k, v) in payload.claims {
            map.insert(k, v);
        }
        // The canonical subject is authoritative: a released claim named `sub`
        // (e.g. mapped from eduPersonPrincipalName) must not override it.
        map.insert("sub".to_string(), serde_json::Value::String(payload.sub));
        Ok(serde_json::Value::Object(map))
    }

    // ── Client authentication ───────────────────────────────────────────

    /// Authenticate the token-endpoint client across the supported methods.
    pub async fn authenticate_client(
        &self,
        form: &BTreeMap<String, String>,
        auth_header: Option<&str>,
        token_url: &str,
    ) -> Result<Client, OAuthError> {
        // private_key_jwt (RFC 7523).
        if let Some(assertion) = form.get("client_assertion") {
            let atype = form.get("client_assertion_type").map(|s| s.as_str());
            if atype != Some(CLIENT_ASSERTION_TYPE) {
                return Err(OAuthError::invalid_client("invalid client_assertion_type"));
            }
            return self
                .verify_private_key_jwt(assertion, form, token_url)
                .await;
        }

        // client_secret_basic.
        if let Some(header) = auth_header {
            if let Some(b64) = header.strip_prefix("Basic ") {
                let (id, secret) = decode_basic(b64)
                    .ok_or_else(|| OAuthError::invalid_client("malformed Basic auth"))?;
                return self.check_secret(&id, &secret).await;
            }
        }

        // client_secret_post.
        if let (Some(id), Some(secret)) = (form.get("client_id"), form.get("client_secret")) {
            return self.check_secret(id, secret).await;
        }

        // public client (auth method "none").
        if let Some(id) = form.get("client_id") {
            let client = self
                .clients
                .get(id)
                .await
                .ok_or_else(|| OAuthError::invalid_client("unknown client"))?;
            if client.token_endpoint_auth_method == crate::client::AUTH_NONE {
                return Ok(client);
            }
        }

        Err(OAuthError::invalid_client("client authentication required"))
    }

    async fn check_secret(&self, client_id: &str, secret: &str) -> Result<Client, OAuthError> {
        let client = self
            .clients
            .get(client_id)
            .await
            .ok_or_else(|| OAuthError::invalid_client("unknown client"))?;
        match &client.client_secret {
            Some(expected) if constant_time_eq(expected.as_bytes(), secret.as_bytes()) => {
                Ok(client)
            }
            _ => Err(OAuthError::invalid_client("bad client secret")),
        }
    }

    async fn verify_private_key_jwt(
        &self,
        assertion: &str,
        form: &BTreeMap<String, String>,
        token_url: &str,
    ) -> Result<Client, OAuthError> {
        // Determine client_id from the form or from the assertion's iss/sub.
        let client_id = match form.get("client_id") {
            Some(id) => id.clone(),
            None => {
                let claims = jwt::peek_claims_unverified(assertion)
                    .map_err(|_| OAuthError::invalid_client("unreadable client_assertion"))?;
                claims
                    .sub
                    .or(claims.iss)
                    .ok_or_else(|| OAuthError::invalid_client("client_assertion missing sub/iss"))?
            }
        };

        let client = self
            .clients
            .get(&client_id)
            .await
            .ok_or_else(|| OAuthError::invalid_client("unknown client"))?;
        if client.token_endpoint_auth_method != AUTH_PRIVATE_KEY_JWT {
            return Err(OAuthError::invalid_client(
                "client is not configured for private_key_jwt",
            ));
        }
        let jwks = client
            .jwks
            .as_ref()
            .ok_or_else(|| OAuthError::invalid_client("client has no keys for private_key_jwt"))?;

        // RFC 7523: iss == sub == client_id, aud == token endpoint URL (or issuer),
        // signature valid, not expired.
        let validation = Validation::new()
            .with_issuer(&client_id)
            .with_subject(&client_id);
        let claims = jwt::verify_with_jwks(jwks, assertion, &validation)
            .map_err(|e| OAuthError::invalid_client(format!("client_assertion invalid: {e}")))?;

        // Audience must include the token endpoint or the issuer identifier.
        let aud_ok = match &claims.aud {
            Some(aud) => aud.contains(token_url) || aud.contains(&self.metadata.issuer),
            None => false,
        };
        if !aud_ok {
            return Err(OAuthError::invalid_client(
                "client_assertion audience mismatch",
            ));
        }

        Ok(client)
    }

    // ── id_token construction ───────────────────────────────────────────

    fn build_id_token(
        &self,
        client_id: &str,
        sub: &str,
        nonce: Option<&str>,
        claims: &BTreeMap<String, serde_json::Value>,
        acr: Option<&str>,
        auth_time: u64,
    ) -> crate::error::Result<String> {
        let now = now_secs();
        let mut c = Claims::default();
        c.iss = Some(self.metadata.issuer.clone());
        c.sub = Some(sub.to_string());
        c.aud = Some(jose_rs::jwt::Audience::Single(client_id.to_string()));
        c.iat = Some(now);
        c.exp = Some(now + self.lifetimes.id_token_ttl);
        if let Some(n) = nonce {
            c.extra
                .insert("nonce".into(), serde_json::Value::String(n.to_string()));
        }
        if let Some(a) = acr {
            c.extra
                .insert("acr".into(), serde_json::Value::String(a.to_string()));
        }
        // `auth_time` reflects the *original* end-user authentication, so it is
        // carried through code/refresh exchanges rather than reset to now.
        c.extra
            .insert("auth_time".into(), serde_json::json!(auth_time));
        for (k, v) in claims {
            // Released claims must never shadow the registered claims set as
            // typed fields: serde flattens `extra`, so a released `sub`
            // (e.g. an attribute map that emits `sub` from eduPersonPrincipalName)
            // would serialize a second `sub` key and break strict JWT parsers.
            if is_reserved_id_token_claim(k) {
                continue;
            }
            c.extra.insert(k.clone(), v.clone());
        }
        jwt::sign(&self.signing_key, &c, None)
    }
}

/// Whether the client is registered for the `refresh_token` grant (RFC 6749 §6).
fn client_allows_refresh(client: &Client) -> bool {
    client.grant_types.iter().any(|g| g == "refresh_token")
}

/// Flatten a multi-valued external claim map into JSON values: single-element
/// lists become scalars, multi-element lists become arrays.
/// Registered claims that `build_id_token` sets as typed [`Claims`] fields (or
/// inserts itself). Released attribute claims carrying these names are dropped
/// so the flattened `extra` map cannot emit a duplicate JSON key.
fn is_reserved_id_token_claim(name: &str) -> bool {
    matches!(
        name,
        "iss" | "sub" | "aud" | "exp" | "iat" | "nbf" | "jti" | "nonce" | "auth_time"
    )
}

pub fn flatten_claims(
    external: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, serde_json::Value> {
    external
        .iter()
        .map(|(k, v)| {
            let value = if v.len() == 1 {
                serde_json::Value::String(v[0].clone())
            } else {
                serde_json::Value::Array(
                    v.iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                )
            };
            (k.clone(), value)
        })
        .collect()
}

/// Build a redirect response appending params to the URI's query or fragment.
fn redirect_with(
    redirect_uri: &str,
    params: &[(String, String)],
    fragment: bool,
) -> crate::http::Response {
    let encoded: String = params
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                crate::oauth_error::urlencode(k),
                crate::oauth_error::urlencode(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let sep = if fragment {
        '#'
    } else if redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    crate::http::Response::redirect(format!("{redirect_uri}{sep}{encoded}"))
}

fn decode_basic(b64: &str) -> Option<(String, String)> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((percent_decode(id), percent_decode(secret)))
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
