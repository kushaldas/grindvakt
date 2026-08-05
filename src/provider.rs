//! The OpenID Provider engine — pure protocol logic for the OP (frontend) side.
//!
//! Authorization codes, access tokens, and refresh tokens carry their own state
//! (sealed via [`crate::tokens::TokenCodec`]); id_tokens are signed JWTs. A
//! small token-use store is still required for one-time authorization-code use
//! and refresh-token rotation.

use crate::client::{
    Client, ClientStore, AUTH_CLIENT_SECRET_BASIC, AUTH_CLIENT_SECRET_POST, AUTH_NONE,
    AUTH_PRIVATE_KEY_JWT,
};
use crate::jwt;
use crate::keys::SigningKey;
use crate::mac::sha256;
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
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

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
///
/// Construct with [`Provider::new`]; the token-use store is installed via
/// [`Provider::with_token_use_store`] rather than a public field so adding
/// stores later does not break struct-literal construction downstream.
pub struct Provider {
    pub metadata: ProviderMetadata,
    pub signing_key: SigningKey,
    pub clients: Arc<dyn ClientStore>,
    pub codec: TokenCodec,
    pub lifetimes: TokenLifetimes,
    token_use_store: Arc<dyn TokenUseStore>,
    /// Maximum accepted age of a `private_key_jwt` client assertion
    /// (RFC 7523), measured from `iat`. Defaults to
    /// [`DEFAULT_CLIENT_ASSERTION_MAX_AGE`]; see
    /// [`Provider::with_client_assertion_max_age`].
    client_assertion_max_age: u64,
}

/// Default maximum age of a `private_key_jwt` client assertion, in seconds.
pub const DEFAULT_CLIENT_ASSERTION_MAX_AGE: u64 = 300;

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

/// Atomic store for one-time token use.
///
/// The token endpoint uses this to consume authorization codes and refresh
/// tokens exactly once. Deployments with multiple replicas should supply a
/// shared implementation; the default in-memory store protects a single
/// process.
#[async_trait::async_trait]
pub trait TokenUseStore: Send + Sync {
    /// Mark `token_hash` as consumed for `ttl_secs`. Returns `Ok(true)` when
    /// this call consumed it, `Ok(false)` when it was already live/consumed.
    async fn consume(&self, token_hash: &str, ttl_secs: u64) -> std::result::Result<bool, String>;
}

/// Single-process [`TokenUseStore`] implementation.
#[derive(Default)]
pub struct InMemoryTokenUseStore {
    inner: RwLock<InMemoryTokenUseInner>,
}

#[derive(Default)]
struct InMemoryTokenUseInner {
    entries: HashMap<String, u64>,
    /// Earliest time the next full expiry sweep may run.
    next_purge: u64,
}

/// How often [`InMemoryTokenUseStore`] sweeps expired entries from the map.
/// Correctness never depends on the sweep — an expired entry for the consumed
/// token is detected on lookup — so this only bounds memory growth.
const IN_MEMORY_PURGE_INTERVAL_SECS: u64 = 60;

impl InMemoryTokenUseStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl TokenUseStore for InMemoryTokenUseStore {
    async fn consume(&self, token_hash: &str, ttl_secs: u64) -> std::result::Result<bool, String> {
        let now = now_secs();
        let mut g = self
            .inner
            .write()
            .map_err(|_| "token-use store lock poisoned".to_string())?;
        if now >= g.next_purge {
            g.entries.retain(|_, exp| *exp > now);
            g.next_purge = now + IN_MEMORY_PURGE_INTERVAL_SECS;
        }
        match g.entries.get(token_hash) {
            Some(exp) if *exp > now => Ok(false),
            _ => {
                g.entries
                    .insert(token_hash.to_string(), now + ttl_secs.max(1));
                Ok(true)
            }
        }
    }
}

/// Redis-backed [`TokenUseStore`] implementation for multi-process deployments.
///
/// Values are written with `SET key 1 NX EX ttl`, so the first consumer wins and
/// Redis expires the replay marker after the original token lifetime.
///
/// Commands run over a shared async [`redis::aio::ConnectionManager`]
/// (multiplexed, reconnecting), so consuming a token never blocks the async
/// executor and does not open a new connection per call. The `redis` feature
/// enables the tokio-backed transport of the `redis` crate.
#[cfg(feature = "redis")]
pub struct RedisStore {
    conn: redis::aio::ConnectionManager,
    key_prefix: String,
}

#[cfg(feature = "redis")]
impl RedisStore {
    pub const DEFAULT_KEY_PREFIX: &'static str = "grindvakt:token-use:";

    pub fn new(redis_url: &str) -> redis::RedisResult<Self> {
        Self::from_client(redis::Client::open(redis_url)?)
    }

    pub fn from_client(client: redis::Client) -> redis::RedisResult<Self> {
        let conn = client.get_connection_manager_lazy(redis::aio::ConnectionManagerConfig::new())?;
        Ok(Self {
            conn,
            key_prefix: Self::DEFAULT_KEY_PREFIX.to_string(),
        })
    }

    pub fn with_key_prefix(mut self, key_prefix: impl Into<String>) -> Self {
        self.key_prefix = key_prefix.into();
        self
    }

    fn key(&self, token_hash: &str) -> String {
        format!("{}{}", self.key_prefix, token_hash)
    }
}

#[cfg(feature = "redis")]
#[async_trait::async_trait]
impl TokenUseStore for RedisStore {
    async fn consume(&self, token_hash: &str, ttl_secs: u64) -> std::result::Result<bool, String> {
        // ConnectionManager is a cheap handle over one shared multiplexed
        // connection; cloning it per call is the intended usage.
        let mut conn = self.conn.clone();
        redis_consume_token_once(&mut conn, &self.key(token_hash), ttl_secs)
            .await
            .map_err(|e| e.to_string())
    }
}

#[cfg(feature = "redis")]
async fn redis_consume_token_once<C: redis::aio::ConnectionLike>(
    conn: &mut C,
    key: &str,
    ttl_secs: u64,
) -> redis::RedisResult<bool> {
    let response: redis::Value = redis::cmd("SET")
        .arg(key)
        .arg("1")
        .arg("EX")
        .arg(ttl_secs.max(1))
        .arg("NX")
        .query_async(conn)
        .await?;

    match response {
        redis::Value::Okay => Ok(true),
        redis::Value::SimpleString(s) if s.eq_ignore_ascii_case("OK") => Ok(true),
        redis::Value::Nil => Ok(false),
        other => Err(redis::RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "unexpected Redis SET NX response",
            format!("{other:?}"),
        ))),
    }
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
            token_use_store: Arc::new(InMemoryTokenUseStore::new()),
            client_assertion_max_age: DEFAULT_CLIENT_ASSERTION_MAX_AGE,
        }
    }

    /// Replace the default single-process token-use store.
    pub fn with_token_use_store(mut self, store: Arc<dyn TokenUseStore>) -> Self {
        self.token_use_store = store;
        self
    }

    /// Override the maximum accepted age of `private_key_jwt` client
    /// assertions (measured from `iat`; `exp` and a single-use `jti` are
    /// always required). The default of 300 seconds follows the OAuth
    /// Security BCP; widen it only for clients that cannot mint fresh
    /// assertions per token request — a wider window extends how long a
    /// captured assertion stays usable, and the `jti` store retains entries
    /// for the assertion's whole lifetime.
    pub fn with_client_assertion_max_age(mut self, secs: u64) -> Self {
        self.client_assertion_max_age = secs;
        self
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
        // OIDC Core §3.2.2.1 / §3.3.2.1: a nonce is REQUIRED for any response
        // type that returns an id_token from the authorization endpoint
        // (implicit and hybrid flows).
        if req.wants_id_token() && req.nonce.is_none() {
            return Err(
                OAuthError::invalid_request("nonce is required for implicit/hybrid flows")
                    .with_state(req.state.clone()),
            );
        }
        if client.token_endpoint_auth_method == AUTH_NONE && req.wants_code() {
            match (
                req.code_challenge.as_deref(),
                req.code_challenge_method.as_deref(),
            ) {
                (Some(challenge), Some("S256")) if !challenge.is_empty() => {}
                _ => {
                    return Err(
                        OAuthError::invalid_request("public clients must use S256 PKCE")
                            .with_state(req.state.clone()),
                    );
                }
            }
        }
        // The requested scope must not exceed the client's registered scope set
        // (mirrors the client_credentials intersection at the token endpoint).
        let allowed: Vec<&str> = client
            .scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if req.scopes().iter().any(|s| !allowed.contains(s)) {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidScope,
                "requested scope exceeds the client's registered scope",
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

        // The client must be registered for the authorization_code grant
        // (mirrors the client_credentials / refresh_token grant gates).
        if !client.grant_types.iter().any(|g| g == "authorization_code") {
            return Err(OAuthError::invalid_grant(
                "authorization_code grant not allowed for client",
            ));
        }

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

        // RFC 6749 §4.1.3: when the authorization request carried a
        // redirect_uri, the token request MUST echo it and it MUST match.
        if !payload.redirect_uri.is_empty() {
            match form.get("redirect_uri") {
                Some(redirect_uri) if redirect_uri == &payload.redirect_uri => {}
                _ => return Err(OAuthError::invalid_grant("redirect_uri mismatch")),
            }
        }

        if client.token_endpoint_auth_method == AUTH_NONE {
            match (
                payload.code_challenge.as_deref(),
                payload.code_challenge_method.as_deref(),
            ) {
                (Some(challenge), Some("S256")) if !challenge.is_empty() => {}
                _ => {
                    return Err(OAuthError::invalid_grant(
                        "public client code was issued without S256 PKCE",
                    ));
                }
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

        self.consume_token_once("code", code, payload.exp, "authorization code already used")
            .await?;

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
        self.consume_token_once("refresh", token, rt.exp, "refresh token already used")
            .await?;

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

    async fn consume_token_once(
        &self,
        kind: &str,
        token: &str,
        exp: u64,
        replay_message: &str,
    ) -> Result<(), OAuthError> {
        let ttl = exp.saturating_sub(now_secs()).max(1);
        let hash = token_use_hash(kind, token);
        match self.token_use_store.consume(&hash, ttl).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(OAuthError::invalid_grant(replay_message)),
            Err(e) => {
                // The store error may carry infrastructure details (Redis
                // addresses, connection failures); log it, but hand the client
                // only a generic error_description.
                tracing::error!(kind, error = %e, "token-use store failure");
                Err(OAuthError::new(
                    OAuthErrorCode::ServerError,
                    "temporarily unable to process the request",
                ))
            }
        }
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
                return self
                    .check_secret(&id, &secret, AUTH_CLIENT_SECRET_BASIC)
                    .await;
            }
        }

        // client_secret_post.
        if let (Some(id), Some(secret)) = (form.get("client_id"), form.get("client_secret")) {
            return self.check_secret(id, secret, AUTH_CLIENT_SECRET_POST).await;
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

    async fn check_secret(
        &self,
        client_id: &str,
        secret: &str,
        presented_method: &str,
    ) -> Result<Client, OAuthError> {
        let client = self
            .clients
            .get(client_id)
            .await
            .ok_or_else(|| OAuthError::invalid_client("unknown client"))?;
        // The presented authentication method must be the one the client
        // registered (OIDC Registration §2, token_endpoint_auth_method).
        if client.token_endpoint_auth_method != presented_method {
            return Err(OAuthError::invalid_client(
                "client authentication method does not match the registered method",
            ));
        }
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
        // signature valid. exp is required and the assertion may be at most
        // client_assertion_max_age seconds old, bounding the replay window.
        let validation = Validation::new()
            .with_issuer(&client_id)
            .with_subject(&client_id)
            .require_exp()
            .with_max_age(self.client_assertion_max_age);
        let claims = jwt::verify_with_jwks(jwks, assertion, &validation).map_err(|e| {
            // The jose-rs detail can carry internals; keep it for the logs and
            // hand the client only a generic description.
            tracing::debug!(error = %e, "client_assertion validation failed");
            OAuthError::invalid_client("client_assertion validation failed")
        })?;

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

        // Replay protection: the assertion's jti is single-use until its exp,
        // so a captured assertion cannot be replayed within its lifetime.
        let jti = claims
            .jti
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_client("client_assertion missing jti"))?;
        let key = format!("assertion:{client_id}:{jti}");
        let ttl = claims
            .exp
            .map(|exp| exp.saturating_sub(now_secs()))
            .unwrap_or(1)
            .max(1);
        match self.token_use_store.consume(&key, ttl).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(OAuthError::invalid_client("client_assertion already used"));
            }
            Err(e) => {
                // As in consume_token_once: store errors may carry
                // infrastructure details; log them, return a generic error.
                tracing::error!(error = %e, "token-use store failure");
                return Err(OAuthError::new(
                    OAuthErrorCode::ServerError,
                    "temporarily unable to process the request",
                ));
            }
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

fn token_use_hash(kind: &str, token: &str) -> String {
    format!(
        "{}:{}",
        kind,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(token.as_bytes()))
    )
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
                // Standard OIDC claims with a non-string JSON type are coerced
                // (e.g. `email_verified` → `true`, not `"true"`); everything
                // else stays a string.
                coerce_standard_claim(k, &v[0])
                    .unwrap_or_else(|| serde_json::Value::String(v[0].clone()))
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

/// Coerce the standard OIDC claims whose JSON type is not a string (OIDC Core
/// §5.1) from their released string form to the spec type: the `*_verified`
/// flags are booleans and `updated_at` is a number (seconds since epoch).
/// Returns `None` for any other claim, or when the value cannot be parsed as
/// the expected type (the caller then keeps it as a string rather than dropping
/// or fabricating data).
fn coerce_standard_claim(name: &str, value: &str) -> Option<serde_json::Value> {
    match name {
        "email_verified" | "phone_number_verified" => {
            match value.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Some(serde_json::Value::Bool(true)),
                "false" | "0" | "no" | "off" => Some(serde_json::Value::Bool(false)),
                _ => None,
            }
        }
        "updated_at" => value
            .trim()
            .parse::<i64>()
            .ok()
            .map(|n| serde_json::json!(n)),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "redis")]
    fn redis_set_cmd(key: &str, ttl_secs: u64) -> redis::Cmd {
        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg("1").arg("EX").arg(ttl_secs).arg("NX");
        cmd
    }

    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn redis_store_consumes_token_once() {
        let mut conn = redis_test::MockRedisConnection::new([redis_test::MockCmd::new(
            redis_set_cmd("grindvakt:token-use:code:abc", 42),
            Ok(redis::Value::Okay),
        )])
        .assert_all_commands_consumed();

        assert!(
            redis_consume_token_once(&mut conn, "grindvakt:token-use:code:abc", 42)
                .await
                .unwrap()
        );
    }

    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn redis_store_reports_existing_token_as_replay() {
        let mut conn = redis_test::MockRedisConnection::new([redis_test::MockCmd::new(
            redis_set_cmd("grindvakt:token-use:refresh:abc", 120),
            Ok(redis::Value::Nil),
        )])
        .assert_all_commands_consumed();

        assert!(
            !redis_consume_token_once(&mut conn, "grindvakt:token-use:refresh:abc", 120)
                .await
                .unwrap()
        );
    }

    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn redis_store_clamps_zero_ttl() {
        let mut conn = redis_test::MockRedisConnection::new([redis_test::MockCmd::new(
            redis_set_cmd("grindvakt:token-use:code:abc", 1),
            Ok(redis::Value::Okay),
        )])
        .assert_all_commands_consumed();

        assert!(
            redis_consume_token_once(&mut conn, "grindvakt:token-use:code:abc", 0)
                .await
                .unwrap()
        );
    }

    #[test]
    fn standard_boolean_and_number_claims_are_typed() {
        let mut external: BTreeMap<String, Vec<String>> = BTreeMap::new();
        external.insert("email".into(), vec!["a@example.com".into()]);
        external.insert("email_verified".into(), vec!["true".into()]);
        external.insert("phone_number_verified".into(), vec!["false".into()]);
        external.insert("updated_at".into(), vec!["1700000000".into()]);

        let flat = flatten_claims(&external);
        // email_verified is a real JSON boolean, not the string "true".
        assert_eq!(flat["email_verified"], serde_json::Value::Bool(true));
        assert_eq!(
            flat["phone_number_verified"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(flat["updated_at"], serde_json::json!(1700000000));
        // Ordinary claims stay strings.
        assert_eq!(
            flat["email"],
            serde_json::Value::String("a@example.com".into())
        );
    }

    #[test]
    fn unparseable_typed_claim_falls_back_to_string() {
        let mut external: BTreeMap<String, Vec<String>> = BTreeMap::new();
        external.insert("email_verified".into(), vec!["maybe".into()]);
        let flat = flatten_claims(&external);
        assert_eq!(
            flat["email_verified"],
            serde_json::Value::String("maybe".into())
        );
    }
}
