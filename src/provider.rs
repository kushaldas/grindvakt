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
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Claims, Validation};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
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
/// Construct with [`Provider::new`] and an explicitly selected token-use
/// store. [`Provider::with_token_use_store`] can replace that policy without
/// exposing the store as a mutable public field.
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
/// shared implementation; [`InMemoryTokenUseStore`] protects only a single
/// process and must be selected explicitly.
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
    /// Construct an OP with an explicitly selected one-time-use store.
    ///
    /// Passing [`InMemoryTokenUseStore`] is appropriate only when a single
    /// process handles every token request. Multi-worker deployments must use
    /// a shared atomic implementation so codes, refresh tokens, and client
    /// assertion identifiers cannot be replayed against another worker.
    pub fn new(
        mut metadata: ProviderMetadata,
        signing_key: SigningKey,
        clients: Arc<dyn ClientStore>,
        codec: TokenCodec,
        lifetimes: TokenLifetimes,
        token_use_store: Arc<dyn TokenUseStore>,
    ) -> Self {
        let supports_token_hash = supports_oidc_token_hash(signing_key.alg());
        metadata.id_token_signing_alg_values_supported = vec![signing_key.alg().to_string()];
        metadata.response_types_supported =
            vec!["code".into(), "id_token".into(), "code token".into()];
        if supports_token_hash {
            metadata.response_types_supported.extend([
                "id_token token".into(),
                "code id_token".into(),
                "code id_token token".into(),
            ]);
        }
        metadata.response_modes_supported = vec!["query".into(), "fragment".into()];
        metadata.grant_types_supported = vec![
            "authorization_code".into(),
            "client_credentials".into(),
            "refresh_token".into(),
        ];
        metadata.subject_types_supported = vec!["public".into()];
        metadata.token_endpoint_auth_methods_supported = vec![
            AUTH_CLIENT_SECRET_BASIC.into(),
            AUTH_CLIENT_SECRET_POST.into(),
            AUTH_PRIVATE_KEY_JWT.into(),
            AUTH_NONE.into(),
        ];
        metadata.code_challenge_methods_supported = vec!["S256".into()];
        metadata.claims_parameter_supported = false;
        metadata.request_parameter_supported = false;
        Self {
            metadata,
            signing_key,
            clients,
            codec,
            lifetimes,
            token_use_store,
            client_assertion_max_age: DEFAULT_CLIENT_ASSERTION_MAX_AGE,
        }
    }

    /// Replace the explicitly selected token-use store.
    pub fn with_token_use_store(mut self, store: Arc<dyn TokenUseStore>) -> Self {
        self.token_use_store = store;
        self
    }

    /// Override the maximum accepted age of `private_key_jwt` client
    /// assertions (measured from `iat`; `exp` and a single-use `jti` are
    /// always required). The default of 300 seconds follows the OAuth
    /// Security BCP; widen it only for clients that cannot mint fresh
    /// assertions per token request — a wider window extends how long a
    /// captured assertion stays usable, and the `jti` store retains each
    /// entry for the whole acceptance window (max age plus validation
    /// leeway).
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
        // Exact registration matching is necessary but not sufficient: a
        // malformed value can itself have been registered. Parse it before it
        // can reach a Location header, while retaining absolute custom-scheme
        // redirect URIs used by native applications.
        if req
            .redirect_uri
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(OAuthError::invalid_request(
                "redirect_uri must not contain whitespace or control characters",
            ));
        }
        let redirect_uri = url::Url::parse(&req.redirect_uri)
            .map_err(|_| OAuthError::invalid_request("redirect_uri must be an absolute URI"))?;
        if redirect_uri.fragment().is_some() {
            return Err(OAuthError::invalid_request(
                "redirect_uri must not contain a fragment",
            ));
        }
        if client.subject_type != "public" {
            return Err(OAuthError::new(
                OAuthErrorCode::UnauthorizedClient,
                "only public subject identifiers are implemented",
            )
            .with_state(req.state.clone()));
        }
        req.validate_response_type()?;
        req.validate_prompt()?;
        req.validate_response_mode()?;
        if req.wants_id_token()
            && (req.wants_code() || req.wants_access_token())
            && !supports_oidc_token_hash(self.signing_key.alg())
        {
            return Err(OAuthError::new(
                OAuthErrorCode::UnsupportedResponseType,
                "the configured signing algorithm does not define OIDC c_hash/at_hash",
            )
            .with_state(req.state.clone()));
        }
        if !client.allows_response_type(&req.response_type) {
            return Err(OAuthError::new(
                OAuthErrorCode::UnauthorizedClient,
                "response_type not allowed for client",
            )
            .with_state(req.state.clone()));
        }
        // OIDC Core sections 3.2.2.1 and 3.3.2.1 require a nonce when an ID
        // token is returned from the authorization endpoint. In particular,
        // nonce remains optional for the `code token` hybrid response type.
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
                (Some(challenge), Some("S256")) if pkce::is_valid_s256_challenge(challenge) => {}
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
        // A client registered without a `scope` is unrestricted here: `None`
        // means "not configured", not "empty set" — treating it as empty would
        // reject every OIDC request (scope=openid) from such a client.
        if let Some(registered) = client.scope.as_deref() {
            let allowed: Vec<&str> = registered.split_whitespace().collect();
            if req.scopes().iter().any(|s| !allowed.contains(s)) {
                return Err(OAuthError::new(
                    OAuthErrorCode::InvalidScope,
                    "requested scope exceeds the client's registered scope",
                )
                .with_state(req.state.clone()));
            }
        }
        Ok(client)
    }

    /// Build the authorization response (a redirect carrying `code` and/or
    /// `id_token`) after the user has authenticated and claims were released.
    pub async fn authorization_redirect(
        &self,
        req: &AuthorizationRequest,
        sub: &str,
        external_claims: &BTreeMap<String, Vec<String>>,
        acr: Option<String>,
    ) -> Result<crate::http::Response, OAuthError> {
        self.authorization_redirect_with_claims(req, sub, external_claims, acr, &BTreeMap::new())
            .await
    }

    /// Like [`Self::authorization_redirect`], but also emits `extra_claims`:
    /// typed id_token/userinfo claims the OP asserts on its own authority rather
    /// than deriving from released user attributes — for example, which upstream
    /// authority authenticated the user.
    ///
    /// Unlike `external_claims` (which [`flatten_claims`] renders, collapsing a
    /// single value to a scalar), `extra_claims` keep their JSON type verbatim,
    /// so an array stays an array even with one element. They overwrite any
    /// released claim of the same name — the OP-asserted value wins over anything
    /// an attribute map produced — and reserved registered claims (`iss`, `sub`,
    /// …) are ignored, exactly as released claims are in [`Self::build_id_token`].
    /// The values are sealed into the authorization code, so they survive the
    /// code and refresh-token exchanges unchanged rather than being recomputed.
    pub async fn authorization_redirect_with_claims(
        &self,
        req: &AuthorizationRequest,
        sub: &str,
        external_claims: &BTreeMap<String, Vec<String>>,
        acr: Option<String>,
        extra_claims: &BTreeMap<String, serde_json::Value>,
    ) -> Result<crate::http::Response, OAuthError> {
        // Revalidate at the minting boundary. AuthorizationRequest is
        // serializable so applications can carry it across a login step; a
        // caller must not be able to deserialize an unvalidated request and
        // mint artifacts from it.
        self.validate_authorization_request(req).await?;
        if sub.is_empty() {
            return Err(OAuthError::new(
                OAuthErrorCode::ServerError,
                "subject identifier must not be empty",
            ));
        }

        let mut claims = filter_claims(&req.scope, flatten_claims(external_claims));
        for (k, v) in extra_claims {
            if is_reserved_id_token_claim(k) {
                continue;
            }
            if claim_allowed_by_scope(&req.scope, k) {
                claims.insert(k.clone(), v.clone());
            }
        }
        let auth_time = now_secs();
        let mut out: Vec<(String, String)> = Vec::new();

        let access_token = if req.wants_access_token() {
            let payload = AccessTokenPayload {
                client_id: req.client_id.clone(),
                sub: sub.to_string(),
                scope: req.scope.clone(),
                claims: claims.clone(),
                exp: auth_time + self.lifetimes.access_token_ttl,
                cnf_jkt: None,
            };
            Some(
                self.codec
                    .seal_access_token(&payload)
                    .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?,
            )
        } else {
            None
        };

        let code = if req.wants_code() {
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
            Some(code)
        } else {
            None
        };

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
                    code.as_deref(),
                    access_token.as_deref(),
                )
                .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;
            out.push(("id_token".to_string(), id_token));
        }

        if let Some(code) = code {
            out.push(("code".to_string(), code));
        }
        if let Some(access_token) = access_token {
            out.push(("access_token".to_string(), access_token));
            out.push(("token_type".to_string(), "Bearer".to_string()));
            out.push((
                "expires_in".to_string(),
                self.lifetimes.access_token_ttl.to_string(),
            ));
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

    /// Handle an ordered token request and reject duplicate parameters before
    /// converting it to the single-valued representation used internally.
    pub async fn handle_token_request_pairs(
        &self,
        form: &[(String, String)],
        auth_header: Option<&str>,
        token_url: &str,
        dpop: Option<&crate::dpop::DpopProof>,
    ) -> Result<TokenResponse, OAuthError> {
        let form = unique_parameters(form)?;
        self.handle_token_request(&form, auth_header, token_url, dpop)
            .await
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

        // Mint an access token, and an ID token only for an OIDC grant.
        let access_payload = AccessTokenPayload {
            client_id: client.client_id.clone(),
            sub: payload.sub.clone(),
            scope: payload.scope.clone(),
            claims: payload.claims.clone(),
            exp: now_secs() + self.lifetimes.access_token_ttl,
            cnf_jkt: dpop.map(|d| d.jkt().to_string()),
        };
        let access_token = self
            .codec
            .seal_access_token(&access_payload)
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        let id_token = if payload.scope.split_whitespace().any(|s| s == "openid") {
            Some(
                self.build_id_token(
                    &client.client_id,
                    &payload.sub,
                    payload.nonce.as_deref(),
                    &payload.claims,
                    payload.acr.as_deref(),
                    payload.auth_time,
                    None,
                    supports_oidc_token_hash(self.signing_key.alg())
                        .then_some(access_token.as_str()),
                )
                .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?,
            )
        } else {
            None
        };

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
                cnf_jkt: dpop.map(|d| d.jkt().to_string()),
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
            id_token,
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
        // `openid` turns an authorization request into an OIDC authentication
        // request. A client-credentials grant has no end user and therefore
        // cannot legitimately grant that scope or expose UserInfo.
        if granted.iter().any(|scope| scope == "openid") {
            return Err(OAuthError::new(
                OAuthErrorCode::InvalidScope,
                "openid scope requires end-user authorization",
            ));
        }
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
            cnf_jkt: dpop.map(|d| d.jkt().to_string()),
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
    /// fresh access token and, for an OIDC grant, an ID token, optionally
    /// narrowing scope. The refresh
    /// token is a stateless sealed [`RefreshTokenPayload`], but every use is
    /// consumed through the configured [`TokenUseStore`] before a rotated token
    /// is returned. DPoP binding applies to the new access token when a proof is
    /// presented.
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
                Some(proof) if proof.jkt() == bound_jkt => Some(bound_jkt.to_string()),
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
            None => dpop.map(|proof| proof.jkt().to_string()),
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

        // A narrowed refresh grant must not retain standard claims belonging
        // to scopes the client removed. Reuse this one filtered map for every
        // artifact minted by the refresh so their authorization agrees.
        let claims = filter_claims(&scope, rt.claims.clone());

        let access_payload = AccessTokenPayload {
            client_id: client.client_id.clone(),
            sub: rt.sub.clone(),
            scope: scope.clone(),
            claims: claims.clone(),
            exp: now + self.lifetimes.access_token_ttl,
            cnf_jkt: cnf_jkt.clone(),
        };
        let access_token = self
            .codec
            .seal_access_token(&access_payload)
            .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?;

        let id_token = if scope.split_whitespace().any(|s| s == "openid") {
            Some(
                self.build_id_token(
                    &client.client_id,
                    &rt.sub,
                    rt.nonce.as_deref(),
                    &claims,
                    rt.acr.as_deref(),
                    rt.auth_time,
                    None,
                    supports_oidc_token_hash(self.signing_key.alg())
                        .then_some(access_token.as_str()),
                )
                .map_err(|e| OAuthError::new(OAuthErrorCode::ServerError, e.to_string()))?,
            )
        } else {
            None
        };

        // Rotate the refresh token (sliding expiry), carrying the narrowed scope.
        let new_refresh = RefreshTokenPayload {
            client_id: client.client_id.clone(),
            sub: rt.sub.clone(),
            scope: scope.clone(),
            nonce: rt.nonce.clone(),
            claims,
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
            id_token,
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

        if !payload
            .scope
            .split_whitespace()
            .any(|scope| scope == "openid")
        {
            return Err(OAuthError::new(
                OAuthErrorCode::AccessDenied,
                "userinfo requires an access token with openid scope",
            ));
        }

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

    /// Authenticate an ordered form while rejecting duplicate credentials and
    /// protocol parameters before client-authentication precedence is applied.
    pub async fn authenticate_client_pairs(
        &self,
        form: &[(String, String)],
        auth_header: Option<&str>,
        token_url: &str,
    ) -> Result<Client, OAuthError> {
        let form = unique_parameters(form)?;
        self.authenticate_client(&form, auth_header, token_url)
            .await
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
        // `with_max_age` already implies `require_iat` in jose-rs; state it
        // explicitly so the freshness bound never silently depends on that
        // implicit coupling.
        let validation = Validation::new()
            .with_issuer(&client_id)
            .with_subject(&client_id)
            .require_exp()
            .require_iat()
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

        // Replay protection: the assertion's jti is single-use, so a captured
        // assertion cannot be replayed within its acceptance window. The store
        // TTL is capped at max_age + leeway: past that point the max-age check
        // above rejects the assertion regardless of its exp, so holding the
        // jti until a (client-chosen, unbounded) exp would only let a hostile
        // client grow the store with arbitrarily long-lived entries.
        let jti = claims
            .jti
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_client("client_assertion missing jti"))?;
        let key = assertion_use_hash(&client_id, jti);
        let ttl = claims
            .exp
            .map(|exp| exp.saturating_sub(now_secs()))
            .unwrap_or(1)
            .min(
                self.client_assertion_max_age
                    .saturating_add(validation.leeway),
            )
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

    // Keep each protocol-bound value explicit at the call sites; grouping them
    // into a loosely typed map would make omission and claim confusion easier.
    #[allow(clippy::too_many_arguments)]
    fn build_id_token(
        &self,
        client_id: &str,
        sub: &str,
        nonce: Option<&str>,
        claims: &BTreeMap<String, serde_json::Value>,
        acr: Option<&str>,
        auth_time: u64,
        code: Option<&str>,
        access_token: Option<&str>,
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
        if let Some(code) = code {
            c.extra.insert(
                "c_hash".into(),
                serde_json::Value::String(oidc_token_hash(self.signing_key.alg(), code)?),
            );
        }
        if let Some(access_token) = access_token {
            c.extra.insert(
                "at_hash".into(),
                serde_json::Value::String(oidc_token_hash(self.signing_key.alg(), access_token)?),
            );
        }
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

fn unique_parameters(params: &[(String, String)]) -> Result<BTreeMap<String, String>, OAuthError> {
    let mut unique = BTreeMap::new();
    for (name, value) in params {
        if unique.insert(name.clone(), value.clone()).is_some() {
            return Err(OAuthError::invalid_request(format!(
                "duplicate token parameter: {name}"
            )));
        }
    }
    Ok(unique)
}

fn oidc_token_hash(alg: JwsAlgorithm, value: &str) -> crate::error::Result<String> {
    let digest = match alg {
        JwsAlgorithm::RS256
        | JwsAlgorithm::PS256
        | JwsAlgorithm::ES256
        | JwsAlgorithm::ES256K
        | JwsAlgorithm::HS256 => Sha256::digest(value.as_bytes()).to_vec(),
        JwsAlgorithm::RS384 | JwsAlgorithm::PS384 | JwsAlgorithm::ES384 | JwsAlgorithm::HS384 => {
            Sha384::digest(value.as_bytes()).to_vec()
        }
        JwsAlgorithm::RS512 | JwsAlgorithm::PS512 | JwsAlgorithm::ES512 | JwsAlgorithm::HS512 => {
            Sha512::digest(value.as_bytes()).to_vec()
        }
        _ => {
            return Err(crate::error::Error::Crypto(format!(
                "{} does not define an OIDC token-hash function",
                alg
            )))
        }
    };
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2]))
}

/// Whether OIDC Core defines the hash primitive needed for `c_hash` and
/// `at_hash` from the JWS `alg` name alone. In particular, legacy `EdDSA`
/// does not identify its curve/hash, so hash-bearing front-channel response
/// types are not advertised for it.
fn supports_oidc_token_hash(alg: JwsAlgorithm) -> bool {
    matches!(
        alg,
        JwsAlgorithm::RS256
            | JwsAlgorithm::PS256
            | JwsAlgorithm::ES256
            | JwsAlgorithm::ES256K
            | JwsAlgorithm::HS256
            | JwsAlgorithm::RS384
            | JwsAlgorithm::PS384
            | JwsAlgorithm::ES384
            | JwsAlgorithm::HS384
            | JwsAlgorithm::RS512
            | JwsAlgorithm::PS512
            | JwsAlgorithm::ES512
            | JwsAlgorithm::HS512
    )
}

fn token_use_hash(kind: &str, token: &str) -> String {
    format!(
        "{}:{}",
        kind,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(token.as_bytes()))
    )
}

/// Store key for a single-use client-assertion `jti`, scoped to the client.
/// Both parts are length-prefixed before hashing so no `(client_id, jti)`
/// pair can collide with another — client_ids are often URLs containing `:`,
/// so plain concatenation would be ambiguous — and an arbitrary-length,
/// client-chosen `jti` never reaches the store key verbatim.
fn assertion_use_hash(client_id: &str, jti: &str) -> String {
    token_use_hash(
        "assertion",
        &format!("{}:{client_id}:{}:{jti}", client_id.len(), jti.len()),
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
        "iss"
            | "sub"
            | "aud"
            | "exp"
            | "iat"
            | "nbf"
            | "jti"
            | "nonce"
            | "auth_time"
            | "acr"
            | "azp"
            | "at_hash"
            | "c_hash"
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

/// Release standard UserInfo claims only when their defining scope was
/// granted. Custom claims remain application-defined and are retained.
fn filter_claims(
    scope: &str,
    claims: BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    claims
        .into_iter()
        .filter(|(name, _)| claim_allowed_by_scope(scope, name))
        .collect()
}

fn claim_allowed_by_scope(scope: &str, name: &str) -> bool {
    let required_scope = match name {
        "name" | "family_name" | "given_name" | "middle_name" | "nickname"
        | "preferred_username" | "profile" | "picture" | "website" | "gender" | "birthdate"
        | "zoneinfo" | "locale" | "updated_at" => Some("profile"),
        "email" | "email_verified" => Some("email"),
        "address" => Some("address"),
        "phone_number" | "phone_number_verified" => Some("phone"),
        _ => None,
    };
    required_scope.is_none_or(|required| scope.split_whitespace().any(|s| s == required))
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

    #[test]
    fn metadata_does_not_advertise_hash_bearing_flows_for_ambiguous_algorithms() {
        let mut jwk = jose_rs::jwk::generate_ed25519().unwrap();
        jwk.alg = Some("EdDSA".into());
        let key = crate::keys::signing_key_from_jwk_json(
            &jwk.to_json().unwrap(),
            Some("EdDSA"),
            Some("ed-key"),
        )
        .unwrap();
        let provider = Provider::new(
            ProviderMetadata::new("https://op.example.com", "https://op.example.com"),
            key,
            Arc::new(crate::client::InMemoryClientStore::new()),
            TokenCodec::new("secret"),
            TokenLifetimes::default(),
            Arc::new(InMemoryTokenUseStore::new()),
        );

        assert!(provider
            .metadata
            .response_types_supported
            .contains(&"id_token".to_string()));
        assert!(!provider
            .metadata
            .response_types_supported
            .contains(&"code id_token".to_string()));
    }

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

    /// The assertion-jti store key must be collision-free across clients:
    /// client_ids are often URLs containing `:`, so plain concatenation of
    /// `client_id` and `jti` would let two different pairs share a key.
    #[test]
    fn assertion_use_hash_is_collision_free_and_carries_no_raw_jti() {
        // Under plain `assertion:{client_id}:{jti}` both pairs would map to
        // "assertion:https://rp.example.com:8080:x".
        let a = assertion_use_hash("https://rp.example.com", "8080:x");
        let b = assertion_use_hash("https://rp.example.com:8080", "x");
        assert_ne!(a, b, "distinct (client_id, jti) pairs must not collide");

        // Deterministic per pair, and the raw jti never appears in the key.
        let long_jti = "j".repeat(4096);
        let k1 = assertion_use_hash("https://rp.example.com", &long_jti);
        let k2 = assertion_use_hash("https://rp.example.com", &long_jti);
        assert_eq!(k1, k2);
        assert!(!k1.contains(&long_jti));
        assert!(k1.len() < 100, "store key length must be bounded");
    }

    /// A recording [`TokenUseStore`] capturing every consume call.
    #[derive(Default)]
    struct RecordingStore {
        seen: std::sync::Mutex<Vec<(String, u64)>>,
    }

    #[async_trait::async_trait]
    impl TokenUseStore for RecordingStore {
        async fn consume(
            &self,
            token_hash: &str,
            ttl_secs: u64,
        ) -> std::result::Result<bool, String> {
            self.seen
                .lock()
                .unwrap()
                .push((token_hash.to_string(), ttl_secs));
            Ok(true)
        }
    }

    /// The jti replay entry must not live until a client-chosen (unbounded)
    /// `exp`: past `iat + max_age + leeway` the max-age check rejects the
    /// assertion anyway, so the store TTL is capped at that window. Otherwise
    /// a hostile client could grow the store with decade-lived entries.
    #[tokio::test]
    async fn client_assertion_jti_ttl_is_capped_at_the_acceptance_window() {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let key = crate::keys::signing_key_from_jwk_json(
            &jwk.to_json().unwrap(),
            Some("ES256"),
            Some("rp-key"),
        )
        .unwrap();

        let client = Client {
            client_id: "rp-pkj".into(),
            client_secret: None,
            redirect_uris: vec![],
            response_types: vec![],
            grant_types: vec!["client_credentials".into()],
            token_endpoint_auth_method: AUTH_PRIVATE_KEY_JWT.into(),
            jwks: Some(key.to_public_jwks()),
            scope: Some("read".into()),
            subject_type: "public".into(),
            client_name: None,
        };
        let store = Arc::new(RecordingStore::default());
        let op = Provider::new(
            ProviderMetadata::new("https://op.example.com", "https://op.example.com"),
            crate::keys::signing_key_from_jwk_json(
                &{
                    let mut k = jose_rs::jwk::generate_ec("P-256").unwrap();
                    k.alg = Some("ES256".into());
                    k
                }
                .to_json()
                .unwrap(),
                Some("ES256"),
                Some("op-key"),
            )
            .unwrap(),
            Arc::new(crate::client::InMemoryClientStore::with_clients(vec![
                client,
            ])),
            TokenCodec::new("op-secret"),
            TokenLifetimes::default(),
            store.clone(),
        );

        // Fresh assertion, but exp a decade out.
        let now = now_secs();
        let token_url = "https://op.example.com/token";
        let claims = Claims {
            iss: Some("rp-pkj".into()),
            sub: Some("rp-pkj".into()),
            aud: Some(jose_rs::jwt::Audience::Single(token_url.into())),
            iat: Some(now),
            exp: Some(now + 10 * 365 * 24 * 3600),
            jti: Some("far-future-jti".into()),
            ..Default::default()
        };
        let mut header = jose_rs::JoseHeader::for_alg(key.alg());
        header.kid = key.kid().map(str::to_string);
        let assertion = jose_rs::jwt::encode(key.signer(), &header, &claims).unwrap();

        let form: BTreeMap<String, String> = [
            (
                "client_assertion_type".to_string(),
                CLIENT_ASSERTION_TYPE.to_string(),
            ),
            ("client_assertion".to_string(), assertion),
        ]
        .into();
        op.authenticate_client(&form, None, token_url)
            .await
            .expect("assertion authenticates");

        let seen = store.seen.lock().unwrap();
        let (hash, ttl) = seen.first().expect("consume was called");
        assert!(hash.starts_with("assertion:"));
        assert!(!hash.contains("far-future-jti"), "raw jti must be hashed");
        assert!(
            *ttl <= DEFAULT_CLIENT_ASSERTION_MAX_AGE + Validation::new().leeway,
            "jti TTL ({ttl}) must be capped at max_age + leeway, not run to exp"
        );
    }
}
