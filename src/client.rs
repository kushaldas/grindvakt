//! OIDC client (relying party) model and storage.

use crate::util::now_secs;
use jose_rs::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Token-endpoint client authentication method.
pub const AUTH_NONE: &str = "none";
pub const AUTH_CLIENT_SECRET_BASIC: &str = "client_secret_basic";
pub const AUTH_CLIENT_SECRET_POST: &str = "client_secret_post";
pub const AUTH_PRIVATE_KEY_JWT: &str = "private_key_jwt";

/// A registered relying party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_response_types")]
    pub response_types: Vec<String>,
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    #[serde(default = "default_auth_method")]
    pub token_endpoint_auth_method: String,
    /// Public keys for client assertions, signed Request Objects and response
    /// encryption. For JWE, the provider selects a key with `use = "enc"` and
    /// a nonempty `kid` from this set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JwkSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Registered subject identifier type (`public` by default). `pairwise`
    /// requires [`crate::provider::Provider::with_caller_managed_pairwise_subjects`]
    /// and application-provided derivation through
    /// [`crate::provider::Provider::authorization_redirect_with_subject_resolver`]
    /// (or its extra-claims variant); arbitrary subject types are rejected.
    #[serde(default = "default_subject_type")]
    pub subject_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// JOSE preferences and sector metadata from the client's registration.
    /// Registrations written before 0.13 deserialize with the empty policy.
    /// Add `response_policy: Default::default()` to an existing Rust struct
    /// literal to select the same defaults.
    #[serde(default, skip_serializing_if = "ResponsePolicy::is_empty")]
    pub response_policy: ResponsePolicy,
}

/// Client metadata used for pairwise subjects, request verification and response encryption.
///
/// Populate these fields from a trusted registration. Each response type has its
/// own JWE settings. Omitting both settings leaves that response signed only.
/// ID token settings apply at authorization, code exchange and refresh.
/// UserInfo settings apply to [`crate::Provider::signed_userinfo`].
/// [`crate::Provider::userinfo`] returns JSON claims.
///
/// Register `ECDH-ES` or `RSA-OAEP-256` for key management. Legacy `RSA-OAEP`
/// also requires the `jose-rs/rsa-oaep` Cargo feature. The default content
/// encryption is `A128CBC-HS256` when only the key management algorithm is set.
/// During rollover the provider tries keys from [`Client::jwks`] in order,
/// skipping unusable recipients. The protected JWE header names the successful
/// key in `kid`. An unsupported combination, a lone `enc`, or a registration
/// with no usable encryption key causes issuance to return `server_error`.
///
/// ```
/// use grindvakt::client::ResponsePolicy;
///
/// // Encrypt ID tokens using the default enc and signed UserInfo using A256GCM.
/// let policy = ResponsePolicy {
///     id_token_encrypted_response_alg: Some("ECDH-ES".into()),
///     userinfo_encrypted_response_alg: Some("RSA-OAEP-256".into()),
///     userinfo_encrypted_response_enc: Some("A256GCM".into()),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResponsePolicy {
    /// Registered URI of the redirect-URI list used to establish a pairwise sector.
    /// The application validates this list when resolving the registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,
    /// Registered JWS algorithm for the frontend to enforce on signed authorization requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    /// JWS algorithm for `private_key_jwt`. With a pin, the provider also requires a `kid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// JWE key management algorithm for encrypting the signed ID token to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    /// ID token content encryption algorithm. Defaults to `A128CBC-HS256` when
    /// only the key management algorithm is registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,
    /// JWE key management algorithm for encrypting signed UserInfo to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,
    /// UserInfo content encryption algorithm, with the same default as for ID tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,
}

impl ResponsePolicy {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

fn default_response_types() -> Vec<String> {
    vec!["code".to_string()]
}
fn default_grant_types() -> Vec<String> {
    vec!["authorization_code".to_string()]
}
fn default_auth_method() -> String {
    AUTH_CLIENT_SECRET_BASIC.to_string()
}
fn default_subject_type() -> String {
    "public".to_string()
}

impl Client {
    /// Identify this registration snapshot by its unpadded base64url SHA-256 digest.
    ///
    /// A caller can carry the digest in protected transaction state and compare it
    /// with the current registration before issuing or redeeming a code. JSON object
    /// ordering is ignored. Array order, credentials, keys and response policy all
    /// contribute to the digest.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the registration cannot be represented in JSON.
    pub fn registration_fingerprint(&self) -> serde_json::Result<String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut registration = self.clone();
        // JWK extensions normally flatten into the key object. Hash them separately
        // so an extension with a standard field's name cannot mask a key change.
        let extensions = registration.jwks.as_mut().map(|jwks| {
            jwks.keys
                .iter_mut()
                .map(|key| std::mem::take(&mut key.extra))
                .collect::<Vec<_>>()
        });
        let mut value = serde_json::to_value((registration, extensions))?;
        value.sort_all_objects();
        Ok(URL_SAFE_NO_PAD.encode(crate::mac::sha256(&serde_json::to_vec(&value)?)))
    }

    /// Whether `uri` exactly matches a registered redirect URI.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    /// Whether the client is allowed the given response type.
    pub fn allows_response_type(&self, rt: &str) -> bool {
        self.response_types
            .iter()
            .any(|registered| crate::request::response_type_eq(registered, rt))
    }
}

/// Storage for clients. The default is in-memory; a federation frontend wraps it
/// with a TTL for auto-registered RPs.
#[async_trait::async_trait]
pub trait ClientStore: Send + Sync {
    async fn get(&self, client_id: &str) -> Option<Client>;
    async fn put(&self, client: Client);
    async fn put_with_ttl(&self, client: Client, ttl: u64) {
        // Default ignores TTL.
        let _ = ttl;
        self.put(client).await;
    }
}

struct Entry {
    client: Client,
    expires_at: Option<u64>,
}

/// In-memory client store with optional per-entry TTL (for federation).
#[derive(Default)]
pub struct InMemoryClientStore {
    inner: RwLock<HashMap<String, Entry>>,
}

impl InMemoryClientStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed static clients at startup.
    pub fn with_clients(clients: Vec<Client>) -> Self {
        let store = Self::new();
        if let Ok(mut g) = store.inner.write() {
            for c in clients {
                g.insert(
                    c.client_id.clone(),
                    Entry {
                        client: c,
                        expires_at: None,
                    },
                );
            }
        }
        store
    }
}

#[async_trait::async_trait]
impl ClientStore for InMemoryClientStore {
    async fn get(&self, client_id: &str) -> Option<Client> {
        // Write lock so an expired entry is removed on lookup, not just hidden.
        let mut g = self.inner.write().ok()?;
        let entry = g.get(client_id)?;
        if let Some(exp) = entry.expires_at {
            if exp <= now_secs() {
                g.remove(client_id);
                return None;
            }
        }
        Some(entry.client.clone())
    }

    async fn put(&self, client: Client) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(
                client.client_id.clone(),
                Entry {
                    client,
                    expires_at: None,
                },
            );
        }
    }

    async fn put_with_ttl(&self, client: Client, ttl: u64) {
        if let Ok(mut g) = self.inner.write() {
            // Opportunistically sweep expired entries so the map cannot grow
            // unboundedly with dead federation registrations.
            let now = now_secs();
            g.retain(|_, e| e.expires_at.is_none_or(|exp| exp > now));
            g.insert(
                client.client_id.clone(),
                Entry {
                    client,
                    expires_at: Some(now + ttl),
                },
            );
        }
    }
}

/// Shares expiring federation registrations across provider replicas using Redis.
///
/// [`ClientStore::put`] installs a process-local registration that takes
/// precedence on lookup. Use [`ClientStore::put_with_ttl`] for a verified
/// dynamic registration and bound its TTL in seconds by the remaining trust
/// lifetime. A zero TTL removes the shared entry immediately. Missing,
/// unreadable and expired Redis values all yield a cache miss.
#[cfg(feature = "redis")]
pub struct RedisClientStore {
    conn: redis::aio::ConnectionManager,
    prefix: String,
    local: InMemoryClientStore,
}

#[cfg(feature = "redis")]
impl RedisClientStore {
    /// Open a lazy Redis connection and seed the process-local store with `clients`.
    ///
    /// Each Redis key is `prefix` followed directly by the client ID. Replicas
    /// of one provider should share a prefix. Give independent providers distinct
    /// namespaces and include any desired separator in the prefix.
    ///
    /// # Errors
    ///
    /// Returns a Redis configuration error if the URL or connection manager is
    /// invalid. The first Redis operation establishes server reachability.
    pub fn new(url: &str, prefix: String, clients: Vec<Client>) -> redis::RedisResult<Self> {
        Ok(Self {
            conn: redis::Client::open(url)?.get_connection_manager_lazy(Default::default())?,
            prefix,
            local: InMemoryClientStore::with_clients(clients),
        })
    }
}

#[cfg(feature = "redis")]
#[async_trait::async_trait]
impl ClientStore for RedisClientStore {
    async fn get(&self, id: &str) -> Option<Client> {
        if let Some(client) = self.local.get(id).await {
            return Some(client);
        }
        let blob = redis::cmd("GET")
            .arg(format!("{}{id}", self.prefix))
            .query_async::<Option<Vec<u8>>>(&mut self.conn.clone())
            .await
            .ok()??;
        serde_json::from_slice(&blob).ok()
    }
    async fn put(&self, client: Client) {
        self.local.put(client).await;
    }
    async fn put_with_ttl(&self, client: Client, ttl: u64) {
        let key = format!("{}{}", self.prefix, client.client_id);
        if ttl == 0 {
            // Redis rejects SET with EX 0, which would leave the previous grant live.
            if redis::cmd("DEL")
                .arg(key)
                .query_async::<i64>(&mut self.conn.clone())
                .await
                .is_err()
            {
                tracing::error!("could not expire verified client registration");
            }
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(&client) {
            let result = redis::cmd("SET")
                .arg(key)
                .arg(bytes)
                .arg("EX")
                .arg(ttl)
                .query_async::<()>(&mut self.conn.clone())
                .await;
            if result.is_err() {
                tracing::error!("could not store verified client registration");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_get_put_ttl() {
        let store = InMemoryClientStore::new();
        let client = Client {
            client_id: "c1".into(),
            client_secret: Some("s".into()),
            redirect_uris: vec!["https://rp/cb".into()],
            response_types: default_response_types(),
            grant_types: default_grant_types(),
            token_endpoint_auth_method: AUTH_CLIENT_SECRET_BASIC.into(),
            jwks: None,
            scope: None,
            subject_type: "public".into(),
            response_policy: Default::default(),
            client_name: None,
        };
        store.put(client.clone()).await;
        assert!(store.get("c1").await.is_some());
        assert!(store.get("nope").await.is_none());

        store.put_with_ttl(client, 0).await;
        assert!(store.get("c1").await.is_none(), "ttl=0 should expire");
    }

    #[tokio::test]
    async fn expired_entries_are_removed() {
        let client = Client {
            client_id: "c1".into(),
            client_secret: Some("s".into()),
            redirect_uris: vec!["https://rp/cb".into()],
            response_types: default_response_types(),
            grant_types: default_grant_types(),
            token_endpoint_auth_method: AUTH_CLIENT_SECRET_BASIC.into(),
            jwks: None,
            scope: None,
            subject_type: "public".into(),
            response_policy: Default::default(),
            client_name: None,
        };
        let store = InMemoryClientStore::new();

        // get removes the expired entry, not just hides it.
        store.put_with_ttl(client.clone(), 0).await;
        assert!(store.get("c1").await.is_none());
        assert!(
            store.inner.read().unwrap().is_empty(),
            "expired entry must be removed on get"
        );

        // put_with_ttl sweeps expired entries left by other keys.
        let mut dead = client.clone();
        dead.client_id = "dead".into();
        store.put_with_ttl(dead, 0).await;
        store.put_with_ttl(client, 3600).await;
        let g = store.inner.read().unwrap();
        assert_eq!(g.len(), 1, "expired entries must be swept on put_with_ttl");
        assert!(g.contains_key("c1"));
    }
}
