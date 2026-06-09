//! OIDC client (relying party) model and storage.

use jose_rs::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use crate::util::now_secs;

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
    /// Keys for `private_key_jwt` client auth and request-object verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JwkSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default = "default_subject_type")]
    pub subject_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
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
    /// Whether `uri` exactly matches a registered redirect URI.
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    /// Whether the client is allowed the given response type.
    pub fn allows_response_type(&self, rt: &str) -> bool {
        self.response_types.iter().any(|r| r == rt)
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
        let g = self.inner.read().ok()?;
        let entry = g.get(client_id)?;
        if let Some(exp) = entry.expires_at {
            if exp <= now_secs() {
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
            g.insert(
                client.client_id.clone(),
                Entry {
                    client,
                    expires_at: Some(now_secs() + ttl),
                },
            );
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
            client_name: None,
        };
        store.put(client.clone()).await;
        assert!(store.get("c1").await.is_some());
        assert!(store.get("nope").await.is_none());

        store.put_with_ttl(client, 0).await;
        assert!(store.get("c1").await.is_none(), "ttl=0 should expire");
    }
}
