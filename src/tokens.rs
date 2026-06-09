//! Stateless authorization codes and access tokens.
//!
//! Both are confidential, self-contained tokens: a JSON payload encrypted as a
//! JWE compact token (`dir` + `A256GCM`) under a 256-bit key derived from the
//! OP's secret. Because they carry their own state (and expiry), neither the
//! token endpoint nor the userinfo endpoint needs a server-side lookup — the
//! whole OP is horizontally scalable with no shared store.

use hkdf::Hkdf;
use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::JweDecryptOptions;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use crate::error::{Error, Result};
use crate::util::now_secs;

/// HKDF salt and info for token-key derivation. Domain-separated from the state
/// cookie key (different salt/info) so the same configured secret yields an
/// independent key for codes/access tokens.
const HKDF_SALT: &[u8] = b"tunnelbana-oidc-token-v1";
const HKDF_INFO: &[u8] = b"tunnelbana oidc token seal: dir+A256GCM";

/// Derive a 256-bit AEAD key from the OP secret via HKDF-SHA256.
fn derive_key(secret: &str) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length");
    okm.to_vec()
}

/// The payload sealed inside an authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodePayload {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    /// Released user claims (internal->external already applied).
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
    pub auth_time: u64,
    pub exp: u64,
    /// Authentication context class reference, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

/// The payload sealed inside an access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenPayload {
    pub client_id: String,
    pub sub: String,
    pub scope: String,
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
    pub exp: u64,
    /// DPoP confirmation thumbprint (RFC 9449 `cnf.jkt`). Present when the token
    /// is sender-constrained; sealed into the token so userinfo/introspection
    /// can read it back without a server lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf_jkt: Option<String>,
}

/// Seals/opens authorization codes and access tokens.
#[derive(Clone)]
pub struct TokenCodec {
    /// AEAD keys derived from the OP secret(s). `keys[0]` is the primary, used
    /// for sealing; every key is tried on open so tokens sealed under a previous
    /// secret keep validating during key rotation.
    keys: Vec<Vec<u8>>,
}

impl TokenCodec {
    /// Derive the codec key from the OP secret via HKDF-SHA256 (domain-separated
    /// from the state cookie key).
    pub fn new(secret: &str) -> Self {
        Self {
            keys: vec![derive_key(secret)],
        }
    }

    /// Register additional, decryption-only secrets (previous keys retained so
    /// tokens sealed before a rotation keep opening). Never used for sealing.
    pub fn with_previous_secrets(mut self, secrets: &[String]) -> Self {
        for s in secrets {
            if !s.is_empty() {
                self.keys.push(derive_key(s));
            }
        }
        self
    }

    fn seal<T: Serialize>(&self, value: &T) -> Result<String> {
        let plaintext = serde_json::to_vec(value)?;
        jose_rs::jwe::encrypt(
            &self.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .map_err(|e| Error::Crypto(format!("token seal: {e}")))
    }

    fn open<T: for<'de> Deserialize<'de>>(&self, token: &str) -> Result<T> {
        // Pin the accepted algorithms — reject anything but dir + A256GCM before
        // touching key material (defence against algorithm substitution).
        let opts = JweDecryptOptions::new(
            vec![JweAlgorithm::Dir],
            vec![JweEncryption::A256GCM],
        );
        let mut last_err = None;
        for key in &self.keys {
            match jose_rs::jwe::decrypt_with_options(key, token, &opts) {
                Ok(plaintext) => return serde_json::from_slice(&plaintext).map_err(Error::from),
                Err(e) => last_err = Some(e),
            }
        }
        Err(Error::Authn(format!(
            "token open: {}",
            last_err.expect("at least one key is always present")
        )))
    }

    pub fn seal_code(&self, payload: &AuthCodePayload) -> Result<String> {
        self.seal(payload)
    }

    /// Open and expiry-check an authorization code.
    pub fn open_code(&self, token: &str) -> Result<AuthCodePayload> {
        let payload: AuthCodePayload = self.open(token)?;
        if payload.exp <= now_secs() {
            return Err(Error::Authn("authorization code expired".into()));
        }
        Ok(payload)
    }

    pub fn seal_access_token(&self, payload: &AccessTokenPayload) -> Result<String> {
        self.seal(payload)
    }

    /// Open and expiry-check an access token.
    pub fn open_access_token(&self, token: &str) -> Result<AccessTokenPayload> {
        let payload: AccessTokenPayload = self.open(token)?;
        if payload.exp <= now_secs() {
            return Err(Error::Authn("access token expired".into()));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrip_and_expiry() {
        let codec = TokenCodec::new("op-secret");
        let payload = AuthCodePayload {
            client_id: "client-1".into(),
            redirect_uri: "https://rp/cb".into(),
            scope: "openid email".into(),
            sub: "user-1".into(),
            nonce: Some("n".into()),
            code_challenge: Some("ch".into()),
            code_challenge_method: Some("S256".into()),
            claims: BTreeMap::new(),
            auth_time: now_secs(),
            exp: now_secs() + 60,
            acr: None,
        };
        let token = codec.seal_code(&payload).unwrap();
        let opened = codec.open_code(&token).unwrap();
        assert_eq!(opened.client_id, "client-1");
        assert_eq!(opened.nonce.as_deref(), Some("n"));

        // Expired.
        let mut expired = payload.clone();
        expired.exp = now_secs() - 1;
        let token = codec.seal_code(&expired).unwrap();
        assert!(codec.open_code(&token).is_err());
    }

    #[test]
    fn wrong_key_cannot_open() {
        let codec = TokenCodec::new("secret-a");
        let other = TokenCodec::new("secret-b");
        let payload = AccessTokenPayload {
            client_id: "c".into(),
            sub: "s".into(),
            scope: "openid".into(),
            claims: BTreeMap::new(),
            exp: now_secs() + 60,
            cnf_jkt: None,
        };
        let token = codec.seal_access_token(&payload).unwrap();
        assert!(other.open_access_token(&token).is_err());
    }

    #[test]
    fn key_rotation_opens_old_tokens() {
        // Seal under the old secret.
        let old = TokenCodec::new("the-old-op-secret");
        let payload = AccessTokenPayload {
            client_id: "c".into(),
            sub: "s".into(),
            scope: "openid".into(),
            claims: BTreeMap::new(),
            exp: now_secs() + 60,
            cnf_jkt: None,
        };
        let token = old.seal_access_token(&payload).unwrap();

        // New codec: primary is the new secret, old kept as a previous secret.
        let rotated = TokenCodec::new("the-new-op-secret")
            .with_previous_secrets(&["the-old-op-secret".to_string()]);
        let opened = rotated.open_access_token(&token).unwrap();
        assert_eq!(opened.sub, "s");

        // A codec without the old secret cannot open it.
        let fresh = TokenCodec::new("the-new-op-secret");
        assert!(fresh.open_access_token(&token).is_err());
    }
}
