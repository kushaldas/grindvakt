//! Stateless authorization codes, access tokens, and refresh tokens.
//!
//! These are confidential, self-contained tokens: each a JSON payload encrypted as a
//! JWE compact token (`dir` + `A256GCM`) under a 256-bit key derived from the
//! OP's secret. Because they carry their own state (and expiry), neither the
//! token endpoint nor the userinfo endpoint needs a server-side lookup — the
//! whole OP is horizontally scalable with no shared store.

use crate::error::{Error, Result};
use crate::util::now_secs;
use hkdf::Hkdf;
use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::JweDecryptOptions;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

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

/// The payload sealed inside a refresh token (RFC 6749 §6).
///
/// It carries everything needed to re-mint an access token and id_token on
/// refresh without a server lookup: the subject, the granted scope, the released
/// claims, the original `auth_time`/`nonce`/`acr` so a refreshed id_token stays
/// faithful to the initial authentication, and any DPoP confirmation thumbprint
/// that sender-constrains the refresh token. Refresh tokens are rotated on each
/// use, but — like every other token here — they are stateless, so they cannot
/// be revoked before their own `exp` (no server-side store to consult).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenPayload {
    pub client_id: String,
    pub sub: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
    pub auth_time: u64,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf_jkt: Option<String>,
}

/// Token-type discriminators sealed alongside each payload so a token of one
/// kind cannot be replayed as another — e.g. a refresh token (or an
/// authorization code) presented as an access token at the userinfo endpoint.
/// The tag is checked on every open.
const TYP_CODE: &str = "code";
const TYP_ACCESS: &str = "at";
const TYP_REFRESH: &str = "rt";

/// On-the-wire envelope: a type tag plus the payload. Sealing wraps the payload;
/// opening verifies the tag before the payload is trusted.
#[derive(Serialize)]
struct SealedEnvelope<'a, T: Serialize> {
    typ: &'a str,
    p: &'a T,
}

#[derive(Deserialize)]
struct OpenedEnvelope<T> {
    #[serde(default)]
    typ: String,
    p: T,
}

/// Seals/opens authorization codes, access tokens, and refresh tokens.
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

    fn seal<T: Serialize>(&self, typ: &str, value: &T) -> Result<String> {
        let plaintext = serde_json::to_vec(&SealedEnvelope { typ, p: value })?;
        jose_rs::jwe::encrypt(
            &self.keys[0],
            &plaintext,
            JweAlgorithm::Dir,
            JweEncryption::A256GCM,
        )
        .map_err(|e| Error::Crypto(format!("token seal: {e}")))
    }

    fn open<T: for<'de> Deserialize<'de>>(&self, expected_typ: &str, token: &str) -> Result<T> {
        // Pin the accepted algorithms — reject anything but dir + A256GCM before
        // touching key material (defence against algorithm substitution).
        let opts = JweDecryptOptions::new(vec![JweAlgorithm::Dir], vec![JweEncryption::A256GCM]);
        let mut last_err = None;
        for key in &self.keys {
            match jose_rs::jwe::decrypt_with_options(key, token, &opts) {
                // Decryption succeeded under this key, so this is one of our
                // tokens: a payload/type problem from here on is a hard error,
                // not a reason to try the next key.
                Ok(plaintext) => {
                    let env: OpenedEnvelope<T> = serde_json::from_slice(&plaintext)?;
                    if env.typ != expected_typ {
                        return Err(Error::Authn(format!(
                            "token type mismatch: expected {expected_typ}, got {}",
                            env.typ
                        )));
                    }
                    return Ok(env.p);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(Error::Authn(format!(
            "token open: {}",
            last_err.expect("at least one key is always present")
        )))
    }

    pub fn seal_code(&self, payload: &AuthCodePayload) -> Result<String> {
        self.seal(TYP_CODE, payload)
    }

    /// Open and expiry-check an authorization code.
    pub fn open_code(&self, token: &str) -> Result<AuthCodePayload> {
        let payload: AuthCodePayload = self.open(TYP_CODE, token)?;
        if payload.exp <= now_secs() {
            return Err(Error::Authn("authorization code expired".into()));
        }
        Ok(payload)
    }

    pub fn seal_access_token(&self, payload: &AccessTokenPayload) -> Result<String> {
        self.seal(TYP_ACCESS, payload)
    }

    /// Open and expiry-check an access token.
    pub fn open_access_token(&self, token: &str) -> Result<AccessTokenPayload> {
        let payload: AccessTokenPayload = self.open(TYP_ACCESS, token)?;
        if payload.exp <= now_secs() {
            return Err(Error::Authn("access token expired".into()));
        }
        Ok(payload)
    }

    pub fn seal_refresh_token(&self, payload: &RefreshTokenPayload) -> Result<String> {
        self.seal(TYP_REFRESH, payload)
    }

    /// Open and expiry-check a refresh token.
    pub fn open_refresh_token(&self, token: &str) -> Result<RefreshTokenPayload> {
        let payload: RefreshTokenPayload = self.open(TYP_REFRESH, token)?;
        if payload.exp <= now_secs() {
            return Err(Error::Authn("refresh token expired".into()));
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
    fn refresh_roundtrip_and_expiry() {
        let codec = TokenCodec::new("op-secret");
        let mut claims = BTreeMap::new();
        claims.insert("email".to_string(), serde_json::json!("anna@example.com"));
        let payload = RefreshTokenPayload {
            client_id: "client-1".into(),
            sub: "user-1".into(),
            scope: "openid email".into(),
            nonce: Some("n".into()),
            claims,
            auth_time: now_secs() - 30,
            exp: now_secs() + 60,
            acr: Some("urn:acr:mock".into()),
            cnf_jkt: None,
        };
        let token = codec.seal_refresh_token(&payload).unwrap();
        let opened = codec.open_refresh_token(&token).unwrap();
        assert_eq!(opened.sub, "user-1");
        assert_eq!(opened.scope, "openid email");
        assert_eq!(opened.acr.as_deref(), Some("urn:acr:mock"));

        // Expired.
        let mut expired = payload.clone();
        expired.exp = now_secs() - 1;
        let token = codec.seal_refresh_token(&expired).unwrap();
        assert!(codec.open_refresh_token(&token).is_err());
    }

    #[test]
    fn token_types_are_not_interchangeable() {
        // A refresh token must not open as an access token (else it could be
        // replayed at userinfo), and vice versa, even under the same key.
        let codec = TokenCodec::new("op-secret");
        let refresh = codec
            .seal_refresh_token(&RefreshTokenPayload {
                client_id: "c".into(),
                sub: "s".into(),
                scope: "openid".into(),
                nonce: None,
                claims: BTreeMap::new(),
                auth_time: now_secs(),
                exp: now_secs() + 60,
                acr: None,
                cnf_jkt: None,
            })
            .unwrap();
        assert!(codec.open_access_token(&refresh).is_err());
        assert!(codec.open_code(&refresh).is_err());

        let access = codec
            .seal_access_token(&AccessTokenPayload {
                client_id: "c".into(),
                sub: "s".into(),
                scope: "openid".into(),
                claims: BTreeMap::new(),
                exp: now_secs() + 60,
                cnf_jkt: None,
            })
            .unwrap();
        assert!(codec.open_refresh_token(&access).is_err());
        assert!(codec.open_code(&access).is_err());
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
