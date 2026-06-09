//! DPoP — Demonstrating Proof of Possession (RFC 9449).
//!
//! Validates the `DPoP: <jwt>` proof presented on the token request, binding
//! the issued access token to the public key in the proof header (`cnf.jkt`).
//! The proof is an ES256 JWS whose protected header carries its own verifying
//! key as a `jwk`; we verify it against that embedded key via the in-house
//! `jose-rs` crate, which also rejects `alg: none` and unbound headers.
//!
//! Replay is prevented by remembering each proof's `jti` for the proof's
//! freshness window (RFC 9449 §11.1). This crate is stateless-by-design, so the
//! store is abstracted behind the [`ReplayStore`] trait: a deployment backs it
//! with whatever store it likes (the `tunnelbana` binary uses the core TTL/disk
//! cache), or uses [`NoReplayStore`] for the stateless-nonce-only mode.
//!
//! DPoP-Nonce (RFC 9449 §8) is supported but off by default. When enabled,
//! nonces are stateless: a base64url HMAC over a timestamp, so no nonce store is
//! needed either.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jose_rs::jwk::{thumbprint::thumbprint_sha256, Jwk};
use serde::Deserialize;
use crate::mac::{constant_time_eq, hmac_sha256, sha256};
use crate::util::now_secs;

/// Small allowance (seconds) for clock skew when checking a proof's `iat`.
const IAT_FUTURE_SKEW_SECS: i64 = 30;

/// Configuration knobs for DPoP validation (replaces authc's `AppConfig`).
#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// Maximum age (seconds) of a proof's `iat` before it is rejected, and the
    /// window for which a `jti` is remembered against replay.
    pub proof_max_age_secs: i64,
    /// Whether a valid `DPoP-Nonce` (RFC 9449 §8) is required.
    pub require_nonce: bool,
    /// Lifetime (seconds) of an issued nonce.
    pub nonce_lifetime_secs: i64,
    /// HMAC key for the stateless nonce. Derive a dedicated key for this — do
    /// not overload the token-signing or sealing key.
    pub nonce_secret: String,
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            proof_max_age_secs: 300,
            require_nonce: false,
            nonce_lifetime_secs: 300,
            nonce_secret: String::new(),
        }
    }
}

/// The outcome of validating a DPoP proof.
#[derive(Debug, Clone)]
pub struct DpopProof {
    /// JWK SHA-256 thumbprint (RFC 7638) — the value bound as `cnf.jkt`.
    pub jkt: String,
}

/// Why DPoP validation failed. The web layer maps these onto the right HTTP
/// response (a `use_dpop_nonce` challenge vs. an `invalid_dpop_proof` error).
#[derive(Debug)]
pub enum DpopError {
    /// The proof was malformed or failed a check.
    Invalid(String),
    /// The proof's `jti` was already seen.
    Replay,
    /// A fresh DPoP nonce is required (RFC 9449 §8) — challenge the client.
    NonceRequired,
    /// Internal error (e.g. replay store outage).
    Server(String),
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DpopError::Invalid(m) => write!(f, "invalid DPoP proof: {m}"),
            DpopError::Replay => write!(f, "DPoP proof replayed"),
            DpopError::NonceRequired => write!(f, "DPoP nonce required"),
            DpopError::Server(m) => write!(f, "DPoP server error: {m}"),
        }
    }
}

impl std::error::Error for DpopError {}

/// A store remembering DPoP `jti`s for their freshness window so the same proof
/// cannot be replayed (RFC 9449 §11.1). Kept out of this crate's stateless core
/// — the deployment backs it with whatever store it likes.
#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Record `jti` for `ttl_secs`. Returns `Ok(true)` if it was newly recorded
    /// (not a replay), `Ok(false)` if it was already present (a replay), or
    /// `Err` on an internal failure.
    async fn record(&self, jti: &str, ttl_secs: u64) -> Result<bool, String>;
}

/// A no-op [`ReplayStore`] for the stateless-nonce-only mode: every `jti` is
/// treated as fresh.
///
/// **Security caveat:** with this store a captured proof can be replayed for the
/// whole `proof_max_age_secs` window *unless* `require_nonce` is also enabled —
/// the HMAC nonce challenge is then the only thing bounding the replay window.
/// Do not pair `NoReplayStore` with `require_nonce = false` on an internet-facing
/// deployment; prefer a real (shared) [`ReplayStore`]. The in-tree frontends use
/// a cache-backed store, never this.
pub struct NoReplayStore;

#[async_trait]
impl ReplayStore for NoReplayStore {
    async fn record(&self, _jti: &str, _ttl_secs: u64) -> Result<bool, String> {
        Ok(true)
    }
}

/// The registered claims of a DPoP proof JWT (RFC 9449 §4.2).
#[derive(Debug, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    nonce: Option<String>,
    /// Access-token hash (RFC 9449 §4.3) — required on resource requests, where
    /// it binds the proof to the specific access token being presented.
    #[serde(default)]
    ath: Option<String>,
}

/// Validate a DPoP proof for a token-endpoint request.
///
/// * `htm` / `htu` — the HTTP method and the absolute request URI the proof
///   must be bound to (query and fragment stripped before comparison).
/// * On success the proof's `jti` has been recorded via `store`, so a replay of
///   the same proof now returns [`DpopError::Replay`].
pub async fn validate_proof(
    store: &dyn ReplayStore,
    config: &DpopConfig,
    proof: &str,
    htm: &str,
    htu: &str,
) -> Result<DpopProof, DpopError> {
    validate_and_record(store, config, proof, htm, htu, None).await
}

/// Validate a DPoP proof for a **resource** request (e.g. userinfo), additionally
/// binding it to `access_token` via the `ath` claim (RFC 9449 §4.3/§7.1). The
/// caller must still check that the returned [`DpopProof::jkt`] equals the access
/// token's `cnf.jkt` confirmation.
pub async fn validate_resource_proof(
    store: &dyn ReplayStore,
    config: &DpopConfig,
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: &str,
) -> Result<DpopProof, DpopError> {
    let ath = ath_of(access_token);
    validate_and_record(store, config, proof, htm, htu, Some(&ath)).await
}

/// `base64url(SHA-256(access_token))` — the value a resource-request proof must
/// carry in its `ath` claim.
fn ath_of(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha256(access_token.as_bytes()))
}

/// Shared body of [`validate_proof`] / [`validate_resource_proof`]: run the
/// store-free crypto + claims checks, then record the `jti` for replay defense.
async fn validate_and_record(
    store: &dyn ReplayStore,
    config: &DpopConfig,
    proof: &str,
    htm: &str,
    htu: &str,
    expected_ath: Option<&str>,
) -> Result<DpopProof, DpopError> {
    // Crypto + claims checks first (no store). Yields the proof key thumbprint
    // and the jti we must guard against replay.
    let Validated { jkt, jti } = validate_proof_inner(config, proof, htm, htu, expected_ath)?;

    // Replay protection: recording *is* the check — a "not newly recorded"
    // result means the jti was seen before.
    let ttl = config.proof_max_age_secs.max(0) as u64;
    match store.record(&jti, ttl).await {
        Ok(true) => {}
        Ok(false) => return Err(DpopError::Replay),
        Err(e) => return Err(DpopError::Server(e)),
    }

    Ok(DpopProof { jkt })
}

/// The store-free result of validating a proof's crypto and claims.
#[derive(Debug)]
struct Validated {
    jkt: String,
    jti: String,
}

/// Validate everything about a DPoP proof except replay: header shape, ES256
/// signature against the embedded key, htm/htu binding, iat freshness, the
/// optional nonce challenge, and — for resource requests — the `ath`
/// access-token binding. Returns the proof key thumbprint and the `jti`.
fn validate_proof_inner(
    config: &DpopConfig,
    proof: &str,
    htm: &str,
    htu: &str,
    expected_ath: Option<&str>,
) -> Result<Validated, DpopError> {
    // 1. Read the protected header to get typ / alg / the embedded JWK.
    let header = jose_rs::jws::decode_header(proof)
        .map_err(|e| DpopError::Invalid(format!("undecodable header: {e}")))?;

    // 2. typ MUST be "dpop+jwt" (RFC 9449 §4.2).
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(DpopError::Invalid("typ must be dpop+jwt".into()));
    }

    // 3. alg MUST be an asymmetric signing alg; the wallet uses ES256. This
    //    also rejects "none" and any symmetric (HS*) alg outright.
    if header.alg != "ES256" {
        return Err(DpopError::Invalid(format!(
            "alg must be ES256, got {}",
            header.alg
        )));
    }

    // 4. The header MUST carry the verifying public key as a `jwk`.
    let jwk_value = header
        .jwk
        .ok_or_else(|| DpopError::Invalid("header is missing jwk".into()))?;
    let jwk = Jwk::from_json(&jwk_value.to_string())
        .map_err(|e| DpopError::Invalid(format!("bad jwk: {e}")))?;

    // A DPoP proof key must be public — reject anything carrying private
    // material so a leaked private JWK can't sneak in.
    if jwk.d.is_some() || jwk.priv_.is_some() {
        return Err(DpopError::Invalid("jwk must not contain private key".into()));
    }

    // 5. Verify the JWS signature against the proof's own key. `verify_with_jwk`
    //    re-binds the header alg and rejects `alg: none` transitively.
    let payload = jose_rs::jws::compact::verify_with_jwk(&jwk, proof)
        .map_err(|e| DpopError::Invalid(format!("signature verification failed: {e}")))?;

    let claims: DpopClaims = serde_json::from_slice(&payload)
        .map_err(|e| DpopError::Invalid(format!("undecodable claims: {e}")))?;

    // 6. htm / htu must match this request.
    if !claims.htm.eq_ignore_ascii_case(htm) {
        return Err(DpopError::Invalid(format!(
            "htm mismatch: proof={}, request={htm}",
            claims.htm
        )));
    }
    if normalize_htu(&claims.htu) != normalize_htu(htu) {
        return Err(DpopError::Invalid(format!(
            "htu mismatch: proof={}, request={htu}",
            claims.htu
        )));
    }

    // 6b. ath binding (RFC 9449 §4.3) — required on resource requests. The proof
    //     must carry the hash of the access token it accompanies, so a proof
    //     minted for one token cannot be presented with another.
    if let Some(expected) = expected_ath {
        match claims.ath.as_deref() {
            Some(got) if constant_time_eq(got.as_bytes(), expected.as_bytes()) => {}
            _ => return Err(DpopError::Invalid("ath missing or mismatched".into())),
        }
    }

    // 7. iat freshness.
    let now = now_secs() as i64;
    if claims.iat > now + IAT_FUTURE_SKEW_SECS {
        return Err(DpopError::Invalid("iat is in the future".into()));
    }
    if now - claims.iat > config.proof_max_age_secs {
        return Err(DpopError::Invalid("proof is too old".into()));
    }

    // 8. DPoP-Nonce challenge (RFC 9449 §8), only when configured to require it.
    if config.require_nonce {
        match claims.nonce.as_deref() {
            Some(n) if validate_nonce(config, n) => {}
            _ => return Err(DpopError::NonceRequired),
        }
    }

    // 9. Bind the token to the proof key.
    let jkt = thumbprint_sha256(&jwk)
        .map_err(|e| DpopError::Server(format!("thumbprint failed: {e}")))?;

    Ok(Validated {
        jkt,
        jti: claims.jti,
    })
}

/// Normalize an `htu` for comparison: drop query and fragment, trim a trailing
/// slash. RFC 9449 §4.3 compares the request URI without query/fragment.
fn normalize_htu(uri: &str) -> String {
    let no_frag = uri.split('#').next().unwrap_or(uri);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    no_query.to_string()
}

// ---------------------------------------------------------------------------
// Stateless DPoP nonces (RFC 9449 §8)
// ---------------------------------------------------------------------------

/// Truncated MAC length (bytes) appended to the timestamp in a nonce.
const NONCE_MAC_LEN: usize = 16;

/// Issue a fresh DPoP nonce: `base64url( ts_be(8) || HMAC-SHA256(secret, ts)[..16] )`.
/// Stateless — validated by recomputing the MAC and checking the age, so no
/// nonce store is required.
pub fn issue_nonce(config: &DpopConfig) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let ts = now_secs() as i64;
    let ts_bytes = ts.to_be_bytes();
    let mac = hmac_sha256(config.nonce_secret.as_bytes(), &ts_bytes);

    let mut out = Vec::with_capacity(8 + NONCE_MAC_LEN);
    out.extend_from_slice(&ts_bytes);
    out.extend_from_slice(&mac[..NONCE_MAC_LEN]);
    URL_SAFE_NO_PAD.encode(out)
}

/// Validate a DPoP nonce we previously issued: the MAC must verify and the
/// embedded timestamp must be within `nonce_lifetime_secs`.
fn validate_nonce(config: &DpopConfig, nonce: &str) -> bool {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let Ok(raw) = URL_SAFE_NO_PAD.decode(nonce) else {
        return false;
    };
    if raw.len() != 8 + NONCE_MAC_LEN {
        return false;
    }
    let (ts_bytes, mac) = raw.split_at(8);
    let expected = hmac_sha256(config.nonce_secret.as_bytes(), ts_bytes);
    if !constant_time_eq(mac, &expected[..NONCE_MAC_LEN]) {
        return false;
    }

    let ts = i64::from_be_bytes(ts_bytes.try_into().unwrap_or_default());
    let age = now_secs() as i64 - ts;
    (0..=config.nonce_lifetime_secs).contains(&age)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DpopConfig {
        DpopConfig {
            proof_max_age_secs: 300,
            require_nonce: false,
            nonce_lifetime_secs: 300,
            nonce_secret: "dev-secret-change-in-production".to_string(),
        }
    }

    #[test]
    fn nonce_roundtrips() {
        let cfg = test_config();
        let n = issue_nonce(&cfg);
        assert!(validate_nonce(&cfg, &n));
    }

    #[test]
    fn tampered_nonce_rejected() {
        let cfg = test_config();
        let mut n = issue_nonce(&cfg);
        // Flip the last character.
        let last = n.pop().unwrap();
        n.push(if last == 'A' { 'B' } else { 'A' });
        assert!(!validate_nonce(&cfg, &n));
    }

    #[test]
    fn nonce_from_other_secret_rejected() {
        let cfg = test_config();
        let n = issue_nonce(&cfg);
        let mut other = test_config();
        other.nonce_secret = "a-different-secret".to_string();
        assert!(!validate_nonce(&other, &n));
    }

    /// Build a signed ES256 DPoP proof from a freshly generated key.
    /// Returns the compact proof and the key's expected thumbprint.
    fn make_proof(htm: &str, htu: &str, iat: i64, nonce: Option<&str>) -> (String, String) {
        make_proof_ath(htm, htu, iat, nonce, None)
    }

    /// Like [`make_proof`] but also setting the `ath` (access-token hash) claim.
    fn make_proof_ath(
        htm: &str,
        htu: &str,
        iat: i64,
        nonce: Option<&str>,
        ath: Option<&str>,
    ) -> (String, String) {
        use jose_rs::jwk::generate::generate_ec;
        use jose_rs::JoseHeader;

        let mut jwk = generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".to_string());
        let public = jwk.to_public_jwk();
        let jkt = thumbprint_sha256(&public).unwrap();

        // Header carries typ=dpop+jwt and the PUBLIC jwk.
        let mut header = JoseHeader::new("ES256");
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some(serde_json::from_str(&public.to_json().unwrap()).unwrap());

        let mut claims = serde_json::json!({
            "jti": crate::util::random_token(16),
            "htm": htm,
            "htu": htu,
            "iat": iat,
        });
        if let Some(n) = nonce {
            claims["nonce"] = serde_json::Value::String(n.to_string());
        }
        if let Some(a) = ath {
            claims["ath"] = serde_json::Value::String(a.to_string());
        }
        let payload = serde_json::to_vec(&claims).unwrap();
        let proof = jose_rs::jws::compact::sign_with_jwk(&jwk, &payload, &header).unwrap();
        (proof, jkt)
    }

    #[tokio::test]
    async fn resource_proof_requires_matching_ath() {
        let cfg = test_config();
        let htu = "https://rs.example/userinfo";
        let token = "the-access-token";
        let now = now_secs() as i64;

        // Correct ath → accepted.
        let (proof, _) = make_proof_ath("GET", htu, now, None, Some(&ath_of(token)));
        assert!(validate_resource_proof(&NoReplayStore, &cfg, &proof, "GET", htu, token)
            .await
            .is_ok());

        // No ath at all → rejected (resource requests require it).
        let (no_ath, _) = make_proof_ath("GET", htu, now, None, None);
        assert!(matches!(
            validate_resource_proof(&NoReplayStore, &cfg, &no_ath, "GET", htu, token)
                .await
                .unwrap_err(),
            DpopError::Invalid(_)
        ));

        // ath bound to a different token → rejected.
        let (wrong, _) = make_proof_ath("GET", htu, now, None, Some(&ath_of("other-token")));
        assert!(matches!(
            validate_resource_proof(&NoReplayStore, &cfg, &wrong, "GET", htu, token)
                .await
                .unwrap_err(),
            DpopError::Invalid(_)
        ));
    }

    #[test]
    fn valid_proof_yields_matching_thumbprint() {
        let cfg = test_config();
        let htu = "https://as.example/oauth2/token";
        let now = now_secs() as i64;
        let (proof, expected_jkt) = make_proof("POST", htu, now, None);

        let v = validate_proof_inner(&cfg, &proof, "POST", htu, None).expect("should validate");
        assert_eq!(v.jkt, expected_jkt);
    }

    #[test]
    fn htm_mismatch_rejected() {
        let cfg = test_config();
        let htu = "https://as.example/oauth2/token";
        let (proof, _) = make_proof("POST", htu, now_secs() as i64, None);
        let err = validate_proof_inner(&cfg, &proof, "GET", htu, None).unwrap_err();
        assert!(matches!(err, DpopError::Invalid(_)));
    }

    #[test]
    fn htu_mismatch_rejected() {
        let cfg = test_config();
        let (proof, _) = make_proof(
            "POST",
            "https://as.example/oauth2/token",
            now_secs() as i64,
            None,
        );
        let err =
            validate_proof_inner(&cfg, &proof, "POST", "https://evil.example/oauth2/token", None)
                .unwrap_err();
        assert!(matches!(err, DpopError::Invalid(_)));
    }

    #[test]
    fn trailing_slash_htu_mismatch_rejected() {
        let cfg = test_config();
        let (proof, _) = make_proof(
            "POST",
            "https://as.example/oauth2/token/",
            now_secs() as i64,
            None,
        );
        let err =
            validate_proof_inner(&cfg, &proof, "POST", "https://as.example/oauth2/token", None)
                .unwrap_err();
        assert!(matches!(err, DpopError::Invalid(_)));
    }

    #[test]
    fn stale_proof_rejected() {
        let cfg = test_config();
        let htu = "https://as.example/oauth2/token";
        let stale = now_secs() as i64 - cfg.proof_max_age_secs - 60;
        let (proof, _) = make_proof("POST", htu, stale, None);
        let err = validate_proof_inner(&cfg, &proof, "POST", htu, None).unwrap_err();
        assert!(matches!(err, DpopError::Invalid(_)));
    }

    #[test]
    fn nonce_required_when_configured_and_absent() {
        let mut cfg = test_config();
        cfg.require_nonce = true;
        let htu = "https://as.example/oauth2/token";
        let (proof, _) = make_proof("POST", htu, now_secs() as i64, None);
        let err = validate_proof_inner(&cfg, &proof, "POST", htu, None).unwrap_err();
        assert!(matches!(err, DpopError::NonceRequired));
    }

    #[test]
    fn valid_nonce_accepted_when_required() {
        let mut cfg = test_config();
        cfg.require_nonce = true;
        let htu = "https://as.example/oauth2/token";
        let nonce = issue_nonce(&cfg);
        let (proof, _) = make_proof("POST", htu, now_secs() as i64, Some(&nonce));
        assert!(validate_proof_inner(&cfg, &proof, "POST", htu, None).is_ok());
    }

    #[test]
    fn htu_normalization() {
        assert_eq!(
            normalize_htu("https://as.example/oauth2/token?foo=bar#x"),
            "https://as.example/oauth2/token"
        );
        assert_eq!(
            normalize_htu("https://as.example/oauth2/token/"),
            "https://as.example/oauth2/token/"
        );
    }

    #[tokio::test]
    async fn validate_proof_records_jti_and_detects_replay() {
        use std::sync::Mutex;
        struct OnceStore(Mutex<std::collections::HashSet<String>>);
        #[async_trait]
        impl ReplayStore for OnceStore {
            async fn record(&self, jti: &str, _ttl: u64) -> Result<bool, String> {
                Ok(self.0.lock().unwrap().insert(jti.to_string()))
            }
        }

        let cfg = test_config();
        let store = OnceStore(Mutex::new(std::collections::HashSet::new()));
        let htu = "https://as.example/oauth2/token";
        let (proof, jkt) = make_proof("POST", htu, now_secs() as i64, None);

        let first = validate_proof(&store, &cfg, &proof, "POST", htu)
            .await
            .expect("first use valid");
        assert_eq!(first.jkt, jkt);

        // Same proof again → replay.
        let err = validate_proof(&store, &cfg, &proof, "POST", htu)
            .await
            .unwrap_err();
        assert!(matches!(err, DpopError::Replay));
    }

    #[tokio::test]
    async fn no_replay_store_allows_reuse() {
        let cfg = test_config();
        let htu = "https://as.example/oauth2/token";
        let (proof, _) = make_proof("POST", htu, now_secs() as i64, None);
        assert!(validate_proof(&NoReplayStore, &cfg, &proof, "POST", htu)
            .await
            .is_ok());
        // NoReplayStore treats every jti as fresh.
        assert!(validate_proof(&NoReplayStore, &cfg, &proof, "POST", htu)
            .await
            .is_ok());
    }
}
