//! Small MAC helpers over the shared `kryptering` backend.
//!
//! These wrap the two primitives the OIDC layer needs for stateless DPoP nonces
//! (RFC 9449 §8) — an HMAC-SHA256 and a constant-time comparison — so callers
//! such as `tunnelbana-oidc` get them from here instead of taking a direct
//! dependency on `kryptering` (the rest of the crypto wrapping already lives in
//! this crate, see [`crate::keys`]).

use kryptering::digest::{compute_hmac, constant_time_eq as kryptering_ct_eq, digest};
use kryptering::HashAlgorithm;

/// Compute HMAC-SHA256 over `data` with `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    compute_hmac(HashAlgorithm::Sha256, key, data)
}

/// Compute a plain SHA-256 digest of `data`. Used for the DPoP `ath`
/// access-token hash (RFC 9449 §4.3).
pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest(HashAlgorithm::Sha256, data)
}

/// Constant-time equality (no early return on first mismatching byte). Returns
/// false for differing lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    kryptering_ct_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_deterministic_and_key_sensitive() {
        let a = hmac_sha256(b"secret", b"message");
        let b = hmac_sha256(b"secret", b"message");
        let c = hmac_sha256(b"other", b"message");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn ct_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn sha256_is_32_bytes_and_deterministic() {
        let a = sha256(b"message");
        let b = sha256(b"message");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, sha256(b"other"));
    }
}
