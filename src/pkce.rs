//! PKCE (RFC 7636) helpers.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Compute the S256 code challenge for a verifier.
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify a `code_verifier` against a stored `code_challenge` + method.
///
/// `method` defaults to `plain` when absent (RFC 7636 §4.3).
pub fn verify(verifier: &str, challenge: &str, method: Option<&str>) -> bool {
    match method.unwrap_or("plain") {
        "S256" => constant_time_eq(s256_challenge(verifier).as_bytes(), challenge.as_bytes()),
        "plain" => constant_time_eq(verifier.as_bytes(), challenge.as_bytes()),
        _ => false,
    }
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
    fn rfc7636_example_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), challenge);
        assert!(verify(verifier, challenge, Some("S256")));
        assert!(!verify("wrong", challenge, Some("S256")));
    }

    #[test]
    fn plain_method() {
        assert!(verify("abc", "abc", Some("plain")));
        assert!(verify("abc", "abc", None));
        assert!(!verify("abc", "xyz", None));
    }
}
