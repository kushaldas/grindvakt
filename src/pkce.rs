//! PKCE (RFC 7636) helpers.

use base64::Engine;
use sha2::{Digest, Sha256};

/// RFC 7636 code-verifier syntax: 43 to 128 unreserved ASCII characters.
pub fn is_valid_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// An S256 challenge is a 32-byte SHA-256 digest encoded as 43 base64url
/// characters without padding.
pub fn is_valid_s256_challenge(value: &str) -> bool {
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value) else {
        return false;
    };
    // Re-encoding rejects alternate strings with non-zero unused trailing
    // bits, so only the canonical representation of a SHA-256 digest passes.
    decoded.len() == 32
        && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) == value
}

/// Compute the S256 code challenge for a verifier.
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify a `code_verifier` against a stored `code_challenge` + method.
///
/// `method` defaults to `plain` when absent (RFC 7636 §4.3).
pub fn verify(verifier: &str, challenge: &str, method: Option<&str>) -> bool {
    if !is_valid_verifier(verifier) {
        return false;
    }
    match method.unwrap_or("plain") {
        "S256" if is_valid_s256_challenge(challenge) => {
            constant_time_eq(s256_challenge(verifier).as_bytes(), challenge.as_bytes())
        }
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
        let verifier = "a".repeat(43);
        assert!(verify(&verifier, &verifier, Some("plain")));
        assert!(verify(&verifier, &verifier, None));
        assert!(!verify(&verifier, &"b".repeat(43), None));
    }

    #[test]
    fn rejects_verifier_and_challenge_outside_rfc7636_abnf() {
        assert!(!is_valid_verifier("short"));
        assert!(!is_valid_verifier(&"a".repeat(129)));
        assert!(!is_valid_verifier(&format!("{}!", "a".repeat(42))));
        assert!(!verify("short", &s256_challenge("short"), Some("S256")));
        assert!(!is_valid_s256_challenge("not-a-challenge"));
    }

    #[test]
    fn rejects_noncanonical_s256_challenge() {
        let canonical = s256_challenge(&"a".repeat(43));
        assert!(is_valid_s256_challenge(&canonical));

        // A SHA-256 digest has four significant bits in its final base64url
        // character. Changing only an unused trailing bit must not create a
        // second accepted spelling for the same digest.
        let replacement = match canonical.as_bytes()[42] {
            b'A' => 'B',
            b'Q' => 'R',
            b'g' => 'h',
            b'w' => 'x',
            other => panic!("unexpected canonical trailing character: {other}"),
        };
        let mut noncanonical = canonical[..42].to_string();
        noncanonical.push(replacement);
        assert!(!is_valid_s256_challenge(&noncanonical));
    }
}
