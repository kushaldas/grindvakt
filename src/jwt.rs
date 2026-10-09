//! Thin helpers over jose-rs for the OIDC/federation flows.

use crate::error::{Error, Result};
use crate::keys::SigningKey;
use base64::Engine;
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::{Jwk, JwkSet};
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Sign a set of claims into a compact JWS using a [`SigningKey`], setting the
/// `alg`, `kid` and (optionally) a custom `typ` header.
pub fn sign(key: &SigningKey, claims: &Claims, typ: Option<&str>) -> Result<String> {
    let mut header = JoseHeader::for_alg(key.alg());
    header.kid = key.kid().map(|k| k.to_string());
    header.typ = typ.map(|t| t.to_string());
    jose_rs::jwt::encode(key.signer(), &header, claims).map_err(Error::from)
}

/// Verify and validate a compact JWS against a JWK Set.
pub fn verify_with_jwks(jwks: &JwkSet, token: &str, validation: &Validation) -> Result<Claims> {
    jose_rs::jwt::decode_with_jwkset(jwks, token, validation).map_err(Error::from)
}

/// Verify and validate a compact JWS against a single JWK.
pub fn verify_with_jwk(jwk: &Jwk, token: &str, validation: &Validation) -> Result<Claims> {
    jose_rs::jwt::decode_with_jwk(jwk, token, validation).map_err(Error::from)
}

/// Read the protected header of a compact JWS without verifying it (used to peek
/// at `kid`/`typ` before key selection).
pub fn peek_header(token: &str) -> Result<JoseHeader> {
    jose_rs::jws::compact::decode_header(token).map_err(Error::from)
}

/// Decode the claims of a JWS without verifying its signature. DANGEROUS — only
/// for inspection (e.g. reading `iss`/`client_id` to pick a verification key).
pub fn peek_claims_unverified(token: &str) -> Result<Claims> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Error::BadRequest("malformed JWT".into()));
    }
    let payload = jose_rs::base64url::decode(parts[1]).map_err(Error::from)?;
    serde_json::from_slice(&payload).map_err(Error::from)
}

/// Compute the OIDC Core `at_hash` / `c_hash` value for `value`: the left half
/// of the SHA-2 digest matching the JWS `alg` (SHA-256, SHA-384 or SHA-512),
/// base64url-encoded without padding.
///
/// Returns [`Error::Crypto`] for algorithms with no defined hash function,
/// such as `EdDSA`.
pub fn oidc_token_hash(alg: JwsAlgorithm, value: &str) -> Result<String> {
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
            return Err(Error::Crypto(format!(
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
pub fn supports_oidc_token_hash(alg: JwsAlgorithm) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_token_hash_matches_core_appendix_a_vectors() {
        assert_eq!(
            oidc_token_hash(
                JwsAlgorithm::RS256,
                "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
            )
            .unwrap(),
            "77QmUPtjPfzWtF2AnpK9RQ"
        );
        assert_eq!(
            oidc_token_hash(
                JwsAlgorithm::RS256,
                "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk"
            )
            .unwrap(),
            "LDktKdoQak3Pk0cnXxCltA"
        );
    }

    #[test]
    fn oidc_token_hash_lengths_follow_alg() {
        assert_eq!(oidc_token_hash(JwsAlgorithm::ES384, "x").unwrap().len(), 32);
        assert_eq!(oidc_token_hash(JwsAlgorithm::ES512, "x").unwrap().len(), 43);
        assert!(oidc_token_hash(JwsAlgorithm::EdDSA, "x").is_err());
        assert!(!supports_oidc_token_hash(JwsAlgorithm::EdDSA));
    }
}
