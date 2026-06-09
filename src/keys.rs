//! Cryptographic key-material loading.
//!
//! Operators may reference signing keys as PEM/DER files **or** as inline/file
//! JWK(s). Everything is normalized to a [`jose_rs::jwk::Jwk`] so the rest of
//! the codebase only ever sees JWKs. jose-rs has no direct PEM parser, so this
//! module bridges PEM/DER → kryptering `SoftwareKey` → JWK.

use crate::error::{Error, Result};
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::{software_key_to_jwk, Jwk, JwkSet};
use kryptering::SoftwareKey;

/// A loaded signing key plus the algorithm and key id to use with it.
#[derive(Clone)]
pub struct SigningKey {
    /// The private JWK (contains `d`).
    pub jwk: Jwk,
    /// The JWS algorithm to sign with.
    pub alg: JwsAlgorithm,
    /// Key id published in JWKS / JWT headers.
    pub kid: Option<String>,
}

impl SigningKey {
    /// The public companion JWK (private components stripped), with `alg`/`kid`
    /// populated for publication in a JWKS document.
    pub fn public_jwk(&self) -> Jwk {
        let mut pub_jwk = self.jwk.to_public_jwk();
        pub_jwk.alg = Some(self.alg.as_str().to_string());
        pub_jwk.kid = self.kid.clone();
        pub_jwk.use_ = Some("sig".to_string());
        pub_jwk
    }

    /// Build a single-key JWKS for the discovery `jwks` endpoint.
    pub fn to_public_jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public_jwk()],
        }
    }
}

/// Default JWS algorithm for a given key type / curve.
fn default_alg(jwk: &Jwk) -> Result<JwsAlgorithm> {
    match jwk.kty.as_str() {
        "RSA" => Ok(JwsAlgorithm::RS256),
        "EC" => match jwk.crv.as_deref() {
            Some("P-256") => Ok(JwsAlgorithm::ES256),
            Some("P-384") => Ok(JwsAlgorithm::ES384),
            Some("P-521") => Ok(JwsAlgorithm::ES512),
            other => Err(Error::Crypto(format!("unsupported EC curve: {other:?}"))),
        },
        "OKP" => Ok(JwsAlgorithm::EdDSA),
        "oct" => Ok(JwsAlgorithm::HS256),
        other => Err(Error::Crypto(format!("unsupported kty: {other}"))),
    }
}

/// Load a signing key from a JWK JSON string.
pub fn signing_key_from_jwk_json(
    json: &str,
    alg_override: Option<&str>,
    kid_override: Option<&str>,
) -> Result<SigningKey> {
    let mut jwk = Jwk::from_json(json).map_err(Error::from)?;
    finalize_signing_key(&mut jwk, alg_override, kid_override)
}

/// Load a signing key from a PEM (or DER) file's bytes.
pub fn signing_key_from_pem(
    bytes: &[u8],
    alg_override: Option<&str>,
    kid_override: Option<&str>,
) -> Result<SigningKey> {
    let sw = parse_private_key(bytes)?;
    let mut jwk = software_key_to_jwk(&sw).map_err(Error::from)?;
    finalize_signing_key(&mut jwk, alg_override, kid_override)
}

fn finalize_signing_key(
    jwk: &mut Jwk,
    alg_override: Option<&str>,
    kid_override: Option<&str>,
) -> Result<SigningKey> {
    let alg = match alg_override {
        Some(s) => JwsAlgorithm::from_str(s)
            .map_err(|e| Error::Crypto(format!("bad signing algorithm {s}: {e}")))?,
        None => default_alg(jwk)?,
    };
    jwk.alg = Some(alg.as_str().to_string());
    if let Some(kid) = kid_override {
        jwk.kid = Some(kid.to_string());
    }
    let kid = jwk.kid.clone();
    Ok(SigningKey {
        jwk: jwk.clone(),
        alg,
        kid,
    })
}

/// Parse a PEM or DER private key into a kryptering `SoftwareKey`, trying the
/// common encodings (PKCS#8, PKCS#1, SEC1) across RSA/EC/Ed25519.
fn parse_private_key(bytes: &[u8]) -> Result<SoftwareKey> {
    // If it looks like PEM, decode to DER first; otherwise treat as DER.
    let der: Vec<u8> = if bytes.starts_with(b"-----BEGIN") {
        let parsed = pem::parse(bytes)
            .map_err(|e| Error::Crypto(format!("invalid PEM: {e}")))?;
        parsed.into_contents()
    } else {
        bytes.to_vec()
    };

    if let Ok(k) = rsa_from_der(&der) {
        return Ok(k);
    }
    if let Ok(k) = ec_p256_from_der(&der) {
        return Ok(k);
    }
    if let Ok(k) = ec_p384_from_der(&der) {
        return Ok(k);
    }
    if let Ok(k) = ed25519_from_der(&der) {
        return Ok(k);
    }
    Err(Error::Crypto(
        "could not parse private key (tried RSA/EC P-256/P-384/Ed25519 in PKCS#8/PKCS#1/SEC1)".into(),
    ))
}

fn rsa_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(der)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(der))
        .map_err(|e| Error::Crypto(format!("not an RSA key: {e}")))?;
    let public = priv_key.to_public_key();
    Ok(SoftwareKey::Rsa {
        private: Some(priv_key),
        public,
    })
}

fn ec_p256_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use p256::pkcs8::DecodePrivateKey;
    // Try PKCS#8 then SEC1.
    let secret = p256::SecretKey::from_pkcs8_der(der)
        .or_else(|_| p256::SecretKey::from_sec1_der(der))
        .map_err(|e| Error::Crypto(format!("not a P-256 key: {e}")))?;
    let signing = p256::ecdsa::SigningKey::from(secret);
    let verifying = *signing.verifying_key();
    Ok(SoftwareKey::EcP256 {
        private: Some(signing),
        public: verifying,
    })
}

fn ec_p384_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use p384::pkcs8::DecodePrivateKey;
    let secret = p384::SecretKey::from_pkcs8_der(der)
        .or_else(|_| p384::SecretKey::from_sec1_der(der))
        .map_err(|e| Error::Crypto(format!("not a P-384 key: {e}")))?;
    let signing = p384::ecdsa::SigningKey::from(secret);
    let verifying = *signing.verifying_key();
    Ok(SoftwareKey::EcP384 {
        private: Some(signing),
        public: verifying,
    })
}

fn ed25519_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let signing = ed25519_dalek::SigningKey::from_pkcs8_der(der)
        .map_err(|e| Error::Crypto(format!("not an Ed25519 key: {e}")))?;
    let public = signing.verifying_key();
    Ok(SoftwareKey::Ed25519 {
        private: Some(signing),
        public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_ec_p256_jwk() {
        // Generate an EC P-256 JWK via jose and round-trip through our loader.
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let json = jwk.to_json().unwrap();
        let key = signing_key_from_jwk_json(&json, None, Some("k1")).unwrap();
        assert_eq!(key.alg, JwsAlgorithm::ES256);
        assert_eq!(key.kid.as_deref(), Some("k1"));
        let pubjwk = key.public_jwk();
        assert!(pubjwk.d.is_none());
        assert_eq!(pubjwk.kid.as_deref(), Some("k1"));
    }

    #[test]
    fn sign_with_loaded_key() {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), None, Some("k1")).unwrap();

        let header = jose_rs::JoseHeader::jwt_for_alg(key.alg);
        let claims = jose_rs::jwt::Claims {
            iss: Some("issuer".into()),
            ..Default::default()
        };
        let token = jose_rs::jwt::encode_with_jwk(&key.jwk, &header, &claims).unwrap();

        // Verify with the public JWK.
        let v = jose_rs::jwt::Validation::new().with_issuer("issuer");
        let decoded = jose_rs::jwt::decode_with_jwk(&key.public_jwk(), &token, &v).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("issuer"));
    }
}
