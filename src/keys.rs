//! Cryptographic key-material loading.
//!
//! Operators may reference signing keys as PEM/DER files **or** as inline/file
//! JWK(s) and — with the `pkcs11` feature — as keys held on a hardware token.
//! Whatever the source, signing is performed through a [`kryptering::Signer`]
//! trait object so the private material may live in memory or never leave an
//! HSM. The public companion JWK (for JWKS publication) is cached at load time.
//!
//! Software keys bridge PEM/DER → kryptering `SoftwareKey` → JWK, then build a
//! `SoftwareSigner`. HSM keys (see [`signing_key_from_pkcs11`]) build a
//! `Pkcs11Signer` and reconstruct the public JWK from the token's public-key
//! object.

use crate::error::{Error, Result};
use jose_rs::algorithm::JwsAlgorithm;
use jose_rs::jwk::{jwk_to_software_key, software_key_to_jwk, Jwk, JwkSet};
use kryptering::{EcCurve as KrypteringEcCurve, KeyAlgorithm, SoftwareKey, SoftwareSigner};
use std::sync::Arc;

/// A loaded signing key: the signer that performs the cryptographic operation,
/// plus the algorithm, key id, and cached public JWK used for publication.
///
/// The signer is held behind an [`Arc`] so cloning a `SigningKey` is cheap and
/// the same backing key (software or HSM) is shared. The private material is
/// never exposed; only [`public_jwk`](Self::public_jwk) is available.
///
/// A `SigningKey` is immutable after construction: `alg`/`kid` are read-only
/// accessors so the signer, the headers, and the cached public JWK can never
/// drift out of agreement.
#[derive(Clone)]
pub struct SigningKey {
    /// The signer doing the actual work — a software key or an HSM-backed key.
    signer: Arc<dyn kryptering::Signer>,
    /// Public companion JWK (no private components), ready for a JWKS document.
    /// Stamped with `alg`/`kid` at construction; safe to cache because the key
    /// is immutable.
    public_jwk: Jwk,
    /// The JWS algorithm to sign with.
    alg: JwsAlgorithm,
    /// Key id published in JWKS / JWT headers.
    kid: Option<String>,
}

impl SigningKey {
    /// The signer used to produce signatures. Pass this to
    /// [`jose_rs::jwt::encode`] / [`jose_rs::jws::compact::sign`].
    pub fn signer(&self) -> &dyn kryptering::Signer {
        self.signer.as_ref()
    }

    /// The JWS algorithm this key signs with.
    pub fn alg(&self) -> JwsAlgorithm {
        self.alg
    }

    /// The key id published in JWKS / JWT headers, if any.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The public companion JWK (private components stripped), with `alg`/`kid`
    /// populated for publication in a JWKS document.
    pub fn public_jwk(&self) -> Jwk {
        self.public_jwk.clone()
    }

    /// Build a single-key JWKS for the discovery `jwks` endpoint.
    pub fn to_public_jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public_jwk.clone()],
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

/// Resolve the effective algorithm, stamp `alg`/`kid` onto the JWK, build the
/// software signer and the cached public JWK.
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

    // Build the in-memory signer from the (private) JWK.
    let sw = jwk_to_software_key(jwk).map_err(Error::from)?;
    let sig_alg = alg.to_crypto().map_err(Error::from)?;
    let signer = SoftwareSigner::new(sig_alg, sw)
        .map_err(|e| Error::Crypto(format!("could not build software signer: {e}")))?;

    let public_jwk = public_jwk_from_private(jwk, alg, &kid);
    Ok(SigningKey {
        signer: Arc::new(signer),
        public_jwk,
        alg,
        kid,
    })
}

/// Derive the publishable public JWK from a private JWK.
fn public_jwk_from_private(jwk: &Jwk, alg: JwsAlgorithm, kid: &Option<String>) -> Jwk {
    let mut pub_jwk = jwk.to_public_jwk();
    pub_jwk.alg = Some(alg.as_str().to_string());
    pub_jwk.kid = kid.clone();
    pub_jwk.use_ = Some("sig".to_string());
    pub_jwk
}

/// Parse a PEM or DER private key into a kryptering `SoftwareKey`, trying the
/// common encodings (PKCS#8, PKCS#1, SEC1) across RSA/EC/Ed25519.
fn parse_private_key(bytes: &[u8]) -> Result<SoftwareKey> {
    // If it looks like PEM, decode to DER first; otherwise treat as DER.
    let der: Vec<u8> = if bytes.starts_with(b"-----BEGIN") {
        let parsed = pem::parse(bytes).map_err(|e| Error::Crypto(format!("invalid PEM: {e}")))?;
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
        "could not parse private key (tried RSA/EC P-256/P-384/Ed25519 in PKCS#8/PKCS#1/SEC1)"
            .into(),
    ))
}

fn rsa_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(der)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(der))
        .map_err(|e| Error::Crypto(format!("not an RSA key: {e}")))?;
    let pkcs8 = priv_key
        .to_pkcs8_der()
        .map_err(|e| Error::Crypto(format!("RSA PKCS#8 encoding failed: {e}")))?;
    SoftwareKey::from_pkcs8_der(KeyAlgorithm::Rsa, pkcs8.as_bytes())
        .map_err(|e| Error::Crypto(format!("RSA key import failed: {e}")))
}

fn ec_p256_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    // Try PKCS#8 then SEC1.
    let secret = p256::SecretKey::from_pkcs8_der(der)
        .or_else(|_| p256::SecretKey::from_sec1_der(der))
        .map_err(|e| Error::Crypto(format!("not a P-256 key: {e}")))?;
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|e| Error::Crypto(format!("P-256 PKCS#8 encoding failed: {e}")))?;
    SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(KrypteringEcCurve::P256), pkcs8.as_bytes())
        .map_err(|e| Error::Crypto(format!("P-256 key import failed: {e}")))
}

fn ec_p384_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let secret = p384::SecretKey::from_pkcs8_der(der)
        .or_else(|_| p384::SecretKey::from_sec1_der(der))
        .map_err(|e| Error::Crypto(format!("not a P-384 key: {e}")))?;
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|e| Error::Crypto(format!("P-384 PKCS#8 encoding failed: {e}")))?;
    SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ec(KrypteringEcCurve::P384), pkcs8.as_bytes())
        .map_err(|e| Error::Crypto(format!("P-384 key import failed: {e}")))
}

fn ed25519_from_der(der: &[u8]) -> Result<SoftwareKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    ed25519_dalek::SigningKey::from_pkcs8_der(der)
        .map_err(|e| Error::Crypto(format!("not an Ed25519 key: {e}")))?;
    SoftwareKey::from_pkcs8_der(KeyAlgorithm::Ed25519, der)
        .map_err(|e| Error::Crypto(format!("Ed25519 key import failed: {e}")))
}

#[cfg(feature = "pkcs11")]
pub use pkcs11::{signing_key_from_pkcs11, Pkcs11KeyConfig};

/// PKCS#11 / HSM-backed signing keys.
///
/// Signing is delegated to the token over PKCS#11 (`C_Sign`); the private key
/// never leaves the hardware. Only asymmetric signing keys are supported
/// (RSA, EC P-256/P-384, Ed25519) — matching the software loader's coverage.
#[cfg(feature = "pkcs11")]
mod pkcs11 {
    use super::*;
    use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
    use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Session, Pkcs11Signer};
    use std::path::PathBuf;

    /// Configuration identifying a signing key on a PKCS#11 token.
    ///
    /// The token is selected through kryptering's default provider selection
    /// for `module_path`, which accepts exactly one initialized token; the key
    /// pair is selected by its `CKA_LABEL`.
    #[derive(Clone)]
    pub struct Pkcs11KeyConfig {
        /// Path to the PKCS#11 module, e.g. `libsofthsm2.so` /
        /// `libkryoptic_pkcs11.so`.
        pub module_path: PathBuf,
        /// User PIN used to log into the token.
        pub pin: String,
        /// `CKA_LABEL` of the private (and matching public) key object.
        pub key_label: String,
        /// JWS algorithm to sign with and advertise (header `alg` + JWKS).
        pub alg: JwsAlgorithm,
        /// Key id published in JWKS / JWT headers.
        pub kid: Option<String>,
    }

    /// Load a signing key whose private material lives on a PKCS#11 token.
    pub fn signing_key_from_pkcs11(cfg: &Pkcs11KeyConfig) -> Result<SigningKey> {
        let provider = Pkcs11Provider::new(&cfg.module_path)
            .map_err(|e| Error::Crypto(format!("PKCS#11 init failed: {e}")))?;
        let session = provider
            .open_session(&cfg.pin)
            .map_err(|e| Error::Crypto(format!("PKCS#11 login failed: {e}")))?;

        let sig_alg = cfg.alg.to_crypto().map_err(Error::from)?;
        let signer = Pkcs11Signer::new(&session, &cfg.key_label, sig_alg)
            .map_err(|e| Error::Crypto(format!("PKCS#11 signer for {}: {e}", cfg.key_label)))?;

        let public_jwk = public_jwk_from_token(&session, &cfg.key_label, cfg.alg, &cfg.kid)?;

        Ok(SigningKey {
            signer: Arc::new(signer),
            public_jwk,
            alg: cfg.alg,
            kid: cfg.kid.clone(),
        })
    }

    /// Reconstruct the publishable public JWK by reading the public-key object's
    /// attributes from the token and reusing jose's `software_key_to_jwk`.
    fn public_jwk_from_token(
        session: &Pkcs11Session,
        key_label: &str,
        alg: JwsAlgorithm,
        kid: &Option<String>,
    ) -> Result<Jwk> {
        let handle = session
            .find_public_key(key_label)
            .map_err(|e| Error::Crypto(format!("public key {key_label} not found: {e}")))?;

        let sw = match alg {
            JwsAlgorithm::RS256 | JwsAlgorithm::RS384 | JwsAlgorithm::RS512 => {
                rsa_public_from_token(session, handle)?
            }
            JwsAlgorithm::ES256 => ec_public_from_token(session, handle, EcCurve::P256)?,
            JwsAlgorithm::ES384 => ec_public_from_token(session, handle, EcCurve::P384)?,
            JwsAlgorithm::EdDSA => ed25519_public_from_token(session, handle)?,
            other => {
                return Err(Error::Crypto(format!(
                    "unsupported PKCS#11 signing algorithm: {}",
                    other.as_str()
                )))
            }
        };

        // software_key_to_jwk on a public-only key emits no private components.
        let jwk = software_key_to_jwk(&sw).map_err(Error::from)?;
        Ok(public_jwk_from_private(&jwk, alg, kid))
    }

    enum EcCurve {
        P256,
        P384,
    }

    /// Read a single byte-valued attribute from an object.
    fn read_attr(
        session: &Pkcs11Session,
        handle: ObjectHandle,
        ty: AttributeType,
    ) -> Result<Vec<u8>> {
        let guard = session
            .session()
            .lock()
            .map_err(|_| Error::Crypto("PKCS#11 session mutex poisoned".into()))?;
        let attrs = guard
            .get_attributes(handle, &[ty])
            .map_err(|e| Error::Crypto(format!("C_GetAttributeValue failed: {e}")))?;
        match attrs.into_iter().next() {
            Some(Attribute::EcPoint(b))
            | Some(Attribute::Modulus(b))
            | Some(Attribute::PublicExponent(b)) => Ok(b),
            _ => Err(Error::Crypto(format!(
                "attribute {ty:?} missing on token object"
            ))),
        }
    }

    fn rsa_public_from_token(session: &Pkcs11Session, handle: ObjectHandle) -> Result<SoftwareKey> {
        use rsa::pkcs8::EncodePublicKey;

        let n = read_attr(session, handle, AttributeType::Modulus)?;
        let e = read_attr(session, handle, AttributeType::PublicExponent)?;
        let public = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&n),
            rsa::BigUint::from_bytes_be(&e),
        )
        .map_err(|e| Error::Crypto(format!("invalid RSA public key from token: {e}")))?;
        let spki = public
            .to_public_key_der()
            .map_err(|e| Error::Crypto(format!("RSA SPKI encoding failed: {e}")))?;
        SoftwareKey::from_spki_der(KeyAlgorithm::Rsa, spki.as_bytes())
            .map_err(|e| Error::Crypto(format!("RSA public key import failed: {e}")))
    }

    fn ec_public_from_token(
        session: &Pkcs11Session,
        handle: ObjectHandle,
        curve: EcCurve,
    ) -> Result<SoftwareKey> {
        let raw = read_attr(session, handle, AttributeType::EcPoint)?;
        match curve {
            EcCurve::P256 => {
                use p256::pkcs8::EncodePublicKey;

                let vk = parse_ec_point(&raw, p256::ecdsa::VerifyingKey::from_sec1_bytes)
                    .map_err(|e| Error::Crypto(format!("invalid P-256 point from token: {e}")))?;
                let spki = vk
                    .to_public_key_der()
                    .map_err(|e| Error::Crypto(format!("P-256 SPKI encoding failed: {e}")))?;
                SoftwareKey::from_spki_der(
                    KeyAlgorithm::Ec(KrypteringEcCurve::P256),
                    spki.as_bytes(),
                )
                .map_err(|e| Error::Crypto(format!("P-256 public key import failed: {e}")))
            }
            EcCurve::P384 => {
                use p384::pkcs8::EncodePublicKey;

                let vk = parse_ec_point(&raw, p384::ecdsa::VerifyingKey::from_sec1_bytes)
                    .map_err(|e| Error::Crypto(format!("invalid P-384 point from token: {e}")))?;
                let spki = vk
                    .to_public_key_der()
                    .map_err(|e| Error::Crypto(format!("P-384 SPKI encoding failed: {e}")))?;
                SoftwareKey::from_spki_der(
                    KeyAlgorithm::Ec(KrypteringEcCurve::P384),
                    spki.as_bytes(),
                )
                .map_err(|e| Error::Crypto(format!("P-384 public key import failed: {e}")))
            }
        }
    }

    fn ed25519_public_from_token(
        session: &Pkcs11Session,
        handle: ObjectHandle,
    ) -> Result<SoftwareKey> {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let raw = read_attr(session, handle, AttributeType::EcPoint)?;
        // Try the raw 32-byte key first; only if that doesn't fit, treat the
        // bytes as a DER OCTET STRING wrapping the key (Edwards `CKA_EC_POINT`).
        let bytes: [u8; 32] = <[u8; 32]>::try_from(raw.as_slice())
            .ok()
            .or_else(|| unwrap_der_octet_string(&raw).and_then(|i| <[u8; 32]>::try_from(i).ok()))
            .ok_or_else(|| Error::Crypto("Ed25519 public key is not 32 bytes".into()))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| Error::Crypto(format!("invalid Ed25519 key from token: {e}")))?;
        let spki = vk
            .to_public_key_der()
            .map_err(|e| Error::Crypto(format!("Ed25519 SPKI encoding failed: {e}")))?;
        SoftwareKey::from_spki_der(KeyAlgorithm::Ed25519, spki.as_bytes())
            .map_err(|e| Error::Crypto(format!("Ed25519 public key import failed: {e}")))
    }

    /// Parse a SEC1 EC point from a `CKA_EC_POINT` value using `parse`.
    ///
    /// `CKA_EC_POINT` is meant to be the DER encoding of an ANSI X9.62 `ECPoint`
    /// — an OCTET STRING wrapping the raw point — but some tokens return the raw
    /// point directly. Both an uncompressed point and a DER OCTET STRING begin
    /// with `0x04`, so we cannot tell them apart by inspection. Instead we try
    /// the bytes as-is first (the SEC1 parser validates length and curve
    /// membership) and only fall back to stripping a DER wrapper if that fails.
    /// This avoids misreading a raw point whose first coordinate byte happens to
    /// look like a DER length.
    fn parse_ec_point<T, E>(
        raw: &[u8],
        parse: impl Fn(&[u8]) -> std::result::Result<T, E>,
    ) -> Result<T> {
        if let Ok(vk) = parse(raw) {
            return Ok(vk);
        }
        if let Some(inner) = unwrap_der_octet_string(raw) {
            if let Ok(vk) = parse(inner) {
                return Ok(vk);
            }
        }
        Err(Error::Crypto("not a valid SEC1 EC point".into()))
    }

    /// If `raw` is a complete DER OCTET STRING (tag `0x04`) whose length field
    /// exactly covers the remaining bytes, return the wrapped contents; else
    /// `None`. Callers must only use this as a fallback after trying to parse
    /// `raw` directly, since a raw uncompressed EC point also starts with `0x04`
    /// and could coincidentally satisfy this shape.
    fn unwrap_der_octet_string(raw: &[u8]) -> Option<&[u8]> {
        if raw.len() < 2 || raw[0] != 0x04 {
            return None;
        }
        let (len, hdr) = match raw[1] {
            n if n < 0x80 => (n as usize, 2),
            0x81 if raw.len() >= 3 => (raw[2] as usize, 3),
            0x82 if raw.len() >= 4 => (((raw[2] as usize) << 8) | raw[3] as usize, 4),
            _ => return None,
        };
        (raw.len() == hdr + len).then(|| &raw[hdr..])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_ec_point_accepts_raw_and_der_wrapped() {
            // A real uncompressed P-256 point (65 bytes, leading 0x04) derived
            // from a fixed nonzero scalar — no RNG needed.
            let mut scalar = [0u8; 32];
            scalar[31] = 1;
            let sk = p256::SecretKey::from_slice(&scalar).unwrap();
            let raw = sk.public_key().to_sec1_bytes(); // uncompressed
            assert_eq!(raw[0], 0x04);
            assert_eq!(raw.len(), 65);

            // Raw form parses.
            parse_ec_point(&raw, p256::ecdsa::VerifyingKey::from_sec1_bytes).unwrap();

            // DER OCTET STRING wrapped form (0x04 0x41 <65 bytes>) parses too.
            let mut der = vec![0x04, raw.len() as u8];
            der.extend_from_slice(&raw);
            parse_ec_point(&der, p256::ecdsa::VerifyingKey::from_sec1_bytes).unwrap();
        }

        #[test]
        fn unwrap_only_strips_complete_octet_string() {
            // Well-formed: tag 0x04, len 3, three content bytes.
            assert_eq!(
                unwrap_der_octet_string(&[0x04, 0x03, 1, 2, 3]),
                Some(&[1u8, 2, 3][..])
            );
            // Length does not cover the buffer -> not a wrapper.
            assert_eq!(unwrap_der_octet_string(&[0x04, 0x03, 1, 2]), None);
            // A raw 65-byte point is not treated as a wrapper in this test (len byte is 0xAB,
            // so it cannot equal the 63-byte content length that would be required here).
            let mut pt = vec![0x04u8];
            pt.extend(std::iter::repeat_n(0xAB, 64));
            assert_eq!(unwrap_der_octet_string(&pt), None);
        }
    }
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
        assert_eq!(key.alg(), JwsAlgorithm::ES256);
        assert_eq!(key.kid(), Some("k1"));
        let pubjwk = key.public_jwk();
        assert!(pubjwk.d.is_none());
        assert_eq!(pubjwk.kid.as_deref(), Some("k1"));
    }

    #[test]
    fn sign_with_loaded_key() {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        let key = signing_key_from_jwk_json(&jwk.to_json().unwrap(), None, Some("k1")).unwrap();

        // Sign through the signer trait object (software- or HSM-agnostic).
        let mut header = jose_rs::JoseHeader::jwt_for_alg(key.alg());
        header.kid = key.kid().map(|k| k.to_string());
        let claims = jose_rs::jwt::Claims {
            iss: Some("issuer".into()),
            ..Default::default()
        };
        let token = jose_rs::jwt::encode(key.signer(), &header, &claims).unwrap();

        // Verify with the public JWK.
        let v = jose_rs::jwt::Validation::new().with_issuer("issuer");
        let decoded = jose_rs::jwt::decode_with_jwk(&key.public_jwk(), &token, &v).unwrap();
        assert_eq!(decoded.iss.as_deref(), Some("issuer"));
    }
}
