//! Thin helpers over jose-rs for the OIDC/federation flows.

use crate::error::{Error, Result};
use crate::keys::SigningKey;
use jose_rs::jwk::{Jwk, JwkSet};
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;

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
