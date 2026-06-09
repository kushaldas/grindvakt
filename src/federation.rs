//! OpenID Federation 1.0 support.
//!
//! Entity statements (build + verify), trust-chain resolution by delegating to a
//! trust anchor's `federation_resolve_endpoint`, and metadata-policy operators.
//! Signing/verification all go through `jose-rs`; outbound fetches go through the
//! injected [`crate::HttpClient`].

use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::keys::SigningKey;
use crate::util::now_secs;

/// The JWT `typ` for federation entity statements.
pub const ENTITY_STATEMENT_TYP: &str = "entity-statement+jwt";

/// The JWT `typ` for a Resolve Response returned by a trust anchor's
/// `federation_resolve_endpoint` (OpenID Federation 1.0 §8.6). Distinct from an
/// entity statement: the metadata is already resolved and a `trust_chain` is
/// included.
pub const RESOLVE_RESPONSE_TYP: &str = "resolve-response+jwt";

/// Pre-distributed trust anchors: entity_id -> trusted JWKS.
pub type TrustAnchors = HashMap<String, JwkSet>;

/// Build and sign a self-issued Entity Configuration JWT
/// (`iss == sub == entity_id`).
#[allow(clippy::too_many_arguments)]
pub fn build_entity_configuration(
    key: &SigningKey,
    entity_id: &str,
    public_jwks: &JwkSet,
    authority_hints: &[String],
    metadata: Value,
    trust_marks: &[Value],
    lifetime: u64,
) -> Result<String> {
    let now = now_secs();
    let mut c = Claims::default();
    c.iss = Some(entity_id.to_string());
    c.sub = Some(entity_id.to_string());
    c.iat = Some(now);
    c.exp = Some(now + lifetime);
    c.extra
        .insert("jwks".to_string(), serde_json::to_value(public_jwks)?);
    if !authority_hints.is_empty() {
        c.extra
            .insert("authority_hints".to_string(), serde_json::to_value(authority_hints)?);
    }
    c.extra.insert("metadata".to_string(), metadata);
    if !trust_marks.is_empty() {
        c.extra
            .insert("trust_marks".to_string(), Value::Array(trust_marks.to_vec()));
    }

    let mut header = JoseHeader::for_alg(key.alg);
    header.kid = key.kid.clone();
    header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
    jose_rs::jwt::encode_with_jwk(&key.jwk, &header, &c).map_err(Error::from)
}

/// The decoded claims of an entity statement, as a JSON object.
#[derive(Debug, Clone)]
pub struct EntityStatement {
    pub claims: Value,
}

impl EntityStatement {
    pub fn iss(&self) -> Option<&str> {
        self.claims.get("iss").and_then(|v| v.as_str())
    }
    pub fn sub(&self) -> Option<&str> {
        self.claims.get("sub").and_then(|v| v.as_str())
    }
    /// The `jwks` carried in the statement (the subject's federation keys).
    pub fn jwks(&self) -> Result<JwkSet> {
        let jwks = self
            .claims
            .get("jwks")
            .ok_or_else(|| Error::BadRequest("entity statement has no jwks".into()))?;
        serde_json::from_value(jwks.clone()).map_err(Error::from)
    }
    /// A metadata sub-document, e.g. `metadata.openid_provider`.
    pub fn metadata(&self, kind: &str) -> Option<Value> {
        self.claims.get("metadata")?.get(kind).cloned()
    }
    pub fn authority_hints(&self) -> Vec<String> {
        self.claims
            .get("authority_hints")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }
}

/// Decode an entity statement without verifying its signature (inspection only).
pub fn decode_unverified(token: &str) -> Result<EntityStatement> {
    let claims = crate::jwt::peek_claims_unverified(token)?;
    let value = serde_json::to_value(&claims)?;
    Ok(EntityStatement { claims: value })
}

/// Verify an entity statement's signature against a JWKS and its `typ`, then
/// return the decoded claims.
pub fn verify(token: &str, jwks: &JwkSet) -> Result<EntityStatement> {
    verify_typed(token, jwks, ENTITY_STATEMENT_TYP)
}

/// Verify a trust-anchor-signed JWT against a JWKS, requiring a specific `typ`
/// header. Entity statements and resolve responses are both TA-signed but carry
/// different `typ` values.
pub fn verify_typed(token: &str, jwks: &JwkSet, typ: &str) -> Result<EntityStatement> {
    let validation = Validation::new().with_typ(typ);
    let claims = crate::jwt::verify_with_jwks(jwks, token, &validation)?;
    let value = serde_json::to_value(&claims)?;
    Ok(EntityStatement { claims: value })
}

/// Verify a self-issued Entity Configuration using the keys it carries
/// (`iss == sub`, signature validates against the embedded `jwks`).
pub fn verify_self_signed(token: &str) -> Result<EntityStatement> {
    let unverified = decode_unverified(token)?;
    if unverified.iss() != unverified.sub() {
        return Err(Error::Authn(
            "entity configuration is not self-issued (iss != sub)".into(),
        ));
    }
    let jwks = unverified.jwks()?;
    verify(token, &jwks)
}

/// Fetch an entity's configuration JWT from its `.well-known/openid-federation`.
pub async fn fetch_entity_configuration(
    http: &Arc<dyn HttpClient>,
    entity_id: &str,
) -> Result<String> {
    let url = format!(
        "{}/.well-known/openid-federation",
        entity_id.trim_end_matches('/')
    );
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "entity config fetch {url} returned {}",
            resp.status
        )));
    }
    Ok(resp.text())
}

/// Resolve a subject entity's metadata by delegating to each configured trust
/// anchor's `federation_resolve_endpoint` (OpenID Federation 1.0 §10). Returns
/// the resolved `metadata` object from the first trust anchor that succeeds.
pub async fn resolve_via_trust_anchors(
    http: &Arc<dyn HttpClient>,
    sub: &str,
    trust_anchors: &TrustAnchors,
) -> Result<Value> {
    let mut last_err: Option<Error> = None;

    for (ta_id, ta_keys) in trust_anchors {
        match resolve_one(http, sub, ta_id, ta_keys).await {
            Ok(metadata) => return Ok(metadata),
            Err(e) => {
                tracing::debug!(trust_anchor = %ta_id, error = %e, "resolve via trust anchor failed");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Authn("no trust anchors configured".into())))
}

async fn resolve_one(
    http: &Arc<dyn HttpClient>,
    sub: &str,
    ta_id: &str,
    ta_keys: &JwkSet,
) -> Result<Value> {
    // 1. Fetch + verify the trust anchor's own entity configuration.
    let ec_jwt = fetch_entity_configuration(http, ta_id).await?;
    let ec = verify(&ec_jwt, ta_keys)?;

    // 2. Find the trust anchor's resolve endpoint.
    let resolve_ep = ec
        .metadata("federation_entity")
        .and_then(|m| m.get("federation_resolve_endpoint").cloned())
        .and_then(|v| v.as_str().map(String::from))
        .ok_or_else(|| {
            Error::Internal(format!("trust anchor {ta_id} has no federation_resolve_endpoint"))
        })?;

    // 3. Call the resolve endpoint.
    let url = format!(
        "{}{}sub={}&trust_anchor={}",
        resolve_ep,
        if resolve_ep.contains('?') { '&' } else { '?' },
        urlenc(sub),
        urlenc(ta_id)
    );
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(Error::Authn(format!(
            "resolve endpoint returned {} for {sub}",
            resp.status
        )));
    }

    // 4. Verify the resolve response (signed by the trust anchor). A resolve
    //    response carries typ=resolve-response+jwt, not entity-statement+jwt.
    let resolved = verify_typed(&resp.text(), ta_keys, RESOLVE_RESPONSE_TYP)?;
    if resolved.sub() != Some(sub) {
        return Err(Error::Authn("resolve response sub mismatch".into()));
    }
    resolved
        .claims
        .get("metadata")
        .cloned()
        .ok_or_else(|| Error::Authn("resolve response has no metadata".into()))
}

// ── Metadata policy (OpenID Federation 1.0 §6) ──────────────────────────────

/// Apply a metadata policy object to a metadata object in place. Supports the
/// `value`, `default`, `add`, `one_of`, `subset_of`, `superset_of` and
/// `essential` operators.
pub fn apply_policy(metadata: &mut Map<String, Value>, policy: &Map<String, Value>) -> Result<()> {
    for (param, ops) in policy {
        let ops = ops
            .as_object()
            .ok_or_else(|| Error::BadRequest(format!("policy for {param} is not an object")))?;

        // value: force.
        if let Some(v) = ops.get("value") {
            metadata.insert(param.clone(), v.clone());
        }
        // default: set if absent.
        if let Some(v) = ops.get("default") {
            metadata.entry(param.clone()).or_insert_with(|| v.clone());
        }
        // add: append to array.
        if let Some(add) = ops.get("add") {
            let entry = metadata
                .entry(param.clone())
                .or_insert_with(|| Value::Array(vec![]));
            if let Some(arr) = entry.as_array_mut() {
                for item in as_array(add) {
                    if !arr.contains(&item) {
                        arr.push(item);
                    }
                }
            }
        }
        // essential: must be present.
        if ops.get("essential").and_then(|v| v.as_bool()) == Some(true)
            && !metadata.contains_key(param)
        {
            return Err(Error::Authn(format!(
                "metadata policy requires essential parameter {param}"
            )));
        }
        // one_of: scalar must be in the list.
        if let Some(allowed) = ops.get("one_of").map(as_array) {
            if let Some(current) = metadata.get(param) {
                if !allowed.contains(current) {
                    return Err(Error::Authn(format!(
                        "metadata {param} not in one_of constraint"
                    )));
                }
            }
        }
        // subset_of: every value must be in the allowed set.
        if let Some(allowed) = ops.get("subset_of").map(as_array) {
            if let Some(current) = metadata.get(param).map(as_array) {
                for v in &current {
                    if !allowed.contains(v) {
                        return Err(Error::Authn(format!(
                            "metadata {param} violates subset_of constraint"
                        )));
                    }
                }
            }
        }
        // superset_of: must contain every required value.
        if let Some(required) = ops.get("superset_of").map(as_array) {
            let current = metadata.get(param).map(as_array).unwrap_or_default();
            for v in &required {
                if !current.contains(v) {
                    return Err(Error::Authn(format!(
                        "metadata {param} violates superset_of constraint"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn as_array(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    }
}

pub(crate) fn urlenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::signing_key_from_jwk_json;

    fn key(kid: &str) -> SigningKey {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some(kid)).unwrap()
    }

    #[test]
    fn entity_configuration_roundtrip() {
        let k = key("fed-1");
        let pub_jwks = k.to_public_jwks();
        let metadata = serde_json::json!({
            "openid_provider": { "issuer": "https://op.example.com" },
            "federation_entity": { "organization_name": "Test OP" }
        });
        let token = build_entity_configuration(
            &k,
            "https://op.example.com",
            &pub_jwks,
            &["https://ta.example.com".to_string()],
            metadata,
            &[],
            3600,
        )
        .unwrap();

        // typ header is set.
        let header = crate::jwt::peek_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some(ENTITY_STATEMENT_TYP));

        // Self-signed verification works.
        let stmt = verify_self_signed(&token).unwrap();
        assert_eq!(stmt.iss(), Some("https://op.example.com"));
        assert_eq!(stmt.sub(), Some("https://op.example.com"));
        assert_eq!(stmt.authority_hints(), vec!["https://ta.example.com"]);
        assert_eq!(
            stmt.metadata("openid_provider").unwrap()["issuer"],
            "https://op.example.com"
        );
    }

    #[test]
    fn verification_fails_with_wrong_keys() {
        let k = key("fed-1");
        let other = key("other");
        let token = build_entity_configuration(
            &k,
            "https://op.example.com",
            &k.to_public_jwks(),
            &[],
            serde_json::json!({}),
            &[],
            3600,
        )
        .unwrap();
        assert!(verify(&token, &other.to_public_jwks()).is_err());
    }

    #[test]
    fn metadata_policy_operators() {
        let mut metadata = serde_json::json!({
            "scopes": ["openid", "email"],
            "subject_type": "public"
        })
        .as_object()
        .unwrap()
        .clone();

        let policy = serde_json::json!({
            "client_registration_types": { "default": ["automatic"] },
            "scopes": { "subset_of": ["openid", "email", "profile"] },
            "subject_type": { "one_of": ["public", "pairwise"] },
            "id_token_signed_response_alg": { "value": "ES256" }
        })
        .as_object()
        .unwrap()
        .clone();

        apply_policy(&mut metadata, &policy).unwrap();
        assert_eq!(metadata["client_registration_types"], serde_json::json!(["automatic"]));
        assert_eq!(metadata["id_token_signed_response_alg"], "ES256");

        // subset violation.
        let mut bad = serde_json::json!({ "scopes": ["openid", "evil"] })
            .as_object()
            .unwrap()
            .clone();
        let p = serde_json::json!({ "scopes": { "subset_of": ["openid"] } })
            .as_object()
            .unwrap()
            .clone();
        assert!(apply_policy(&mut bad, &p).is_err());
    }
}
