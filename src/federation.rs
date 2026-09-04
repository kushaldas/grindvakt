//! OpenID Federation 1.0 support.
//!
//! Entity statements (build + verify), trust-chain resolution by delegating to a
//! trust anchor's `federation_resolve_endpoint`, and metadata-policy operators.
//! Signing/verification all go through `jose-rs`; outbound fetches go through the
//! injected [`crate::HttpClient`].

use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::keys::SigningKey;
use crate::util::now_secs;
use jose_rs::jwk::JwkSet;
use jose_rs::jwt::{Claims, Validation};
use jose_rs::JoseHeader;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// The JWT `typ` for federation entity statements.
pub const ENTITY_STATEMENT_TYP: &str = "entity-statement+jwt";

/// The JWT `typ` for a Resolve Response returned by a trust anchor's
/// `federation_resolve_endpoint` (OpenID Federation 1.0 §8.6). Distinct from an
/// entity statement: the metadata is already resolved and a `trust_chain` is
/// included.
pub const RESOLVE_RESPONSE_TYP: &str = "resolve-response+jwt";

/// The JWT `typ` for a signed JWK Set document published at `signed_jwks_uri`
/// (OpenID Federation 1.1 §5.2.1).
pub const JWK_SET_TYP: &str = "jwk-set+jwt";

/// Pre-distributed trust anchors: entity_id -> trusted JWKS.
pub type TrustAnchors = HashMap<String, JwkSet>;

/// A successful resolve response, bound to a configured trust anchor.
#[derive(Debug, Clone)]
pub struct ResolvedEntity {
    pub issuer: String,
    pub subject: String,
    pub metadata: Value,
    /// Federation Entity signing keys from the subject's Entity Configuration at
    /// the start of the returned trust chain.
    pub subject_jwks: JwkSet,
    /// The resolve response's `exp` (seconds since epoch) - how long the trust
    /// anchor vouches for the resolved metadata. Callers can use it to bound
    /// caching.
    pub exp: Option<u64>,
}

/// Read a seconds-since-epoch claim that may be an integer or (as some
/// implementations emit) a fractional float.
pub(crate) fn claim_secs(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_f64().map(|f| f as u64))
}

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
        c.extra.insert(
            "authority_hints".to_string(),
            serde_json::to_value(authority_hints)?,
        );
    }
    c.extra.insert("metadata".to_string(), metadata);
    if !trust_marks.is_empty() {
        c.extra.insert(
            "trust_marks".to_string(),
            Value::Array(trust_marks.to_vec()),
        );
    }

    let mut header = JoseHeader::for_alg(key.alg());
    header.kid = key.kid().map(|k| k.to_string());
    header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
    jose_rs::jwt::encode(key.signer(), &header, &c).map_err(Error::from)
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
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
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
    // exp is mandatory (OpenID Federation 1.0 §3.1 / §8.6): a statement that
    // never expires could be replayed indefinitely.
    let validation = Validation::new().with_typ(typ).require_exp();
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
) -> Result<ResolvedEntity> {
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
) -> Result<ResolvedEntity> {
    // 1. Fetch + verify the trust anchor's own entity configuration.
    let ec_jwt = fetch_entity_configuration(http, ta_id).await?;
    let ec = verify(&ec_jwt, ta_keys)?;
    let self_issued = verify_self_signed(&ec_jwt)?;
    if ec.iss() != Some(ta_id) || ec.sub() != Some(ta_id) {
        return Err(Error::Authn(format!(
            "trust anchor {ta_id} entity configuration is not issued for the configured entity id"
        )));
    }
    if self_issued.iss() != Some(ta_id) || self_issued.sub() != Some(ta_id) {
        return Err(Error::Authn(format!(
            "trust anchor {ta_id} entity configuration is not self-issued"
        )));
    }

    // 2. Find the trust anchor's resolve endpoint.
    let resolve_ep = ec
        .metadata("federation_entity")
        .and_then(|m| m.get("federation_resolve_endpoint").cloned())
        .and_then(|v| v.as_str().map(String::from))
        .ok_or_else(|| {
            Error::Internal(format!(
                "trust anchor {ta_id} has no federation_resolve_endpoint"
            ))
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
    extract_resolved_entity(&resolved, ta_id, sub, ta_keys)
}

fn extract_resolved_entity(
    resolved: &EntityStatement,
    ta_id: &str,
    sub: &str,
    ta_keys: &JwkSet,
) -> Result<ResolvedEntity> {
    if resolved.iss() != Some(ta_id) {
        return Err(Error::Authn("resolve response issuer mismatch".into()));
    }
    if resolved.sub() != Some(sub) {
        return Err(Error::Authn("resolve response sub mismatch".into()));
    }

    let chain = resolved
        .claims
        .get("trust_chain")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Authn("resolve response has no trust_chain".into()))?;
    let subject_ec = validate_trust_chain(chain, sub, ta_id, ta_keys)?;

    let metadata = resolved
        .claims
        .get("metadata")
        .cloned()
        .ok_or_else(|| Error::Authn("resolve response has no metadata".into()))?;

    Ok(ResolvedEntity {
        issuer: ta_id.to_string(),
        subject: sub.to_string(),
        metadata,
        subject_jwks: subject_ec.jwks()?,
        exp: resolved.claims.get("exp").and_then(claim_secs),
    })
}

fn validate_trust_chain(
    chain: &[Value],
    sub: &str,
    ta_id: &str,
    ta_keys: &JwkSet,
) -> Result<EntityStatement> {
    let tokens: Vec<&str> = chain
        .iter()
        .map(|v| {
            v.as_str().ok_or_else(|| {
                Error::Authn("resolve response trust_chain contains a non-string".into())
            })
        })
        .collect::<Result<_>>()?;
    if tokens.is_empty() {
        return Err(Error::Authn("resolve response trust_chain is empty".into()));
    }

    let unverified: Vec<EntityStatement> = tokens
        .iter()
        .map(|token| decode_unverified(token))
        .collect::<Result<_>>()?;
    for (idx, stmt) in unverified.iter().enumerate() {
        validate_statement_claims(stmt, &format!("trust_chain[{idx}]"))?;
    }

    let first = unverified
        .first()
        .expect("non-empty trust chain was checked");
    if first.iss() != Some(sub) || first.sub() != Some(sub) {
        return Err(Error::Authn(
            "resolve response trust_chain does not start with the subject entity configuration"
                .into(),
        ));
    }

    let last = unverified
        .last()
        .expect("non-empty trust chain was checked");
    if last.iss() != Some(ta_id) || last.sub() != Some(ta_id) {
        return Err(Error::Authn(
            "resolve response trust_chain does not end with the selected trust anchor".into(),
        ));
    }

    for idx in 0..unverified.len().saturating_sub(1) {
        if unverified[idx].iss() != unverified[idx + 1].sub() {
            return Err(Error::Authn(format!(
                "trust_chain[{idx}] issuer does not match trust_chain[{}] subject",
                idx + 1
            )));
        }
    }

    let subject_ec = verify_self_signed(tokens[0])?;
    for idx in 0..unverified.len().saturating_sub(1) {
        let signer_jwks = unverified[idx + 1].jwks()?;
        verify(tokens[idx], &signer_jwks).map_err(|e| {
            Error::Authn(format!(
                "trust_chain[{idx}] signature failed against trust_chain[{}] keys: {e}",
                idx + 1
            ))
        })?;
    }

    let ta_token = tokens[tokens.len() - 1];
    let ta_ec = verify(ta_token, ta_keys)?;
    verify_self_signed(ta_token)?;
    if ta_ec.iss() != Some(ta_id) || ta_ec.sub() != Some(ta_id) {
        return Err(Error::Authn(
            "resolve response trust_chain trust anchor mismatch".into(),
        ));
    }

    Ok(subject_ec)
}

fn validate_statement_claims(stmt: &EntityStatement, label: &str) -> Result<()> {
    let iss = stmt.iss().filter(|s| !s.is_empty());
    let sub = stmt.sub().filter(|s| !s.is_empty());
    if iss.is_none() || sub.is_none() {
        return Err(Error::Authn(format!("{label} missing iss/sub")));
    }
    let iat = stmt
        .claims
        .get("iat")
        .and_then(claim_secs)
        .ok_or_else(|| Error::Authn(format!("{label} missing iat")))?;
    let exp = stmt
        .claims
        .get("exp")
        .and_then(claim_secs)
        .ok_or_else(|| Error::Authn(format!("{label} missing exp")))?;
    let now = now_secs();
    if iat > now {
        return Err(Error::Authn(format!("{label} iat is in the future")));
    }
    if exp <= now {
        return Err(Error::Authn(format!("{label} has expired")));
    }
    Ok(())
}

/// Resolve an Entity Type key set using the representations from OpenID
/// Federation 1.1 §5.2.1.
pub async fn entity_metadata_jwks(
    http: &Arc<dyn HttpClient>,
    metadata: &Value,
    subject_entity_id: &str,
    subject_fed_jwks: &JwkSet,
) -> Result<JwkSet> {
    if let Some(jwks) = metadata.get("jwks") {
        return serde_json::from_value(jwks.clone()).map_err(Error::from);
    }
    if let Some(uri) = metadata.get("signed_jwks_uri").and_then(|v| v.as_str()) {
        return fetch_signed_jwks(http, uri, subject_entity_id, subject_fed_jwks).await;
    }
    if let Some(uri) = metadata.get("jwks_uri").and_then(|v| v.as_str()) {
        crate::rp::validate_service_endpoint_for_issuer("jwks_uri", uri, subject_entity_id)?;
        let resp = http.get(uri).await?;
        if resp.status != 200 {
            return Err(Error::Internal(format!(
                "jwks fetch failed ({})",
                resp.status
            )));
        }
        return JwkSet::from_json(&resp.text()).map_err(Error::from);
    }
    Err(Error::Authn(
        "metadata has neither jwks, signed_jwks_uri, nor jwks_uri".into(),
    ))
}

/// Fetch and verify a signed JWK Set document referenced by `signed_jwks_uri`.
pub async fn fetch_signed_jwks(
    http: &Arc<dyn HttpClient>,
    signed_jwks_uri: &str,
    subject_entity_id: &str,
    subject_fed_jwks: &JwkSet,
) -> Result<JwkSet> {
    // This function is public and can be called without first parsing an
    // entity metadata document, so enforce the endpoint policy at the direct
    // network boundary as well.
    crate::rp::validate_service_endpoint_for_issuer(
        "signed_jwks_uri",
        signed_jwks_uri,
        subject_entity_id,
    )?;
    let resp = http.get(signed_jwks_uri).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "signed_jwks_uri fetch failed ({})",
            resp.status
        )));
    }
    if let Some(content_type) = resp.content_type.as_deref() {
        if !content_type.starts_with("application/jwk-set+jwt") {
            return Err(Error::Authn(format!(
                "signed_jwks_uri returned unexpected content type {content_type}"
            )));
        }
    }

    let claims = crate::jwt::verify_with_jwks(
        subject_fed_jwks,
        &resp.text(),
        &Validation::new().with_typ(JWK_SET_TYP),
    )?;
    if claims.sub.as_deref() != Some(subject_entity_id) {
        return Err(Error::Authn("signed_jwks_uri sub mismatch".into()));
    }
    if claims.iss.as_deref().is_none() {
        return Err(Error::Authn("signed_jwks_uri response missing iss".into()));
    }

    let keys = claims
        .extra
        .get("keys")
        .cloned()
        .ok_or_else(|| Error::Authn("signed_jwks_uri response has no keys".into()))?;
    Ok(JwkSet {
        keys: serde_json::from_value(keys)?,
    })
}

// ── Collection / listing endpoint (OP discovery) ────────────────────────────

/// One entity returned by a trust anchor's collection (listing) endpoint, with
/// its UI presentation already flattened for a discovery page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionEntity {
    /// The entity identifier (used as the OP/IdP to authenticate against).
    pub entity_id: String,
    /// A human-friendly name: the entity's `openid_provider` display name,
    /// else its `federation_entity` display name, else the entity id.
    pub display_name: String,
    /// An optional logo URL for the discovery page.
    pub logo_uri: Option<String>,
}

/// Fetch a list of federation entities of a given type from a trust anchor's
/// collection endpoint (e.g. a SUNET/inmor `…/collection`), flattening their
/// UI info for a discovery page. `entity_type` is the federation entity-type
/// filter, e.g. `"openid_provider"`.
///
/// The endpoint is expected to answer with
/// `{"entities": [{"entity_id": "...", "ui_infos": {"openid_provider": {...},
/// "federation_entity": {...}}}, ...]}`.
pub async fn fetch_collection(
    http: &Arc<dyn HttpClient>,
    collection_endpoint: &str,
    entity_type: &str,
) -> Result<Vec<CollectionEntity>> {
    let url = format!(
        "{}{}entity_type={}",
        collection_endpoint,
        if collection_endpoint.contains('?') {
            '&'
        } else {
            '?'
        },
        urlenc(entity_type),
    );
    let resp = http.get(&url).await?;
    if resp.status != 200 {
        return Err(Error::Internal(format!(
            "collection endpoint {url} returned {}",
            resp.status
        )));
    }
    let body: Value = resp.json()?;
    Ok(parse_collection(&body, entity_type))
}

/// Parse a collection-endpoint response body into [`CollectionEntity`] list.
/// Separated from the fetch so it can be unit-tested without HTTP. Entries
/// without an `entity_id`, or that do not advertise `entity_type`, are skipped.
pub fn parse_collection(body: &Value, entity_type: &str) -> Vec<CollectionEntity> {
    let Some(entities) = body.get("entities").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let ui_name = |entity: &Value, kind: &str| -> Option<String> {
        entity
            .get("ui_infos")
            .and_then(|u| u.get(kind))
            .and_then(|m| m.get("display_name"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let ui_logo = |entity: &Value, kind: &str| -> Option<String> {
        entity
            .get("ui_infos")
            .and_then(|u| u.get(kind))
            .and_then(|m| m.get("logo_uri"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };

    entities
        .iter()
        .filter(|entity| {
            // Per the entity collection spec, an entity_type-filtered response
            // must include only entities that explicitly advertise one of the
            // requested entity types.
            match entity.get("entity_types").and_then(|v| v.as_array()) {
                Some(types) => types.iter().any(|t| t.as_str() == Some(entity_type)),
                None => false,
            }
        })
        .filter_map(|entity| {
            let entity_id = entity.get("entity_id").and_then(|v| v.as_str())?;
            if entity_id.is_empty() {
                return None;
            }
            let display_name = ui_name(entity, entity_type)
                .or_else(|| ui_name(entity, "federation_entity"))
                .unwrap_or_else(|| entity_id.to_string());
            let logo_uri =
                ui_logo(entity, entity_type).or_else(|| ui_logo(entity, "federation_entity"));
            Some(CollectionEntity {
                entity_id: entity_id.to_string(),
                display_name,
                logo_uri,
            })
        })
        .collect()
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
    use std::sync::Mutex;

    fn key(kid: &str) -> SigningKey {
        let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
        jwk.alg = Some("ES256".into());
        signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some(kid)).unwrap()
    }

    struct RecordingHttp {
        get_urls: Mutex<Vec<String>>,
        response: crate::http::HttpFetchResponse,
    }

    #[async_trait::async_trait]
    impl HttpClient for RecordingHttp {
        async fn get(&self, url: &str) -> Result<crate::http::HttpFetchResponse> {
            self.get_urls.lock().unwrap().push(url.to_string());
            Ok(self.response.clone())
        }

        async fn post_form(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            Err(Error::Internal("unexpected POST".into()))
        }
    }

    #[tokio::test]
    async fn entity_jwks_endpoints_reject_raw_controls_before_fetch() {
        let subject_jwks = key("subject").to_public_jwks();
        let recording = Arc::new(RecordingHttp {
            get_urls: Mutex::new(Vec::new()),
            response: crate::http::HttpFetchResponse {
                status: 200,
                body: serde_json::to_vec(&subject_jwks).unwrap(),
                content_type: Some("application/json".into()),
            },
        });
        let http: Arc<dyn HttpClient> = recording.clone();
        let unsafe_uri = "https://op.example/jwks\r\nX-Test: injected";

        for field in ["jwks_uri", "signed_jwks_uri"] {
            let metadata = serde_json::json!({ (field): unsafe_uri });
            assert!(
                entity_metadata_jwks(&http, &metadata, "https://op.example", &subject_jwks)
                    .await
                    .is_err(),
                "unsafe {field} must be rejected"
            );
        }
        assert!(
            fetch_signed_jwks(&http, unsafe_uri, "https://op.example", &subject_jwks)
                .await
                .is_err(),
            "direct signed_jwks_uri fetch must validate before HTTP"
        );
        assert!(recording.get_urls.lock().unwrap().is_empty());

        let safe_uri = "https://op.example/jwks?tenant=one";
        let fetched = entity_metadata_jwks(
            &http,
            &serde_json::json!({ "jwks_uri": safe_uri }),
            "https://op.example",
            &subject_jwks,
        )
        .await
        .expect("valid HTTPS jwks_uri must still be fetched");
        assert_eq!(fetched.keys.len(), subject_jwks.keys.len());
        assert_eq!(
            recording.get_urls.lock().unwrap().as_slice(),
            &[safe_uri.to_string()]
        );
    }

    #[tokio::test]
    async fn remote_federation_entity_cannot_redirect_jwks_fetch_to_loopback_http() {
        let subject_jwks = key("subject").to_public_jwks();
        let recording = Arc::new(RecordingHttp {
            get_urls: Mutex::new(Vec::new()),
            response: crate::http::HttpFetchResponse {
                status: 200,
                body: serde_json::to_vec(&subject_jwks).unwrap(),
                content_type: Some("application/json".into()),
            },
        });
        let http: Arc<dyn HttpClient> = recording.clone();
        let local_uri = "http://127.0.0.1:8080/jwks";

        for field in ["jwks_uri", "signed_jwks_uri"] {
            let metadata = serde_json::json!({ (field): local_uri });
            assert!(
                entity_metadata_jwks(&http, &metadata, "https://remote.example", &subject_jwks,)
                    .await
                    .is_err(),
                "remote entity must not authorize loopback HTTP {field}"
            );
        }
        assert!(
            fetch_signed_jwks(&http, local_uri, "https://remote.example", &subject_jwks,)
                .await
                .is_err()
        );
        assert!(
            recording.get_urls.lock().unwrap().is_empty(),
            "rejected loopback endpoints must not be fetched"
        );

        entity_metadata_jwks(
            &http,
            &serde_json::json!({ "jwks_uri": local_uri }),
            "http://localhost:8080",
            &subject_jwks,
        )
        .await
        .expect("loopback development entity may use a loopback HTTP endpoint");
        assert_eq!(
            recording.get_urls.lock().unwrap().as_slice(),
            &[local_uri.to_string()]
        );
    }

    fn subordinate_statement(
        key: &SigningKey,
        iss: &str,
        sub: &str,
        subject_jwks: &JwkSet,
    ) -> String {
        let now = crate::util::now_secs();
        let mut c = Claims::default();
        c.iss = Some(iss.to_string());
        c.sub = Some(sub.to_string());
        c.iat = Some(now);
        c.exp = Some(now + 3600);
        c.extra.insert(
            "jwks".to_string(),
            serde_json::to_value(subject_jwks).unwrap(),
        );
        let mut header = JoseHeader::for_alg(key.alg());
        header.kid = key.kid().map(str::to_string);
        header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
        jose_rs::jwt::encode(key.signer(), &header, &c).unwrap()
    }

    fn resolve_response(
        key: &SigningKey,
        issuer: &str,
        subject: &str,
        chain: Vec<String>,
    ) -> EntityStatement {
        let now = crate::util::now_secs();
        let mut c = Claims::default();
        c.iss = Some(issuer.to_string());
        c.sub = Some(subject.to_string());
        c.iat = Some(now);
        c.exp = Some(now + 3600);
        c.extra.insert(
            "metadata".to_string(),
            serde_json::json!({ "openid_relying_party": { "client_id": subject } }),
        );
        c.extra
            .insert("trust_chain".to_string(), serde_json::json!(chain));
        let mut header = JoseHeader::for_alg(key.alg());
        header.kid = key.kid().map(str::to_string);
        header.typ = Some(RESOLVE_RESPONSE_TYP.to_string());
        let jwt = jose_rs::jwt::encode(key.signer(), &header, &c).unwrap();
        verify_typed(&jwt, &key.to_public_jwks(), RESOLVE_RESPONSE_TYP).unwrap()
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

    /// Regression: entity statements without `exp` must be rejected (OpenID
    /// Federation 1.0 §3.1) — a statement that never expires could otherwise be
    /// replayed indefinitely. Applies equally to trust-anchor entity
    /// configurations and resolve responses (`verify_typed`).
    #[test]
    fn entity_statement_without_exp_is_rejected() {
        let k = key("fed-1");
        let mut c = Claims::default();
        c.iss = Some("https://op.example.com".into());
        c.sub = Some("https://op.example.com".into());
        c.iat = Some(crate::util::now_secs());
        c.extra.insert(
            "jwks".to_string(),
            serde_json::to_value(k.to_public_jwks()).unwrap(),
        );
        let mut header = JoseHeader::for_alg(k.alg());
        header.kid = k.kid().map(str::to_string);
        header.typ = Some(ENTITY_STATEMENT_TYP.to_string());
        let token = jose_rs::jwt::encode(k.signer(), &header, &c).unwrap();

        assert!(
            verify(&token, &k.to_public_jwks()).is_err(),
            "entity statement without exp must be rejected"
        );
        assert!(
            verify_typed(&token, &k.to_public_jwks(), ENTITY_STATEMENT_TYP).is_err(),
            "verify_typed must require exp"
        );
    }

    #[test]
    fn resolve_response_trust_chain_is_validated_end_to_end() {
        let subject_key = key("rp");
        let ta_key = key("ta");
        let subject = "https://rp.example.com";
        let ta = "https://ta.example.com";
        let subject_ec = build_entity_configuration(
            &subject_key,
            subject,
            &subject_key.to_public_jwks(),
            &[ta.to_string()],
            serde_json::json!({ "openid_relying_party": { "client_id": subject } }),
            &[],
            3600,
        )
        .unwrap();
        let ta_statement =
            subordinate_statement(&ta_key, ta, subject, &subject_key.to_public_jwks());
        let ta_ec = build_entity_configuration(
            &ta_key,
            ta,
            &ta_key.to_public_jwks(),
            &[],
            serde_json::json!({
                "federation_entity": {
                    "federation_resolve_endpoint": "https://ta.example.com/resolve"
                }
            }),
            &[],
            3600,
        )
        .unwrap();

        let resolved = resolve_response(
            &ta_key,
            ta,
            subject,
            vec![subject_ec.clone(), ta_statement, ta_ec.clone()],
        );
        let entity =
            extract_resolved_entity(&resolved, ta, subject, &ta_key.to_public_jwks()).unwrap();
        assert_eq!(entity.subject, subject);
        assert_eq!(
            entity.subject_jwks.keys.len(),
            subject_key.to_public_jwks().keys.len()
        );

        let attacker = key("attacker");
        let bad_statement =
            subordinate_statement(&attacker, ta, subject, &subject_key.to_public_jwks());
        let bad_resolved =
            resolve_response(&ta_key, ta, subject, vec![subject_ec, bad_statement, ta_ec]);
        assert!(
            extract_resolved_entity(&bad_resolved, ta, subject, &ta_key.to_public_jwks()).is_err(),
            "subordinate statements must verify against the next entity's jwks"
        );
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
        assert_eq!(
            metadata["client_registration_types"],
            serde_json::json!(["automatic"])
        );
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

    #[test]
    fn parse_collection_flattens_ui_with_fallbacks() {
        // Mirrors a SUNET/inmor `…/collection?entity_type=openid_provider`
        // response: per-type UI with display_name/logo fallbacks.
        let body = serde_json::json!({
            "entities": [
                {
                    // openid_provider UI is empty -> fall back to federation_entity.
                    "entity_id": "https://op-a.example",
                    "entity_types": ["openid_provider", "federation_entity"],
                    "ui_infos": {
                        "federation_entity": { "display_name": "OP A Org", "logo_uri": "https://op-a.example/logo.svg" },
                        "openid_provider": { "display_name": null, "logo_uri": null }
                    }
                },
                {
                    // openid_provider UI wins when present.
                    "entity_id": "https://op-b.example",
                    "entity_types": ["openid_provider"],
                    "ui_infos": {
                        "openid_provider": { "display_name": "OP B", "logo_uri": "https://op-b.example/b.png" }
                    }
                },
                {
                    // No UI at all -> display_name defaults to the entity id.
                    "entity_id": "https://op-c.example",
                    "entity_types": ["openid_provider"]
                },
                {
                    // Wrong entity type -> filtered out.
                    "entity_id": "https://rp.example",
                    "entity_types": ["openid_relying_party"],
                    "ui_infos": { "openid_relying_party": { "display_name": "An RP" } }
                }
            ]
        });

        let ops = parse_collection(&body, "openid_provider");
        assert_eq!(
            ops,
            vec![
                CollectionEntity {
                    entity_id: "https://op-a.example".into(),
                    display_name: "OP A Org".into(),
                    logo_uri: Some("https://op-a.example/logo.svg".into()),
                },
                CollectionEntity {
                    entity_id: "https://op-b.example".into(),
                    display_name: "OP B".into(),
                    logo_uri: Some("https://op-b.example/b.png".into()),
                },
                CollectionEntity {
                    entity_id: "https://op-c.example".into(),
                    display_name: "https://op-c.example".into(),
                    logo_uri: None,
                },
            ]
        );
    }

    #[test]
    fn claim_secs_handles_integer_and_fractional_values() {
        // Some federation software (e.g. realta) emits fractional exp/iat.
        assert_eq!(
            claim_secs(&serde_json::json!(1812696063u64)),
            Some(1812696063)
        );
        assert_eq!(
            claim_secs(&serde_json::json!(1812696063.17286)),
            Some(1812696063)
        );
        assert_eq!(claim_secs(&serde_json::json!("not a number")), None);
        assert_eq!(claim_secs(&serde_json::json!(null)), None);
    }

    #[test]
    fn parse_collection_handles_missing_entities() {
        assert!(parse_collection(&serde_json::json!({}), "openid_provider").is_empty());
        assert!(
            parse_collection(&serde_json::json!({ "entities": [] }), "openid_provider").is_empty()
        );
    }

    #[test]
    fn parse_collection_requires_explicit_entity_type_membership() {
        let body = serde_json::json!({
            "entities": [
                {
                    "entity_id": "https://typed.example",
                    "entity_types": ["openid_provider"]
                },
                {
                    "entity_id": "https://untyped.example",
                    "ui_infos": {
                        "openid_provider": { "display_name": "Untyped OP" }
                    }
                }
            ]
        });

        let ops = parse_collection(&body, "openid_provider");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].entity_id, "https://typed.example");
    }
}
