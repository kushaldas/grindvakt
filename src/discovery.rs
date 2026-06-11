//! Home-organization discovery for OpenID Federation RPs.
//!
//! Helpers for the (SUNET-proposed) home-organization discovery flow and for
//! OpenID Connect Core §4 Third-Party Initiated Login. A discovery service
//! presents a list of OPs (obtained from a trust anchor's collection endpoint,
//! see [`crate::federation::fetch_collection`]) to the user; the selection is
//! returned to the RP's `initiate_login_uri` as a third-party initiated login.
//!
//! This module is deliberately not re-exported at the crate root: only
//! consumers that participate in the discovery flow reach for
//! `grindvakt::discovery::…` explicitly.
//!
//! - RP side, outgoing call: [`discovery_request_url`] builds the redirect to
//!   the (out-of-band configured) discovery endpoint.
//! - RP side, return call: [`parse_third_party_initiated_login`] validates the
//!   request arriving at the RP's `initiate_login_uri`.
//! - Discovery-service side: [`initiate_login_uri`] /
//!   [`initiate_login_uri_from_resolved`] extract the verified RP's return
//!   endpoint, [`third_party_login_url`] builds the selection link, and
//!   [`promote_hint`] applies the OP-hint promotion rule.

use crate::error::{Error, Result};
use crate::federation::{urlenc, CollectionEntity, ResolvedEntity};
use crate::http::HttpClient;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Validate an OpenID Federation Entity Identifier as accepted on a wire
/// parameter (`entity_id`, `iss`, `hint`): an https URL with a host and no
/// query or fragment.
pub fn validate_entity_id(s: &str) -> Result<()> {
    let url =
        url::Url::parse(s).map_err(|e| Error::BadRequest(format!("invalid entity id: {e}")))?;
    if url.scheme() != "https" {
        return Err(Error::BadRequest("entity id must use https".into()));
    }
    if url.host_str().is_none() {
        return Err(Error::BadRequest("entity id has no host".into()));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::BadRequest(
            "entity id must not contain a query or fragment".into(),
        ));
    }
    Ok(())
}

/// Append a query parameter to a URL that may or may not already have one.
fn push_param(url: &mut String, key: &str, value: &str) {
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(key);
    url.push('=');
    url.push_str(&urlenc(value));
}

// ── RP side ─────────────────────────────────────────────────────────────────

/// Build the URL an RP redirects the browser to in order to start home
/// organization discovery (the *outgoing call*):
/// `<discovery_endpoint>?entity_id=<rp>[&hint=<op>][&target_link_uri=<uri>]`.
///
/// `discovery_endpoint` is the discovery service's absolute endpoint URL.
/// `rp_entity_id` is the RP's own entity identifier; `op_hint` optionally
/// names a preferred OP; `target_link_uri` lets the RP learn where to send the
/// user after login without keeping a session (the discovery service must
/// return it verbatim).
pub fn discovery_request_url(
    discovery_endpoint: &str,
    rp_entity_id: &str,
    op_hint: Option<&str>,
    target_link_uri: Option<&str>,
) -> Result<String> {
    validate_entity_id(rp_entity_id)?;
    if let Some(hint) = op_hint {
        validate_entity_id(hint)?;
    }
    let mut url = url::Url::parse(discovery_endpoint)
        .map_err(|e| Error::BadRequest(format!("invalid discovery endpoint: {e}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("entity_id", rp_entity_id);
        if let Some(hint) = op_hint {
            query.append_pair("hint", hint);
        }
        if let Some(target) = target_link_uri {
            query.append_pair("target_link_uri", target);
        }
    }
    Ok(url.into())
}

/// A parsed and validated Third-Party Initiated Login request (OpenID Connect
/// Core 1.0 §4), as received at the RP's `initiate_login_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThirdPartyInitiatedLogin {
    /// The issuer (OP) the RP should send the authentication request to.
    pub iss: String,
    /// Optional hint about the end-user to be logged in.
    pub login_hint: Option<String>,
    /// Where to send the user after a successful login. The RP MUST verify
    /// this value against its own allowlist before redirecting to it.
    pub target_link_uri: Option<String>,
}

/// Parse the query parameters arriving at an RP's `initiate_login_uri` into a
/// [`ThirdPartyInitiatedLogin`]. `iss` is required and must be a valid https
/// entity identifier.
pub fn parse_third_party_initiated_login(
    params: &BTreeMap<String, String>,
) -> Result<ThirdPartyInitiatedLogin> {
    let iss = params
        .get("iss")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::BadRequest("third-party initiated login is missing iss".into()))?;
    validate_entity_id(iss)?;
    Ok(ThirdPartyInitiatedLogin {
        iss: iss.clone(),
        login_hint: params.get("login_hint").filter(|v| !v.is_empty()).cloned(),
        target_link_uri: params
            .get("target_link_uri")
            .filter(|v| !v.is_empty())
            .cloned(),
    })
}

// ── Discovery-service side ──────────────────────────────────────────────────

/// Extract a verified RP's `initiate_login_uri` from its resolved metadata
/// (`metadata.openid_relying_party.initiate_login_uri`). The URI must be https
/// without a fragment — it is the only place a discovery service ever sends a
/// user, so anything weaker would turn the service into an open redirector.
pub fn initiate_login_uri(metadata: &Value) -> Result<String> {
    let uri = metadata
        .get("openid_relying_party")
        .and_then(|m| m.get("initiate_login_uri"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Authn("relying party metadata has no initiate_login_uri".into()))?;
    let parsed = url::Url::parse(uri)
        .map_err(|e| Error::Authn(format!("invalid initiate_login_uri: {e}")))?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(Error::Authn(
            "initiate_login_uri must be an https URL".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(Error::Authn(
            "initiate_login_uri must not contain a fragment".into(),
        ));
    }
    Ok(uri.to_string())
}

/// [`initiate_login_uri`] over a [`ResolvedEntity`] from
/// [`crate::federation::resolve_via_trust_anchors`].
pub fn initiate_login_uri_from_resolved(entity: &ResolvedEntity) -> Result<String> {
    initiate_login_uri(&entity.metadata)
}

/// Fetch and verify an RP's *self-published* entity configuration
/// (`<entity_id>/.well-known/openid-federation`, self-signed) and extract the
/// `initiate_login_uri` it advertises.
///
/// For discovery services running in an open mode: the RP is not required to
/// chain up to a trust anchor, but the redirect target is still limited to
/// what the entity itself publishes under its own identifier — never a
/// caller-supplied URL.
pub async fn self_published_initiate_login_uri(
    http: &Arc<dyn HttpClient>,
    rp_entity_id: &str,
) -> Result<String> {
    validate_entity_id(rp_entity_id)?;
    let jwt = crate::federation::fetch_entity_configuration(http, rp_entity_id).await?;
    let stmt = crate::federation::verify_self_signed(&jwt)?;
    if stmt.iss() != Some(rp_entity_id) || stmt.sub() != Some(rp_entity_id) {
        return Err(Error::Authn(
            "entity configuration is not issued by the requested entity".into(),
        ));
    }
    let metadata = stmt.claims.get("metadata").cloned().unwrap_or(Value::Null);
    initiate_login_uri(&metadata)
}

/// Build the third-party initiated login URL the user is sent to after
/// selecting an OP (the *return call*):
/// `<initiate_login_uri>?iss=<op>[&login_hint=…][&target_link_uri=…]`.
///
/// `target_link_uri` is attached verbatim (it is only ever appended to a
/// verified `initiate_login_uri`, never used as a redirect target itself).
pub fn third_party_login_url(
    initiate_login_uri: &str,
    op_entity_id: &str,
    login_hint: Option<&str>,
    target_link_uri: Option<&str>,
) -> String {
    let mut url = initiate_login_uri.to_string();
    push_param(&mut url, "iss", op_entity_id);
    if let Some(hint) = login_hint {
        push_param(&mut url, "login_hint", hint);
    }
    if let Some(target) = target_link_uri {
        push_param(&mut url, "target_link_uri", target);
    }
    url
}

/// Compare two entity identifiers, ignoring a trailing slash.
fn entity_id_eq(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// If `hint` names one of the entities, move it to the front of the list — the
/// discovery flow requires a matching OP hint to become the default choice.
/// Returns whether `hint` matched any entity.
pub fn promote_hint(entities: &mut Vec<CollectionEntity>, hint: &str) -> bool {
    match entities
        .iter()
        .position(|e| entity_id_eq(&e.entity_id, hint))
    {
        Some(0) => true,
        Some(pos) => {
            let entity = entities.remove(pos);
            entities.insert(0, entity);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn op(id: &str) -> CollectionEntity {
        CollectionEntity {
            entity_id: id.into(),
            display_name: id.into(),
            logo_uri: None,
        }
    }

    #[test]
    fn entity_id_validation() {
        assert!(validate_entity_id("https://rp.example.com").is_ok());
        assert!(validate_entity_id("https://rp.example.com/oidc").is_ok());
        assert!(validate_entity_id("http://rp.example.com").is_err());
        assert!(validate_entity_id("https://rp.example.com/?x=1").is_err());
        assert!(validate_entity_id("https://rp.example.com/#frag").is_err());
        assert!(validate_entity_id("not a url").is_err());
        assert!(validate_entity_id("javascript:alert(1)").is_err());
    }

    #[test]
    fn discovery_request_url_encodes_params() {
        let url = discovery_request_url(
            "https://discovery.example.com/discovery",
            "https://rp.example.com/oidc",
            Some("https://op.example.com"),
            Some("https://app.example.com/deep?x=1&y=2"),
        )
        .unwrap();
        assert_eq!(
            url,
            "https://discovery.example.com/discovery\
             ?entity_id=https%3A%2F%2Frp.example.com%2Foidc\
             &hint=https%3A%2F%2Fop.example.com\
             &target_link_uri=https%3A%2F%2Fapp.example.com%2Fdeep%3Fx%3D1%26y%3D2"
        );
    }

    #[test]
    fn discovery_request_url_joins_existing_query() {
        let url = discovery_request_url(
            "https://discovery.example.com/?ui=compact",
            "https://rp.example.com",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            url,
            "https://discovery.example.com/?ui=compact&entity_id=https%3A%2F%2Frp.example.com"
        );
    }

    #[test]
    fn discovery_request_url_rejects_invalid_endpoint() {
        assert!(discovery_request_url("not a url", "https://rp.example.com", None, None).is_err());
    }

    #[test]
    fn discovery_request_url_places_query_before_fragment() {
        let url = discovery_request_url(
            "https://discovery.example.com/discovery#chooser",
            "https://rp.example.com",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            url,
            "https://discovery.example.com/discovery?entity_id=https%3A%2F%2Frp.example.com#chooser"
        );
    }

    #[test]
    fn discovery_request_url_rejects_bad_ids() {
        assert!(
            discovery_request_url("https://d.example", "http://rp.example", None, None).is_err()
        );
        assert!(discovery_request_url(
            "https://d.example",
            "https://rp.example",
            Some("not a url"),
            None
        )
        .is_err());
    }

    #[test]
    fn third_party_initiated_login_parsing() {
        let mut params = BTreeMap::new();
        params.insert("iss".to_string(), "https://op.example.com".to_string());
        params.insert(
            "target_link_uri".to_string(),
            "https://app.example.com/x".to_string(),
        );
        let login = parse_third_party_initiated_login(&params).unwrap();
        assert_eq!(login.iss, "https://op.example.com");
        assert_eq!(login.login_hint, None);
        assert_eq!(
            login.target_link_uri.as_deref(),
            Some("https://app.example.com/x")
        );

        // iss is required and must be https.
        assert!(parse_third_party_initiated_login(&BTreeMap::new()).is_err());
        let mut bad = BTreeMap::new();
        bad.insert("iss".to_string(), "http://op.example.com".to_string());
        assert!(parse_third_party_initiated_login(&bad).is_err());
    }

    #[test]
    fn initiate_login_uri_extraction() {
        let metadata = json!({
            "openid_relying_party": {
                "client_name": "Test RP",
                "initiate_login_uri": "https://rp.example.com/initiate"
            }
        });
        assert_eq!(
            initiate_login_uri(&metadata).unwrap(),
            "https://rp.example.com/initiate"
        );

        // Missing, non-https, or fragmented URIs are rejected.
        assert!(initiate_login_uri(&json!({ "openid_relying_party": {} })).is_err());
        assert!(initiate_login_uri(&json!({})).is_err());
        assert!(initiate_login_uri(&json!({
            "openid_relying_party": { "initiate_login_uri": "http://rp.example.com/initiate" }
        }))
        .is_err());
        assert!(initiate_login_uri(&json!({
            "openid_relying_party": { "initiate_login_uri": "https://rp.example.com/i#frag" }
        }))
        .is_err());
    }

    #[test]
    fn third_party_login_url_keeps_target_verbatim() {
        let target = "https://app.example.com/deep?x=1&y=2";
        let url = third_party_login_url(
            "https://rp.example.com/initiate",
            "https://op.example.com",
            None,
            Some(target),
        );
        assert_eq!(
            url,
            "https://rp.example.com/initiate\
             ?iss=https%3A%2F%2Fop.example.com\
             &target_link_uri=https%3A%2F%2Fapp.example.com%2Fdeep%3Fx%3D1%26y%3D2"
        );

        // Round-trip: the RP parsing the return call sees the exact value.
        let query = url.split_once('?').unwrap().1;
        let params: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let login = parse_third_party_initiated_login(&params).unwrap();
        assert_eq!(login.target_link_uri.as_deref(), Some(target));
    }

    struct OneShot {
        body: String,
    }

    #[async_trait::async_trait]
    impl crate::http::HttpClient for OneShot {
        async fn get(&self, _url: &str) -> Result<crate::http::HttpFetchResponse> {
            Ok(crate::http::HttpFetchResponse {
                status: 200,
                body: self.body.clone().into_bytes(),
                content_type: Some("application/entity-statement+jwt".into()),
            })
        }
        async fn post_form(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _headers: &[(String, String)],
        ) -> Result<crate::http::HttpFetchResponse> {
            Ok(crate::http::HttpFetchResponse {
                status: 404,
                body: Vec::new(),
                content_type: None,
            })
        }
    }

    fn rp_entity_configuration(entity_id: &str, rp_metadata: serde_json::Value) -> String {
        let k = {
            let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
            jwk.alg = Some("ES256".into());
            crate::keys::signing_key_from_jwk_json(
                &jwk.to_json().unwrap(),
                Some("ES256"),
                Some("rp"),
            )
            .unwrap()
        };
        crate::federation::build_entity_configuration(
            &k,
            entity_id,
            &k.to_public_jwks(),
            &[],
            json!({ "openid_relying_party": rp_metadata }),
            &[],
            3600,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn self_published_initiate_login_uri_roundtrip() {
        let body = rp_entity_configuration(
            "https://rp.example.com",
            json!({ "initiate_login_uri": "https://rp.example.com/initiate" }),
        );
        let http: Arc<dyn crate::http::HttpClient> = Arc::new(OneShot { body });
        assert_eq!(
            self_published_initiate_login_uri(&http, "https://rp.example.com")
                .await
                .unwrap(),
            "https://rp.example.com/initiate"
        );

        // The statement must be issued by the requested entity id.
        assert!(
            self_published_initiate_login_uri(&http, "https://other.example.com")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn self_published_requires_initiate_login_uri() {
        let body = rp_entity_configuration("https://rp.example.com", json!({}));
        let http: Arc<dyn crate::http::HttpClient> = Arc::new(OneShot { body });
        assert!(
            self_published_initiate_login_uri(&http, "https://rp.example.com")
                .await
                .is_err()
        );
    }

    #[test]
    fn hint_promotion() {
        let mut ops = vec![
            op("https://a.example"),
            op("https://b.example"),
            op("https://c.example"),
        ];

        // No match leaves the order alone.
        assert!(!promote_hint(&mut ops, "https://nope.example"));
        assert_eq!(ops[0].entity_id, "https://a.example");

        // Match moves to the front (trailing slash normalized).
        assert!(promote_hint(&mut ops, "https://c.example/"));
        assert_eq!(ops[0].entity_id, "https://c.example");
        assert_eq!(ops.len(), 3);

        // Already first still counts as a hint match.
        assert!(promote_hint(&mut ops, "https://c.example"));
        assert_eq!(ops[0].entity_id, "https://c.example");
    }
}
