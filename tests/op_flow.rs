//! End-to-end OP engine tests: authorization code + PKCE flow, id_token
//! verification, userinfo, and `private_key_jwt` client authentication.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use grindvakt::client::{
    Client, InMemoryClientStore, AUTH_CLIENT_SECRET_POST, AUTH_NONE, AUTH_PRIVATE_KEY_JWT,
};
use grindvakt::keys::{signing_key_from_jwk_json, SigningKey};
use grindvakt::metadata::ProviderMetadata;
use grindvakt::pkce;
use grindvakt::provider::{InMemoryTokenUseStore, Provider, TokenLifetimes, CLIENT_ASSERTION_TYPE};
use grindvakt::request::AuthorizationRequest;
use grindvakt::tokens::TokenCodec;

struct AcceptDpopProof;

#[async_trait]
impl grindvakt::dpop::ReplayStore for AcceptDpopProof {
    async fn record(&self, _jti: &str, _ttl_secs: u64) -> Result<bool, String> {
        Ok(true)
    }
}

/// Produce the opaque proof capability through the same validation boundary
/// an HTTP adapter uses; tests must not be able to fabricate a trusted `jkt`.
async fn validated_dpop_proof() -> grindvakt::dpop::DpopProof {
    use jose_rs::JoseHeader;

    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".to_string());
    let public = jwk.to_public_jwk();
    let mut header = JoseHeader::new("ES256");
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_str(&public.to_json().unwrap()).unwrap());
    let endpoint = "https://op.example.com/token";
    let claims = serde_json::json!({
        "jti": grindvakt::util::random_token(16),
        "htm": "POST",
        "htu": endpoint,
        "iat": grindvakt::util::now_secs() as i64,
    });
    let compact =
        jose_rs::jws::compact::sign_with_jwk(&jwk, &serde_json::to_vec(&claims).unwrap(), &header)
            .unwrap();
    grindvakt::dpop::validate_proof(
        &AcceptDpopProof,
        &grindvakt::dpop::DpopConfig::default(),
        &compact,
        "POST",
        endpoint,
    )
    .await
    .unwrap()
}

fn ec_signing_key(kid: &str) -> SigningKey {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    signing_key_from_jwk_json(&jwk.to_json().unwrap(), Some("ES256"), Some(kid)).unwrap()
}

fn provider_with(clients: InMemoryClientStore) -> Provider {
    let metadata = ProviderMetadata::new("https://op.example.com", "https://op.example.com");
    Provider::new(
        metadata,
        ec_signing_key("op-key-1"),
        Arc::new(clients),
        TokenCodec::new("op-secret"),
        TokenLifetimes::default(),
        Arc::new(InMemoryTokenUseStore::new()),
    )
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn extract_param(redirect: &str, key: &str) -> Option<String> {
    let (_, query) = redirect.split_once(['?', '#'])?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            }
        }
    }
    None
}

#[tokio::test]
async fn authorization_code_pkce_flow() {
    // Public client using PKCE (auth method "none").
    let client = Client {
        client_id: "rp-1".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: Some("openid email".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let verifier = "verifier-0123456789-0123456789-0123456789-01";
    let challenge = pkce::s256_challenge(verifier);

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-1"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email"),
        ("state", "state-xyz"),
        ("nonce", "nonce-abc"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();

    // Validate against the client.
    op.validate_authorization_request(&req).await.unwrap();

    // User authenticated; release claims.
    let mut claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    claims.insert("email".into(), vec!["anna@example.com".into()]);
    let redirect = op
        .authorization_redirect(&req, "subject-123", &claims, Some("urn:acr:pwd".into()))
        .await
        .unwrap();
    assert_eq!(redirect.status, 302);
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(location.starts_with("https://rp.example.com/cb?"));
    assert_eq!(
        extract_param(&location, "state").as_deref(),
        Some("state-xyz")
    );
    let code = extract_param(&location, "code").unwrap();

    // Token exchange with PKCE verifier.
    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-1"),
                ("code_verifier", verifier),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("token exchange");

    assert_eq!(token_resp.token_type, "Bearer");
    let id_token = token_resp.id_token.clone().unwrap();

    let replay = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-1"),
                ("code_verifier", verifier),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(replay.code, grindvakt::OAuthErrorCode::InvalidGrant);

    // Verify the id_token with the OP's published JWKS.
    let jwks = op.jwks_document();
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer("https://op.example.com")
        .with_audience("rp-1");
    let id_claims = jose_rs::jwt::decode_with_jwkset(&jwks, &id_token, &validation).unwrap();
    assert_eq!(id_claims.sub.as_deref(), Some("subject-123"));
    assert_eq!(
        id_claims.extra.get("nonce").and_then(|v| v.as_str()),
        Some("nonce-abc")
    );
    assert_eq!(
        id_claims.extra.get("email").and_then(|v| v.as_str()),
        Some("anna@example.com")
    );
    assert_eq!(
        id_claims.extra.get("acr").and_then(|v| v.as_str()),
        Some("urn:acr:pwd")
    );

    // UserInfo with the access token.
    let userinfo = op.userinfo(&token_resp.access_token, None).await.unwrap();
    assert_eq!(userinfo["sub"], "subject-123");
    assert_eq!(userinfo["email"], "anna@example.com");
}

/// `authorization_redirect_with_claims` emits OP-asserted typed claims that keep
/// their JSON type through code and refresh exchanges: a single-element array
/// stays an array (never collapsed to a scalar the way a released attribute
/// would be), it overwrites a released claim of the same name, and reserved
/// registered claims are ignored.
#[tokio::test]
async fn extra_claims_keep_json_type_and_win_over_released() {
    let client = Client {
        client_id: "rp-1".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: Some("openid".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let verifier = "verifier-0123456789-0123456789-0123456789-01";
    let challenge = pkce::s256_challenge(verifier);
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-1"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
        ("nonce", "nonce-abc"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();
    op.validate_authorization_request(&req).await.unwrap();

    // A released attribute tries to set `authenticating_authority`; the
    // OP-asserted extra claim must win, and its array shape must survive.
    let mut released: BTreeMap<String, Vec<String>> = BTreeMap::new();
    released.insert(
        "authenticating_authority".into(),
        vec!["https://spoofed.example".into()],
    );
    let mut extra: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    extra.insert(
        "authenticating_authority".into(),
        serde_json::json!(["https://idp.example.org"]),
    );
    // Reserved claims in `extra` must not overwrite their canonical values.
    extra.insert("sub".into(), serde_json::json!("attacker"));
    extra.insert(
        "acr".into(),
        serde_json::json!(["urn:acr:attacker-controlled-wrong-type"]),
    );

    let redirect = op
        .authorization_redirect_with_claims(
            &req,
            "subject-123",
            &released,
            Some("urn:acr:trusted".into()),
            &extra,
        )
        .await
        .unwrap();
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let code = extract_param(&location, "code").unwrap();

    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-1"),
                ("code_verifier", verifier),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("token exchange");

    let id_token = token_resp.id_token.clone().unwrap();
    let jwks = op.jwks_document();
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer("https://op.example.com")
        .with_audience("rp-1");
    let assert_id_token_claims = |token: &str| {
        let claims = jose_rs::jwt::decode_with_jwkset(&jwks, token, &validation).unwrap();
        // Reserved extra claims cannot rewrite canonical values.
        assert_eq!(claims.sub.as_deref(), Some("subject-123"));
        assert_eq!(
            claims.extra.get("acr").and_then(|value| value.as_str()),
            Some("urn:acr:trusted")
        );
        // The OP-asserted value wins over the released one and remains an array.
        assert_eq!(
            claims.extra.get("authenticating_authority"),
            Some(&serde_json::json!(["https://idp.example.org"])),
            "extra claim must overwrite the released claim and remain an array"
        );
    };
    assert_id_token_claims(&id_token);

    // It reaches userinfo too, still an array.
    let userinfo = op.userinfo(&token_resp.access_token, None).await.unwrap();
    assert_eq!(
        userinfo["authenticating_authority"],
        serde_json::json!(["https://idp.example.org"])
    );
    assert!(userinfo.get("acr").is_none());

    // The typed claim and canonical ACR survive refresh and token rotation.
    let refresh = token_resp.refresh_token.expect("refresh token issued");
    let refreshed = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "rp-1"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("refresh exchange");
    assert_id_token_claims(refreshed.id_token.as_deref().unwrap());
    let refreshed_userinfo = op.userinfo(&refreshed.access_token, None).await.unwrap();
    assert_eq!(
        refreshed_userinfo["authenticating_authority"],
        serde_json::json!(["https://idp.example.org"])
    );
    assert!(refreshed_userinfo.get("acr").is_none());

    let rotated = refreshed.refresh_token.expect("rotated refresh token");
    let refreshed_again = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &rotated),
                ("client_id", "rp-1"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("rotated refresh exchange");
    assert_id_token_claims(refreshed_again.id_token.as_deref().unwrap());
    let refreshed_again_userinfo = op
        .userinfo(&refreshed_again.access_token, None)
        .await
        .unwrap();
    assert_eq!(
        refreshed_again_userinfo["authenticating_authority"],
        serde_json::json!(["https://idp.example.org"])
    );
    assert!(refreshed_again_userinfo.get("acr").is_none());
}

#[tokio::test]
async fn refresh_token_grant_flow() {
    // Confidential client registered for the refresh_token grant.
    let client = Client {
        client_id: "rp-conf".into(),
        client_secret: Some("s3cret".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    // Authorization code (no PKCE; confidential client).
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-conf"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email profile"),
        ("nonce", "nonce-abc"),
    ]))
    .unwrap();
    let mut claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    claims.insert("email".into(), vec!["anna@example.com".into()]);
    let redirect = op
        .authorization_redirect(&req, "subject-123", &claims, Some("urn:acr:pwd".into()))
        .await
        .unwrap();
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let code = extract_param(&location, "code").unwrap();

    // Code exchange returns a refresh token.
    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-conf"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("token exchange");
    let refresh = token_resp
        .refresh_token
        .clone()
        .expect("refresh token issued");

    // Refresh, narrowing scope to a subset of the original grant.
    let refreshed = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("scope", "openid email"),
                ("client_id", "rp-conf"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("refresh exchange");
    assert_eq!(refreshed.scope.as_deref(), Some("openid email"));

    // Rotation: a new refresh token is returned, and the new access token works.
    let rotated = refreshed.refresh_token.clone().expect("rotated refresh");
    assert_ne!(rotated, refresh, "refresh token should rotate");
    let userinfo = op.userinfo(&refreshed.access_token, None).await.unwrap();
    assert_eq!(userinfo["sub"], "subject-123");

    let old_replay = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "rp-conf"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(old_replay.code, grindvakt::OAuthErrorCode::InvalidGrant);

    // The refreshed id_token preserves the subject and original nonce.
    let jwks = op.jwks_document();
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer("https://op.example.com")
        .with_audience("rp-conf");
    let id_claims =
        jose_rs::jwt::decode_with_jwkset(&jwks, &refreshed.id_token.unwrap(), &validation).unwrap();
    assert_eq!(id_claims.sub.as_deref(), Some("subject-123"));
    assert_eq!(
        id_claims.extra.get("nonce").and_then(|v| v.as_str()),
        Some("nonce-abc")
    );

    // Requesting any scope outside the original grant is rejected, even when
    // mixed with otherwise-valid scopes.
    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &rotated),
                ("scope", "openid admin"),
                ("client_id", "rp-conf"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidScope);

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &rotated),
                ("scope", "admin"),
                ("client_id", "rp-conf"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await;
    assert!(err.is_err(), "scope escalation must be rejected");
}

#[tokio::test]
async fn dpop_bound_refresh_token_requires_matching_proof() {
    let client = Client {
        client_id: "rp-dpop".into(),
        client_secret: Some("s3cret".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-dpop"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "subject-123", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let code = extract_param(&location, "code").unwrap();

    let original_proof = validated_dpop_proof().await;
    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-dpop"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            Some(&original_proof),
        )
        .await
        .expect("token exchange");
    assert_eq!(token_resp.token_type, "DPoP");
    let refresh = token_resp.refresh_token.expect("refresh token issued");
    let opened_refresh = op.codec.open_refresh_token(&refresh).unwrap();
    assert_eq!(
        opened_refresh.cnf_jkt.as_deref(),
        Some(original_proof.jkt())
    );

    let missing_proof = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "rp-dpop"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        missing_proof.code,
        grindvakt::OAuthErrorCode::InvalidDpopProof
    );

    let wrong_proof = validated_dpop_proof().await;
    let wrong_key = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "rp-dpop"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            Some(&wrong_proof),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong_key.code, grindvakt::OAuthErrorCode::InvalidDpopProof);

    let refreshed = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "rp-dpop"),
                ("client_secret", "s3cret"),
            ]),
            None,
            "https://op.example.com/token",
            Some(&original_proof),
        )
        .await
        .expect("refresh with matching DPoP proof");
    assert_eq!(refreshed.token_type, "DPoP");
    let opened_access = op.codec.open_access_token(&refreshed.access_token).unwrap();
    assert_eq!(opened_access.cnf_jkt.as_deref(), Some(original_proof.jkt()));
    let rotated = refreshed.refresh_token.expect("rotated refresh token");
    let opened_rotated = op.codec.open_refresh_token(&rotated).unwrap();
    assert_eq!(
        opened_rotated.cnf_jkt.as_deref(),
        Some(original_proof.jkt())
    );
}

#[tokio::test]
async fn refresh_token_denied_when_grant_not_registered() {
    // Client NOT registered for refresh_token: code exchange yields none, and a
    // forged refresh attempt is rejected.
    let client = Client {
        client_id: "rp-1".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let verifier = "verifier-0123456789-0123456789-0123456789-01";
    let challenge = pkce::s256_challenge(verifier);
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-1"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = &redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let code = extract_param(location, "code").unwrap();

    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-1"),
                ("code_verifier", verifier),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap();
    assert!(
        token_resp.refresh_token.is_none(),
        "no refresh token without the grant"
    );

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", "anything"),
                ("client_id", "rp-1"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await;
    assert!(err.is_err(), "refresh_token grant must be denied");
}

#[tokio::test]
async fn pkce_mismatch_rejected() {
    let client = Client {
        client_id: "rp-1".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let verifier = "verifier-0123456789-0123456789-0123456789-01";
    let challenge = pkce::s256_challenge(verifier);
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-1"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = &redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let code = extract_param(location, "code").unwrap();

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", "rp-1"),
                (
                    "code_verifier",
                    "wrong-verifier-0123456789-0123456789-012345",
                ),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await;
    assert!(err.is_err(), "wrong PKCE verifier must be rejected");
}

#[tokio::test]
async fn public_code_flow_requires_s256_pkce() {
    let client = Client {
        client_id: "rp-public".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-public"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
    ]))
    .unwrap();
    let err = op.validate_authorization_request(&req).await.unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidRequest);

    // The minting boundary revalidates too, so a deserialized/unvalidated
    // request cannot bypass the public-client PKCE requirement.
    let mint_err = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .await
        .unwrap_err();
    assert_eq!(mint_err.code, grindvakt::OAuthErrorCode::InvalidRequest);
}

#[tokio::test]
async fn private_key_jwt_client_auth() {
    // The client authenticates with private_key_jwt; the OP holds its public JWKS.
    let client_key = ec_signing_key("rp-key-1");
    let jwks = client_key.to_public_jwks();

    let client = Client {
        client_id: "rp-fed".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_PRIVATE_KEY_JWT.into(),
        jwks: Some(jwks),
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    // Issue a code (no PKCE).
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-fed"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub-fed", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = &redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let code = extract_param(location, "code").unwrap();

    // Build a client assertion (RFC 7523) addressed to the token endpoint.
    let token_url = "https://op.example.com/token";
    let assertion =
        grindvakt::rp::build_client_assertion(&client_key, "rp-fed", token_url).unwrap();

    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ]),
            None,
            token_url,
            None,
        )
        .await
        .expect("private_key_jwt token exchange");
    assert!(token_resp.id_token.is_some());

    // A wrong audience must be rejected.
    let bad_assertion = grindvakt::rp::build_client_assertion(
        &client_key,
        "rp-fed",
        "https://evil.example.com/token",
    )
    .unwrap();
    let err = op
        .authenticate_client(
            &map(&[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &bad_assertion),
            ]),
            None,
            token_url,
        )
        .await;
    assert!(err.is_err(), "wrong audience must be rejected");
}

/// A confidential client using `client_secret_post` to obtain a token via the
/// `client_credentials` grant; scopes are intersected with the client's set and
/// no id_token is issued.
#[tokio::test]
async fn client_credentials_flow() {
    let client = Client {
        client_id: "svc-1".into(),
        client_secret: Some("svc-secret".into()),
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("read write admin".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    // Request a subset of the allowed scopes (the disallowed "delete" is dropped).
    let resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "client_credentials"),
                ("client_id", "svc-1"),
                ("client_secret", "svc-secret"),
                ("scope", "read delete admin"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("client_credentials token");

    assert_eq!(resp.token_type, "Bearer");
    assert!(
        resp.id_token.is_none(),
        "no id_token for client_credentials"
    );
    assert_eq!(resp.scope.as_deref(), Some("read admin"));

    // The sealed access token carries client_id as subject and the granted scope.
    let opened = op.codec.open_access_token(&resp.access_token).unwrap();
    assert_eq!(opened.sub, "svc-1");
    assert_eq!(opened.client_id, "svc-1");
    assert_eq!(opened.scope, "read admin");
    assert!(opened.cnf_jkt.is_none(), "no DPoP binding without a proof");
}

/// A client not registered for the grant is refused.
#[tokio::test]
async fn client_credentials_disallowed_grant_rejected() {
    let client = Client {
        client_id: "svc-2".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "client_credentials"),
                ("client_id", "svc-2"),
                ("client_secret", "s"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidGrant);
}

/// Requesting only scopes the client is not allowed yields invalid_scope.
#[tokio::test]
async fn client_credentials_empty_scope_intersection_rejected() {
    let client = Client {
        client_id: "svc-3".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "client_credentials"),
                ("client_id", "svc-3"),
                ("client_secret", "s"),
                ("scope", "write"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidScope);
}

/// A public ("none"-auth) client must not be issued a client_credentials token
/// even if its registered grant list includes the grant — there is no secret to
/// prove, so anyone knowing the client_id could otherwise mint tokens.
#[tokio::test]
async fn client_credentials_public_client_rejected() {
    let client = Client {
        client_id: "pub-svc".into(),
        client_secret: None,
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "client_credentials"),
                ("client_id", "pub-svc"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidClient);
}

/// A DPoP-bound token request sets token_type=DPoP and seals cnf.jkt into the
/// access token so userinfo/introspection can read it back.
#[tokio::test]
async fn client_credentials_dpop_bound() {
    let client = Client {
        client_id: "svc-4".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let proof = validated_dpop_proof().await;
    let resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "client_credentials"),
                ("client_id", "svc-4"),
                ("client_secret", "s"),
            ]),
            None,
            "https://op.example.com/token",
            Some(&proof),
        )
        .await
        .expect("dpop token");

    assert_eq!(resp.token_type, "DPoP");
    let opened = op.codec.open_access_token(&resp.access_token).unwrap();
    assert_eq!(opened.cnf_jkt.as_deref(), Some(proof.jkt()));
}

/// Regression: an attribute map that releases a claim named `sub` (e.g.
/// `eduPersonPrincipalName -> sub` on the OpenID profile) must not produce an
/// id_token with two `sub` keys, and userinfo's `sub` must stay the canonical
/// subject. A federation RP parsing the id_token strictly would otherwise fail
/// with "duplicate field `sub`".
#[tokio::test]
async fn released_sub_claim_does_not_duplicate_id_token_subject() {
    let client = Client {
        client_id: "rp-sub".into(),
        client_secret: None,
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_NONE.into(),
        jwks: None,
        scope: Some("openid email".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let verifier = "verifier-0123456789-0123456789-0123456789-01";
    let challenge = pkce::s256_challenge(verifier);
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-sub"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email"),
        ("nonce", "nonce-1"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]))
    .unwrap();
    op.validate_authorization_request(&req).await.unwrap();

    // The released attribute set carries `sub` (mapped from eppn) alongside the
    // real subject identifier the OP passes positionally.
    let mut claims: BTreeMap<String, Vec<String>> = BTreeMap::new();
    claims.insert("sub".into(), vec!["anna@scope.example".into()]);
    claims.insert("email".into(), vec!["anna@example.com".into()]);
    let redirect = op
        .authorization_redirect(&req, "canonical-subject-id", &claims, None)
        .await
        .unwrap();
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let code = extract_param(&location, "code").unwrap();

    let token_resp = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-sub"),
                ("code_verifier", verifier),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .expect("token exchange");
    let id_token = token_resp.id_token.clone().unwrap();

    // The raw JWT payload must contain exactly one `sub` key.
    let payload_b64 = id_token.split('.').nth(1).unwrap();
    use base64::Engine;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .unwrap();
    let sub_keys = String::from_utf8(payload)
        .unwrap()
        .matches("\"sub\"")
        .count();
    assert_eq!(sub_keys, 1, "id_token payload must carry exactly one sub");

    // Strict verification (serde rejects duplicate keys) succeeds and the
    // subject is the canonical one, not the released eppn.
    let jwks = op.jwks_document();
    let validation = jose_rs::jwt::Validation::new()
        .with_issuer("https://op.example.com")
        .with_audience("rp-sub");
    let id_claims = jose_rs::jwt::decode_with_jwkset(&jwks, &id_token, &validation).unwrap();
    assert_eq!(id_claims.sub.as_deref(), Some("canonical-subject-id"));

    // UserInfo keeps the canonical subject too.
    let userinfo = op.userinfo(&token_resp.access_token, None).await.unwrap();
    assert_eq!(userinfo["sub"], "canonical-subject-id");
    assert_eq!(userinfo["email"], "anna@example.com");
}

/// Regression: client assertions (`private_key_jwt`) must carry `exp` (with an
/// age bound), and a captured assertion must not be replayable — its `jti` is
/// consumed once via the token-use store.
#[tokio::test]
async fn private_key_jwt_requires_exp_and_tracks_jti_replay() {
    let client_key = ec_signing_key("rp-key-2");
    let client = Client {
        client_id: "rp-pkj".into(),
        client_secret: None,
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: AUTH_PRIVATE_KEY_JWT.into(),
        jwks: Some(client_key.to_public_jwks()),
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));
    let token_url = "https://op.example.com/token";

    // An assertion without exp must be rejected; the error description must
    // stay generic (no jose-rs detail leaks to the client).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = jose_rs::jwt::Claims {
        iss: Some("rp-pkj".into()),
        sub: Some("rp-pkj".into()),
        aud: Some(jose_rs::jwt::Audience::Single(token_url.into())),
        iat: Some(now),
        jti: Some("no-exp-jti".into()),
        ..Default::default()
    };
    let mut header = jose_rs::JoseHeader::for_alg(client_key.alg());
    header.kid = client_key.kid().map(str::to_string);
    let no_exp = jose_rs::jwt::encode(client_key.signer(), &header, &claims).unwrap();
    let err = op
        .authenticate_client(
            &map(&[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &no_exp),
            ]),
            None,
            token_url,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidClient);
    assert_eq!(
        err.description.as_deref(),
        Some("client_assertion validation failed"),
        "validation detail must not leak into error_description"
    );

    // An assertion without iat must be rejected too: the max-age bound is
    // measured from iat, so a missing iat would make it unenforceable.
    let claims = jose_rs::jwt::Claims {
        iss: Some("rp-pkj".into()),
        sub: Some("rp-pkj".into()),
        aud: Some(jose_rs::jwt::Audience::Single(token_url.into())),
        exp: Some(now + 300),
        jti: Some("no-iat-jti".into()),
        ..Default::default()
    };
    let no_iat = jose_rs::jwt::encode(client_key.signer(), &header, &claims).unwrap();
    let err = op
        .authenticate_client(
            &map(&[
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", &no_iat),
            ]),
            None,
            token_url,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidClient);
    assert_eq!(
        err.description.as_deref(),
        Some("client_assertion validation failed")
    );

    // A valid assertion authenticates once...
    let assertion =
        grindvakt::rp::build_client_assertion(&client_key, "rp-pkj", token_url).unwrap();
    let form = map(&[
        ("client_assertion_type", CLIENT_ASSERTION_TYPE),
        ("client_assertion", &assertion),
    ]);
    op.authenticate_client(&form, None, token_url)
        .await
        .expect("first use of the assertion");

    // ...but replaying the same assertion (same jti) is rejected.
    let err = op
        .authenticate_client(&form, None, token_url)
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidClient);
    assert_eq!(
        err.description.as_deref(),
        Some("client_assertion already used")
    );
}

/// Regression: the client-assertion max age is configurable. The default
/// 300-second bound rejects older assertions; a provider built with
/// `with_client_assertion_max_age` accepts them (exp and single-use jti are
/// still enforced).
#[tokio::test]
async fn private_key_jwt_max_age_is_configurable() {
    let client_key = ec_signing_key("rp-key-3");
    let client = Client {
        client_id: "rp-pkj-age".into(),
        client_secret: None,
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: AUTH_PRIVATE_KEY_JWT.into(),
        jwks: Some(client_key.to_public_jwks()),
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let token_url = "https://op.example.com/token";

    // An assertion issued 600 seconds ago, still well within its exp.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = jose_rs::jwt::Claims {
        iss: Some("rp-pkj-age".into()),
        sub: Some("rp-pkj-age".into()),
        aud: Some(jose_rs::jwt::Audience::Single(token_url.into())),
        iat: Some(now - 600),
        exp: Some(now + 3000),
        jti: Some("old-assertion-jti".into()),
        ..Default::default()
    };
    let mut header = jose_rs::JoseHeader::for_alg(client_key.alg());
    header.kid = client_key.kid().map(str::to_string);
    let assertion = jose_rs::jwt::encode(client_key.signer(), &header, &claims).unwrap();
    let form = map(&[
        ("client_assertion_type", CLIENT_ASSERTION_TYPE),
        ("client_assertion", &assertion),
    ]);

    // The default 300 s bound rejects it.
    let op = provider_with(InMemoryClientStore::with_clients(vec![client.clone()]));
    let err = op
        .authenticate_client(&form, None, token_url)
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidClient);

    // A widened bound accepts it.
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]))
        .with_client_assertion_max_age(3600);
    op.authenticate_client(&form, None, token_url)
        .await
        .expect("assertion within the configured max age");
}

/// Regression: the requested scope at the authorization endpoint must not
/// exceed the client's registered scope set.
#[tokio::test]
async fn authorization_request_scope_checked_against_registered_scope() {
    let client = Client {
        client_id: "rp-scope".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("openid email".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    // A subset of the registered scope is fine.
    let ok = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-scope"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email"),
    ]))
    .unwrap();
    op.validate_authorization_request(&ok).await.unwrap();

    // Any scope outside the registered set is rejected, even when mixed with
    // valid scopes.
    let excess = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-scope"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid admin"),
    ]))
    .unwrap();
    let err = op
        .validate_authorization_request(&excess)
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidScope);
}

/// A client registered without a `scope` is unrestricted at the authorization
/// endpoint: `None` means "not configured", not "empty set" — otherwise every
/// OIDC request (scope=openid) from such a client would fail.
#[tokio::test]
async fn client_without_registered_scope_is_unrestricted() {
    let client = Client {
        client_id: "rp-noscope".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-noscope"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid email"),
    ]))
    .unwrap();
    op.validate_authorization_request(&req)
        .await
        .expect("scope: None must not be treated as an empty allowlist");
}

/// Regression: the presented token-endpoint authentication method must match
/// the client's registered `token_endpoint_auth_method`.
#[tokio::test]
async fn presented_auth_method_must_match_registered_method() {
    use base64::Engine;

    let client = Client {
        client_id: "rp-basic".into(),
        client_secret: Some("topsecret".into()),
        redirect_uris: vec![],
        response_types: vec![],
        grant_types: vec!["client_credentials".into()],
        token_endpoint_auth_method: grindvakt::client::AUTH_CLIENT_SECRET_BASIC.into(),
        jwks: None,
        scope: Some("read".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    // The correct secret presented via client_secret_post is rejected: the
    // client is registered for client_secret_basic only.
    let err = op
        .authenticate_client(
            &map(&[("client_id", "rp-basic"), ("client_secret", "topsecret")]),
            None,
            "https://op.example.com/token",
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidClient);

    // The registered method works.
    let b64 = base64::engine::general_purpose::STANDARD.encode("rp-basic:topsecret");
    let header = format!("Basic {b64}");
    op.authenticate_client(
        &map(&[("client_id", "rp-basic")]),
        Some(&header),
        "https://op.example.com/token",
    )
    .await
    .expect("registered basic auth method");
}

/// Regression: implicit and hybrid response types require a nonce (OIDC Core
/// §3.2.2.1 / §3.3.2.1).
#[tokio::test]
async fn implicit_and_hybrid_flows_require_nonce() {
    let client = Client {
        client_id: "rp-implicit".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["id_token token".into(), "code id_token".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("openid".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    for response_type in ["id_token token", "code id_token"] {
        let req = AuthorizationRequest::from_params(&map(&[
            ("client_id", "rp-implicit"),
            ("response_type", response_type),
            ("redirect_uri", "https://rp.example.com/cb"),
            ("scope", "openid"),
        ]))
        .unwrap();
        let err = op.validate_authorization_request(&req).await.unwrap_err();
        assert_eq!(
            err.code,
            grindvakt::OAuthErrorCode::InvalidRequest,
            "{response_type} without nonce must be rejected"
        );

        let req = AuthorizationRequest::from_params(&map(&[
            ("client_id", "rp-implicit"),
            ("response_type", response_type),
            ("redirect_uri", "https://rp.example.com/cb"),
            ("scope", "openid"),
            ("nonce", "n-1"),
        ]))
        .unwrap();
        op.validate_authorization_request(&req)
            .await
            .unwrap_or_else(|e| panic!("{response_type} with nonce must pass: {e}"));
    }
}

/// OIDC Core §3.1.2.1 forbids combining `prompt=none` with another
/// prompt value. Unknown values on their own remain accepted because the OP
/// is allowed to ignore extensions it does not understand.
#[tokio::test]
async fn authorization_request_validates_prompt_none_combinations() {
    let client = Client {
        client_id: "rp-prompt".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("openid".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    for prompt in ["none", "login", "future_extension", "None login"] {
        let req = AuthorizationRequest::from_params(&map(&[
            ("client_id", "rp-prompt"),
            ("response_type", "code"),
            ("redirect_uri", "https://rp.example.com/cb"),
            ("scope", "openid"),
            ("prompt", prompt),
        ]))
        .unwrap();
        op.validate_authorization_request(&req)
            .await
            .unwrap_or_else(|e| panic!("prompt={prompt} should pass: {e}"));
    }

    for prompt in ["none login", "none none"] {
        let req = AuthorizationRequest::from_params(&map(&[
            ("client_id", "rp-prompt"),
            ("response_type", "code"),
            ("redirect_uri", "https://rp.example.com/cb"),
            ("scope", "openid"),
            ("state", "state-prompt"),
            ("prompt", prompt),
        ]))
        .unwrap();
        let err = op.validate_authorization_request(&req).await.unwrap_err();
        assert_eq!(
            err.code,
            grindvakt::OAuthErrorCode::InvalidRequest,
            "prompt={prompt}"
        );
        assert_eq!(err.state.as_deref(), Some("state-prompt"));
    }
}

/// Regression: the hybrid `code id_token` response type defaults to the
/// fragment response mode, so the id_token is not leaked in the URL query.
#[tokio::test]
async fn hybrid_flow_defaults_to_fragment_response_mode() {
    let client = Client {
        client_id: "rp-hybrid".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code id_token".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("openid".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-hybrid"),
        ("response_type", "code id_token"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
        ("nonce", "n-1"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = &redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let fragment = location.split_once('#').expect("fragment separator").1;
    assert!(
        fragment.contains("id_token="),
        "id_token must be delivered in the fragment: {location}"
    );
}

/// Regression: when the authorization code carries a redirect_uri, the token
/// request MUST echo a matching redirect_uri (RFC 6749 §4.1.3).
#[tokio::test]
async fn token_request_must_echo_redirect_uri() {
    let client = Client {
        client_id: "rp-redir".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["authorization_code".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("openid".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-redir"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = &redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let code = extract_param(location, "code").unwrap();

    // No redirect_uri echoed at all -> invalid_grant.
    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", "rp-redir"),
                ("client_secret", "s"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidGrant);
}

/// Regression: a client not registered for the authorization_code grant cannot
/// redeem a code at the token endpoint (mirrors the client_credentials and
/// refresh_token grant gates).
#[tokio::test]
async fn authorization_code_grant_must_be_registered() {
    let client = Client {
        client_id: "rp-nogrant".into(),
        client_secret: Some("s".into()),
        redirect_uris: vec!["https://rp.example.com/cb".into()],
        response_types: vec!["code".into()],
        grant_types: vec!["refresh_token".into()],
        token_endpoint_auth_method: AUTH_CLIENT_SECRET_POST.into(),
        jwks: None,
        scope: Some("openid".into()),
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-nogrant"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
    ]))
    .unwrap();
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
        .await
        .unwrap();
    let location = &redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1;
    let code = extract_param(location, "code").unwrap();

    let err = op
        .handle_token_request(
            &map(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://rp.example.com/cb"),
                ("client_id", "rp-nogrant"),
                ("client_secret", "s"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidGrant);
}
