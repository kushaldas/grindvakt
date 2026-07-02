//! End-to-end OP engine tests: authorization code + PKCE flow, id_token
//! verification, userinfo, and `private_key_jwt` client authentication.

use std::collections::BTreeMap;
use std::sync::Arc;

use grindvakt::client::{
    Client, InMemoryClientStore, AUTH_CLIENT_SECRET_POST, AUTH_NONE, AUTH_PRIVATE_KEY_JWT,
};
use grindvakt::keys::{signing_key_from_jwk_json, SigningKey};
use grindvakt::metadata::ProviderMetadata;
use grindvakt::pkce;
use grindvakt::provider::{Provider, TokenLifetimes, CLIENT_ASSERTION_TYPE};
use grindvakt::request::AuthorizationRequest;
use grindvakt::tokens::TokenCodec;

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
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let store = InMemoryClientStore::with_clients(vec![client]);
    let op = provider_with(store);

    let verifier = "verifier-0123456789-0123456789-0123456789";
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
    use grindvakt::dpop::DpopProof;

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
        .unwrap();
    let location = redirect
        .headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap();
    let code = extract_param(&location, "code").unwrap();

    let original_proof = DpopProof {
        jkt: "original-proof-key".into(),
    };
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
        Some("original-proof-key")
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

    let wrong_proof = DpopProof {
        jkt: "wrong-proof-key".into(),
    };
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
    assert_eq!(opened_access.cnf_jkt.as_deref(), Some("original-proof-key"));
    let rotated = refreshed.refresh_token.expect("rotated refresh token");
    let opened_rotated = op.codec.open_refresh_token(&rotated).unwrap();
    assert_eq!(
        opened_rotated.cnf_jkt.as_deref(),
        Some("original-proof-key")
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

    let verifier = "verifier-0123456789-0123456789-0123456789";
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

    let verifier = "verifier-0123456789-0123456789-0123456789";
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
                ("code_verifier", "the-wrong-verifier-the-wrong-verifier"),
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

    // Defense in depth for codes created by callers that skipped validation or
    // by older versions before S256 PKCE was mandatory for public clients.
    let redirect = op
        .authorization_redirect(&req, "sub", &BTreeMap::new(), None)
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
                ("client_id", "rp-public"),
            ]),
            None,
            "https://op.example.com/token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, grindvakt::OAuthErrorCode::InvalidGrant);
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
    use grindvakt::dpop::DpopProof;

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

    let proof = DpopProof {
        jkt: "the-proof-key-thumbprint".into(),
    };
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
    assert_eq!(opened.cnf_jkt.as_deref(), Some("the-proof-key-thumbprint"));
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
        scope: None,
        subject_type: "public".into(),
        client_name: None,
    };
    let op = provider_with(InMemoryClientStore::with_clients(vec![client]));

    let verifier = "verifier-0123456789-0123456789-0123456789";
    let challenge = pkce::s256_challenge(verifier);
    let req = AuthorizationRequest::from_params(&map(&[
        ("client_id", "rp-sub"),
        ("response_type", "code"),
        ("redirect_uri", "https://rp.example.com/cb"),
        ("scope", "openid"),
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
