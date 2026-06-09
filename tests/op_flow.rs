//! End-to-end OP engine tests: authorization code + PKCE flow, id_token
//! verification, userinfo, and `private_key_jwt` client authentication.

use std::collections::BTreeMap;
use std::sync::Arc;

use grindvakt::keys::{signing_key_from_jwk_json, SigningKey};
use grindvakt::client::{
    Client, InMemoryClientStore, AUTH_CLIENT_SECRET_POST, AUTH_NONE, AUTH_PRIVATE_KEY_JWT,
};
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
    assert_eq!(extract_param(&location, "state").as_deref(), Some("state-xyz"));
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
    let location = &redirect.headers.iter().find(|(k, _)| k == "location").unwrap().1;
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
    let location = &redirect.headers.iter().find(|(k, _)| k == "location").unwrap().1;
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
    assert!(resp.id_token.is_none(), "no id_token for client_credentials");
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
