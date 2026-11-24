//! # grindvakt
//!
//! A reusable, runtime-agnostic OAuth 2.0 / OpenID Connect (and, in
//! [`federation`], OpenID Federation 1.0) protocol library built on `jose-rs`.
//!
//! `grindvakt` is independent of any web framework and of any particular
//! identity proxy: the OP engine ([`provider`]) and the RP flow ([`rp`]) are
//! pure logic, with outbound HTTP injected via the [`http::HttpClient`] trait.
//! It can be consumed directly from an actix-web, axum, or any other Rust
//! application — the [`tunnelbana`](https://crates.io) identity proxy is just
//! one such consumer.
//!
//! - OP (provider) side: [`provider::Provider`] — discovery, jwks, authorization,
//!   token (incl. `private_key_jwt` and DPoP), userinfo, stateless JWT tokens.
//! - RP (client) side: [`rp`] — discovery, auth request, code exchange,
//!   id_token verification, userinfo.
//! - Sender-constrained tokens: [`dpop`] (RFC 9449).
//! - Home-organization discovery / third-party initiated login: [`discovery`]
//!   (opt-in by module path, not re-exported at the root).
//!
//! ## Foundational primitives
//!
//! Alongside the protocol logic, grindvakt exposes the small, generic building
//! blocks the protocol layer needs and that downstream crates re-use:
//! [`error`] (the shared `Error`/`Result`), [`http`] (framework-agnostic
//! request/response types and the outbound [`http::HttpClient`] trait),
//! [`keys`] (PEM/DER/JWK signing-key loading via `kryptering`), [`mac`]
//! (HMAC/SHA-256/constant-time helpers) and [`util`].
//!
//! ## Upgrading from 0.12 to 0.13
//!
//! Existing JSON client registrations deserialize with an empty
//! [`client::ResponsePolicy`]. Their ID tokens are signed, and
//! [`Provider::userinfo`] returns JSON claims. To serve signed UserInfo, call
//! [`Provider::signed_userinfo`]. To encrypt either signed response, set the
//! corresponding policy in the client's registration.
//!
//! Authorization codes issued by 0.13 carry a [`Client::registration_fingerprint`].
//! If the registration changes before code exchange, an authenticated client
//! receives `invalid_grant` and can start a new authorization. The
//! [`tokens`] module describes how existing codes and tokens survive an upgrade.
//!
//! Applications that make separate claim release decisions can pass
//! [`provider::AuthorizedClaims`] to [`Provider::authorization_redirect_with_authorized_claims`].
//! Existing authorization methods apply the scope filter to one shared set
//! of application claims. Both paths reserve names such as `acr` and
//! `auth_time` for the provider. Supply those values as ID token authentication
//! parameters if a relying party needs them.
//!
//! When updating Rust code, add `response_policy: Default::default()` to
//! [`Client`] literals and handle [`OAuthErrorCode::UnmetAuthenticationRequirements`]
//! in exhaustive matches. Direct constructors of [`federation::ResolvedEntity`]
//! now supply `trust_marks` (an empty vector when no marks were returned).
//! [`tokens::AuthCodePayload`] and [`tokens::RefreshTokenPayload`] document
//! their new optional fields. The re-exported [`jose_rs`] 0.13 uses sorted
//! maps for `Claims.extra` and `JoseHeader.extra`.

// The `jose_rs::jwt::Claims` builder pattern (default + field assignment) is the
// ergonomic way to construct claims; silence the lint crate-wide.
#![allow(clippy::field_reassign_with_default)]
// `ClientAuth::PrivateKeyJwt` carries a SigningKey, which is intentionally
// larger than the secret-string variants.
#![allow(clippy::large_enum_variant)]

// --- Foundational primitives ---
pub mod error;
pub mod http;
pub mod keys;
pub mod mac;
pub mod util;

// --- OAuth2 / OIDC / Federation protocol ---
pub mod callback;
pub mod client;
pub mod discovery;
pub mod dpop;
pub mod federation;
pub mod jwt;
pub mod metadata;
pub mod oauth_error;
pub mod pkce;
pub mod provider;
pub mod request;
pub mod rp;
pub mod tokens;

// Re-export the JOSE library so downstream crates can name its types (e.g.
// `JwkSet` in `federation::TrustAnchors`) without pinning their own version.
pub use jose_rs;

// Convenient root re-exports — primitives.
pub use error::{display_safe, escape_upstream_text, is_invisible_format};
pub use error::{Error, Result};
pub use http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
pub use keys::{signing_key_from_jwk_json, signing_key_from_pem, SigningKey};
#[cfg(feature = "pkcs11")]
pub use keys::{signing_key_from_pkcs11, Pkcs11KeyConfig};

// Convenient root re-exports — protocol.
pub use callback::{
    parse_authorization_response, parse_authorization_response_multi,
    parse_authorization_response_request, parse_authorization_response_str, AuthorizationResponse,
    AuthorizationResponseOptions, JarmOptions, ResponseMode, JARM_ASYMMETRIC_ALGORITHMS, JARM_TYP,
};
pub use client::{Client, ClientStore, InMemoryClientStore};
pub use dpop::{DpopConfig, DpopError, DpopProof, NoReplayStore, ReplayStore};
pub use jwt::{is_symmetric_jws_algorithm, JWS_ALGORITHMS};
pub use metadata::ProviderMetadata;
pub use oauth_error::{OAuthError, OAuthErrorCode, ParseOAuthErrorCodeError};
#[cfg(feature = "redis")]
pub use provider::RedisStore;
pub use provider::{InMemoryTokenUseStore, Provider, TokenLifetimes, TokenResponse, TokenUseStore};
pub use request::AuthorizationRequest;
pub use tokens::TokenCodec;
