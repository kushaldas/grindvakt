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
pub use error::{Error, Result};
pub use http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
pub use keys::{signing_key_from_jwk_json, signing_key_from_pem, SigningKey};
#[cfg(feature = "pkcs11")]
pub use keys::{signing_key_from_pkcs11, Pkcs11KeyConfig};

// Convenient root re-exports — protocol.
pub use client::{Client, ClientStore, InMemoryClientStore};
pub use dpop::{DpopConfig, DpopError, DpopProof, NoReplayStore, ReplayStore};
pub use metadata::ProviderMetadata;
pub use oauth_error::{OAuthError, OAuthErrorCode};
pub use provider::{Provider, TokenLifetimes, TokenResponse};
pub use request::AuthorizationRequest;
pub use tokens::TokenCodec;
