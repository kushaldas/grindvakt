# Changelog

## unreleased

## 0.5.0 [2026-06-25]

- Added optional PKCS#11 / HSM signing behind the new, default-off `pkcs11`
  feature. With it enabled, `signing_key_from_pkcs11(&Pkcs11KeyConfig)` loads a
  signing key whose private material stays on a hardware token (SoftHSM2,
  Kryoptic, …); all asymmetric signing flows — id_tokens, federation entity
  statements, RP client assertions and signed request objects — then sign over
  PKCS#11 (`C_Sign`) and the key never leaves the module. The public key is read
  back from the token and published unchanged through `to_public_jwks()`.
  Supports RSA (`RS256/384/512`), EC (`ES256`/`ES384`) and `EdDSA` (Ed25519).
  - Keys are identified by `CKA_LABEL` on the first slot with an initialized
    token; kryptering 0.3 exposes no slot/token selection.
  - Symmetric token sealing (codes/access/refresh tokens) stays software-only.
- **Breaking**: `SigningKey` is now immutable after construction and no longer
  exposes public fields. It holds a `kryptering::Signer` trait object (software-
  or HSM-backed) plus a cached public JWK, so software and HSM keys are
  interchangeable. The former `jwk` field is gone; `alg` and `kid` are now
  read-only accessors (`alg()` / `kid()`) rather than public fields, which keeps
  the signer, the JWT headers, and the cached public JWK from drifting apart.
  Use `public_jwk()` / `to_public_jwks()` to obtain the publishable key and the
  new `signer()` accessor when calling jose-rs signing APIs directly.
  Construction via `signing_key_from_pem` / `signing_key_from_jwk_json` is
  unchanged.

## 0.4.0 [2026-06-23]

- The OP now emits standard OIDC claims with their correct JSON type instead of
  always stringifying released attributes (OIDC Core §5.1): `email_verified`
  and `phone_number_verified` serialize as JSON booleans, and `updated_at` as a
  number. Applies to both the id_token and the userinfo response (they share
  `flatten_claims`). A value that cannot be parsed as the expected type is left
  as a string rather than dropped or fabricated. This lets RPs that strictly
  type `email_verified` as a boolean (e.g. Vaultwarden/OIDCWarden) consume it.

- Added the `refresh_token` grant (RFC 6749 §6). The OP now issues a refresh
  token from the authorization-code exchange for clients registered with
  `refresh_token` in `grant_types`, and the token endpoint handles
  `grant_type=refresh_token`: it authenticates the client, opens the (stateless)
  refresh token, enforces client binding, allows scope to be **narrowed** (never
  widened), mints a new access token and id_token, and **rotates** the refresh
  token (sliding expiry). New `tokens::RefreshTokenPayload`,
  `TokenCodec::seal_refresh_token`/`open_refresh_token`,
  `TokenLifetimes.refresh_token_ttl` (default 30 days), and
  `TokenResponse.refresh_token`. `refresh_token` is advertised in
  `grant_types_supported`.
  - The refreshed id_token preserves the original `auth_time`, `nonce`, and
    `acr` (`build_id_token` now takes `auth_time`) so it stays faithful to the
    initial authentication.
  - DPoP-bound refresh tokens preserve their `cnf.jkt` binding across rotation
    and require a matching DPoP proof when redeemed.
  - Refresh tokens are stateless like codes/access tokens, so they cannot be
    revoked before their own expiry (no server-side store) — an accepted
    trade-off of the stateless design; rotation slides the window but does not
    add server-side reuse detection.
- Hardening: every sealed token (code, access token, refresh token) now carries
  a type tag that is verified on open, so a token of one kind can no longer be
  replayed as another (e.g. a refresh token or authorization code presented as
  an access token at userinfo). **Token format change**: tokens sealed by
  ≤ 0.3.x do not open under 0.4.0 — codes/access tokens are short-lived so this
  only affects in-flight tokens across an upgrade.

## 0.3.1 [2026-06-11]

- Added `rp::signed_request_object` building an RFC 9101 signed request
  object (JAR) for the authorization request, as OpenID Federation automatic
  registration requires: the OP authenticates the RP at the authorization
  endpoint against the keys in its resolved `openid_relying_party` metadata
  (and Shibboleth's OIDC OP plugin uses the request object as the trigger to
  resolve the RP's trust chain). Claims carry `client_id`, `redirect_uri`,
  `scope`, `response_type`, `state`, `nonce`, optional PKCE challenge, plus
  `iss`/`aud`/`iat`/`exp`/`jti`; the JWS header is plain `alg`+`kid` (no
  `typ`) for interoperability.

## 0.3.0 [2026-06-11]

- `federation::ResolvedEntity` gained a public `exp` field carrying the
  resolve response's expiry (seconds since epoch, tolerant of fractional
  values some implementations emit) so callers can bound caching of resolved
  metadata. Breaking for code constructing `ResolvedEntity` literally.
- Added `discovery::self_published_rp` returning the full metadata claims
  object and statement `exp` of a verified self-published entity
  configuration; `discovery::self_published_initiate_login_uri` is now a thin
  wrapper over it.

## 0.2.0 [2026-06-11]

- Added the opt-in `discovery` module (not re-exported at the crate root) with
  helpers for the home-organization discovery flow and OpenID Connect Core §4
  Third-Party Initiated Login: entity-id validation, discovery request URL
  building for RPs, `initiate_login_uri` extraction from resolved relying-party
  metadata, third-party initiated login URL building and parsing, OP-hint
  promotion over collection results, and `self_published_initiate_login_uri`
  for discovery services that accept RPs outside the federation by verifying
  the RP's own self-signed entity configuration.
- Re-exported `jose_rs` at the crate root so downstream crates can name JOSE
  types (e.g. `JwkSet` in `federation::TrustAnchors`) without pinning their own
  copy of the dependency.

- Hardened OpenID Federation resolve handling to validate the selected trust
  anchor's self-issued entity configuration, require resolve responses to be
  issued by the selected trust anchor, and require a returned trust chain that
  starts with the subject entity configuration and ends with the selected trust
  anchor.
- Added Entity Type key resolution helpers for OpenID Federation metadata,
  including `signed_jwks_uri` support and stricter handling of malformed inline
  `jwks` values so callers do not silently downgrade to weaker key retrieval.
- Tightened entity collection parsing to require explicit `entity_types`
  membership for `entity_type`-filtered results, matching the entity collection
  specification.
- Prevented released claims named `sub` from duplicating or overriding the
  canonical OpenID Connect subject in ID Tokens and UserInfo responses.
