# Changelog

## unreleased

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
