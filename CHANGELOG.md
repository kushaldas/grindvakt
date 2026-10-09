# Changelog

## 0.9.0 [unreleased]

- `rp::validate_issuer`, `rp::validate_service_endpoint_for_issuer` and
  `rp::validate_redirect_uri_syntax` are now public and documented, and so is
  `jwt::oidc_token_hash` (moved from the provider internals), so
  applications can apply the same endpoint and `at_hash`/`c_hash` rules the
  library uses.
- **Breaking:** `ProviderMetadata::userinfo_endpoint` is now
  `Option<String>` and is omitted from serialized metadata when `None`.
  `rp::discover` now accepts providers that do not advertise UserInfo. Use
  the new `ProviderInfo::require_userinfo_endpoint` / `require_jwks_uri` to
  get a clear error when an endpoint is missing.
- **Breaking:** `HttpFetchResponse` has a new `headers` field (lower-cased
  names, in order) so callers can honour `Cache-Control` and similar headers
  when caching JWKS. It now implements `Default` and gains `new`,
  `with_header`, `header`, `header_values` and `cache_control` (which joins multiple `Cache-Control` lines with `, `). `HttpClient` implementations
  should fill in `headers`. Code that builds it with a struct literal must add
  the field or use `..Default::default()`.
- `HttpClient` gains `get_with_headers`, with a default implementation that
  returns an error, so existing clients keep compiling. Implement it to
  enable GET requests to UserInfo.
  `HttpClient` implementations must not send credentials to another origin
  on a redirect. For `post_form` (client secrets, client assertions,
  authorization codes and PKCE verifiers in the body) that means not
  following cross-origin redirects at all, including method-preserving `307`
  and `308`, which resend the body; the simplest correct policy is to not
  follow redirects for `post_form`. For `get_with_headers`, do not follow
  redirects or strip `Authorization` on a cross-origin redirect. The library
  cannot enforce this, so it is documented on the trait and on
  `UserinfoMethod::Get`.
- **Breaking:** `Error` is now `#[non_exhaustive]` and has a new `UpstreamHttp` variant (`Error::upstream_http()`). It carries the upstream status, the OAuth `error` / `error_description` (from the JSON body or the `WWW-Authenticate` header), and a sanitized body (control and bidi characters escaped, length capped). Non-success responses from the token, UserInfo, JWKS and discovery endpoints, and from federation entity-configuration, resolve, JWKS, signed JWKS and collection fetches, now return this variant instead of `Authn`/`Internal`. Their `Display` text is unchanged (except as noted below), but code that matched `Error::Authn(_)` or `Error::Internal(_)` for these failures must match `Error::UpstreamHttp(_)`. A `200` response whose JSON body is an OAuth error (`error` string, no `access_token` or `sub`) from the token or UserInfo endpoint is reported through the same variant with the `error` and `error_description` rather than as a missing-field error or a success. `status_hint` is unchanged for token and UserInfo failures (401, as for `Authn` before) and is 502 for the discovery, JWKS and federation fetch failures (500 as `Internal` before). **Migration:** `Error::Authn` still exists, so `matches!(e, Error::Authn(_))` and `match` arms on it still compile but no longer fire for these failures; search for them and use `Error::is_auth_failure()` where they meant "authentication failed". Use the new `Error::is_auth_failure()` (true for `Authn` and for `UpstreamHttp` from token or UserInfo requests; the federation fetch failures are not auth failures) at re-authentication, session-teardown and alerting decision points instead of matching `Error::Authn(_)`, which no longer fires for these failures. The token-endpoint error message no longer embeds the upstream body (`token endpoint returned 400`); read `upstream_http().body` instead, which is escaped and length-capped, handle it deliberately, and never log it verbatim: upstream bodies can echo submitted values or carry personal data. `UpstreamHttpError` redacts its `body` and `error_description` in `Debug` output (the fields stay readable); neither must be logged verbatim, as upstream errors can echo submitted values or carry personal data. Other `Display` texts are unchanged, except that the federation resolve endpoint failure now reads `internal error: resolve endpoint returned N for ...` (it is a metadata fetch, not an auth failure) instead of using the `authentication error:` prefix.
- UserInfo can now be fetched over GET (`UserinfoMethod::Get`, which needs `HttpClient::get_with_headers`) or POST through `rp::fetch_userinfo_response`. It returns the raw response, and `rp::userinfo_signed_claims` verifies a signed `application/jwt` UserInfo response (JWS signature against the allowed algorithms, `iss`, `aud` and `sub`; `exp` is checked if present). Its last argument is `rp::UserinfoJwtOptions`, which has no `Default` or `new()` and must be built with one of three constructors that say how the JWT is proven to be UserInfo: `typed(typ)` requires a UserInfo-specific JOSE `typ` header (`typ` values that are empty, `JWT`, `id_token+jwt` or `at+jwt` are refused with `Error::BadRequest`), `dedicated_keys()` is the caller's attestation that the JWKS holds only keys the OP uses to sign UserInfo, and `untyped_shared_key_compat()` is a compatibility mode for OPs that sign UserInfo and id_tokens with the same keys and set no `typ`. Prefer `typed` or `dedicated_keys`. Builders: `with_require_exp` rejects tokens without `exp`; by default the token must carry `iat` and be at most 300 seconds old (`with_max_age`, or `without_max_age` for OPs that emit neither `iat` nor `exp`). The token must carry a `kid` (jose-rs otherwise tries every key in the set); an OP that publishes a single key without `kid` is conforming, so `UserinfoJwtOptions::allow_missing_kid()` accepts that case, and only for a one-key JWK Set (OIDC Core §10.1 requires `kid` for several keys). The audience must be exactly the client (a string or a one-element array); multi-audience and duplicated-audience tokens are refused. Tokens that look like id_tokens or access tokens (claims `nonce`, `at_hash` or `c_hash`, or `typ` `id_token+jwt` / `at+jwt`) are refused in every mode, but these markers and the age bound are defence in depth, not proof that a token is UserInfo: in shared-key compat mode a fresh id_token without `nonce`, `at_hash` and `c_hash` is accepted for up to the age bound. encrypted responses are not supported. The raw response is not bound to any subject: read it only through `userinfo_json_claims` or `userinfo_signed_claims`. `rp::userinfo_json_claims` parses JSON responses and binds them to the expected subject. `rp::fetch_userinfo` keeps its signature and behaviour (POST, JSON).
- **Breaking:** `rp::verify_id_token` and `rp::verify_id_token_with` now require the id_token to carry a `kid` when the JWK Set has more than one key, as OIDC Core §10.1 requires. Without it jose-rs tried every key in the set, so a token signed by any key in a mixed-trust set verified. A set with a single key still needs no `kid`. An OP that omits `kid` while publishing several keys is out of spec and will be rejected.
- Added `rp::verify_id_token_with` and `rp::IdTokenOptions` for configurable clock-skew leeway, OIDC `max_age` enforcement against `auth_time` (rejects tokens without `auth_time` when `max_age` is set), an `acr` allow-list, and `at_hash` validation against the access token using the hash for the id_token's JWS `alg`. `with_access_token` only checks `at_hash` when the id_token carries it; add `with_required_at_hash` to reject id_tokens without it. An id_token that carries `at_hash` or `c_hash` while no access token or authorization code was supplied to check it against is refused by `verify_id_token_with`, so the binding is never silently skipped; `allow_unchecked_hashes()` opts out for flows that do not use the hash (the code flow makes validating `at_hash` optional), and `verify_id_token` sets it to keep its behaviour. `with_authorization_code` and `with_required_c_hash` do the same for `c_hash`, so hybrid-flow RPs can bind the front-channel id_token to the authorization code. `rp::verify_id_token` keeps jose-rs's default 60-second leeway and otherwise behaves as before, apart from the `kid` rule above. The leeway is capped at `rp::MAX_ID_TOKEN_LEEWAY` (300 seconds; larger values fail with `BadRequest`) and is not added to `max_age`, which is a session-age limit.
- The authorization `state` parameter is bounded: values longer than 1024 characters or outside printable ASCII (RFC 6749 `VSCHAR`, which excludes controls, bidi and line-separator characters) are refused with `invalid_request` ("invalid state parameter"), and `OAuthError` never echoes a `state` that could not have been accepted. This closes unbounded `Location` headers and raw bidi or U+2028/U+2029 characters in error responses.
- `OAuthError` descriptions on the wire (`to_response`, `to_redirect`) are now normalized to the RFC 6749 §§4.1.2.1 and 5.2 character set: printable ASCII without `"` and `\`, other characters replaced by `?`, capped at 256 characters with no truncation marker. The `description` field keeps the raw text and `Display` escapes it for logs, so client-supplied values such as an unsupported `grant_type` no longer put log escapes or an ellipsis on the wire.
- Error messages that quote remote or client-supplied values (issuers, token types, audiences, content types, DPoP and request parameters) now escape control and bidi formatting characters and cap their length. Endpoint validation also rejects bidi characters and other invisible formatting characters (zero-width characters, soft hyphen, BOM, fillers, variation selectors, tag characters), so `validate_issuer` and the endpoint validators do not accept look-alike URLs such as `https://example.com<U+200B>.evil.invalid`. U+061C (Arabic letter mark) and the line and paragraph separators U+2028 and U+2029 are treated the same way.
- Added `rp::fetch_jwks_response` and `rp::JwksResponse`, which return the JWK Set with its `Cache-Control` and `ETag` headers a parsed `Age`, and `cache_ttl_secs()` (remaining freshness: `max-age` minus `Age`, saturating at 0 and capped at `MAX_JWKS_CACHE_TTL_SECS`, 24 hours, so an upstream cannot pin a key set indefinitely; `cache_ttl_secs_max` takes another ceiling) and `advertised_ttl_secs()` helpers so applications can cache JWKS. The library does not cache; `HttpClient` implementations must fill `HttpFetchResponse::headers`. `rp::fetch_jwks` is unchanged.

## 0.8.2 [2026-09-28]

- Updated to `jose-rs` 0.7.1 and aligned the direct signing backend with
  its `kryptering` 0.6 dependency.
- Refreshed compatible dependencies, including `async-trait` 0.1.92,
  `base64` 0.23.1, `redis` 1.7.1, and `thiserror` 2.0.21, along with
  compatible transitive dependencies in `Cargo.lock`.

## 0.8.1 [2026-09-23]

- Require `cryptoki` 0.12.1 or newer in the 0.12 series to fix the
  `CKA_ALLOWED_MECHANISMS` out-of-bounds read (RUSTSEC-2026-0286) in the optional
  PKCS#11 backend.
- Added `Provider::with_caller_managed_pairwise_subjects` for applications that
  already derive the final OIDC subject (ADR 0008). Providers remain public-only
  by default; opting in advertises and accepts `pairwise` client registrations
  while still rejecting unknown subject types. The caller owns sector validation
  and privacy guarantees. Grindvakt preserves the supplied subject unchanged
  through authorization, token exchange, refresh rotation, and UserInfo, allowing
  existing integrations to retain their subject values and account links.
- Bound caller-managed subject derivation to the client registration validated
  at issuance through `authorization_redirect_with_subject_resolver` and
  `authorization_redirect_with_claims_and_subject_resolver`. Observed registration
  changes or removal during resolution abort issuance. Methods accepting a
  precomputed subject now accept only public-subject registrations, preventing
  an earlier public subject from being reused after a switch to pairwise.
- Provider discovery metadata now advertises the `implicit` grant alongside
  the supported implicit and hybrid response types.
- **Breaking:** `OAuthError::to_redirect` requires the validated response
  mode, `Provider::new` is fallible so it can reject provider-wide symmetric
  `HS*` ID-token signing keys, and the direct JWKS/UserInfo fetch helpers
  require their associated issuer.
- Remote issuers and federation entities can no longer advertise loopback
  HTTP service endpoints. The loopback development exception applies only
  when the issuer/entity is itself a loopback HTTP origin.
- Token requests that present more than one client-authentication method are
  rejected with `invalid_client`, as required by RFC 6749 section 2.3.

## 0.8.0 [2026-09-03]

- Hardened OIDC authorization responses: all advertised standard response
  types are implemented, token-bearing responses use fragments, hybrid hashes
  are emitted, and response-type order is handled per RFC 6749.
- Hardened RP validation with exact issuer matching, safe endpoint policy,
  mandatory token-response fields, explicit signing-algorithm and audience
  policy, `azp` validation, public-client PKCE, and UserInfo subject binding.
- **Breaking:** Public authorization and token-endpoint parsers now require
  ordered parameter pairs so duplicate protocol parameters cannot be erased by
  a map before validation. Reserved authorization extras are also rejected;
  authorization errors preserve the validated response mode.
- Malformed registered redirect URIs and RP/federation service endpoints with
  raw whitespace or control characters are rejected, every supplied PKCE tuple
  must use canonical S256, and narrowed refresh grants remove standard claims
  for scopes the client dropped.
- RP ID-token validation accepts a one-element JSON array in `aud` without
  requiring `azp`, while retaining `azp` and trust checks for multiple
  audiences and for any explicitly supplied `azp` claim.
- **Breaking:** Authorization requests preserve repeated RFC 8707 `resource`
  parameters in `AuthorizationRequest::resources` instead of `extra`, while
  duplicate single-valued parameters remain invalid.
- DPoP always fails closed without an atomic replay store, and `DpopProof` is
  opaque so only validation can create it.
- **Breaking:** `Provider::new` now requires an explicit `TokenUseStore`, and
  RP token verification / UserInfo APIs require their security-policy inputs.

## 0.7.2 [2026-08-31]

- Added `Provider::authorization_redirect_with_claims` for OP-asserted claims
  that preserve their JSON types and take precedence over released attributes.
  Reserved ID-token claims, including the canonical `acr`, cannot be overridden,
  and typed claims are preserved across authorization-code, refresh-token, and
  rotated-refresh exchanges and in UserInfo responses.

## 0.7.1 [2026-08-24]

- Added exact, case-sensitive `AuthorizationRequest::has_prompt` handling and
  authorization-request validation that rejects `prompt=none` when combined
  with another prompt value, as required by OpenID Connect Core §3.1.2.1.

## 0.7.0 [2026-08-05]

Security fixes from a completed audit (see ADR 0003–0007). Some are
behavior-breaking for non-compliant clients; see the ADRs for migration
notes.

- Depends on jose-rs 0.7.0, which hard-rejects JWTs pinning an unknown
  `kid`, and JWEs carrying a `zip` member or an empty `crit` array
  (jose-rs ADR 0002–0004).

- `private_key_jwt` client assertions must now carry `iat`, `exp`
  (age-bounded to 300 seconds by default, adjustable via
  `Provider::with_client_assertion_max_age`) and a `jti`; the `jti` is
  consumed once through the `TokenUseStore` under a hashed, client-scoped
  key, with the TTL capped at the acceptance window (`max_age` + leeway), so
  a captured assertion can no longer be replayed and a hostile client cannot
  fill the store with long-lived entries. The `invalid_client` error no
  longer embeds jose-rs validation details (ADR 0003).
- The authorization endpoint now rejects requested scopes outside the
  client's registered scope set (`invalid_scope`; clients registered without
  a `scope` remain unrestricted), requires a `nonce` for
  implicit/hybrid response types, and the hybrid `code id_token` flow now
  defaults to the fragment response mode so the id_token is not leaked in the
  URL (ADR 0004).
- The token endpoint now requires the `redirect_uri` to be echoed and to match
  the one sealed in the authorization code (RFC 6749 §4.1.3), and rejects the
  `authorization_code` grant for clients not registered for it (ADR 0004).
- Token-endpoint client authentication is pinned to the registered
  `token_endpoint_auth_method`: presenting a valid secret over the wrong
  method (basic vs post) is rejected. Discovery no longer advertises
  `request_parameter_supported` / `claims_parameter_supported`, which were
  never implemented (ADR 0005).
- RP side: `verify_id_token` requires `exp` and `iat`; `discover` requires an
  https issuer (http only for loopback hosts) and verifies the returned
  issuer matches the requested one (OIDC Discovery §4.3); `exchange_code`
  truncates upstream error bodies to 512 characters and strips control
  characters (ADR 0006).
- `InMemoryClientStore` removes expired entries on `get` and sweeps them on
  `put_with_ttl`, bounding memory growth from TTL'd federation registrations.
  Federation entity statements and resolve responses are now verified with
  `require_exp` (ADR 0007).

## 0.6.2 [2026-08-04]

- Updated to `jose-rs` 0.6.0 and `kryptering` 0.5.0, migrated key loading to
  kryptering's opaque software-key API, and refreshed all compatible
  dependencies. `jose-rs` 0.6.0 is now resolved directly from crates.io.
- Updated all GitHub Actions workflows to the SHA-pinned `actions/checkout`
  v7.0.1 release.

## 0.6.1 [2026-07-07]

- Updated the JOSE/signing dependency stack to `jose-rs` 0.5.1 and
  `kryptering` 0.4.1. This keeps grindvakt's direct signing backend aligned
  with the JOSE layer, removes the duplicate `kryptering` 0.3 dependency from
  the lockfile, and preserves the existing software and PKCS#11 signing APIs.
- Refreshed the PKCS#11 documentation and package comments for kryptering
  0.4's provider selection behavior.

## 0.6.0 [2026-07-02]

- Added replay protection for authorization codes and refresh tokens via the
  new `TokenUseStore` trait. `Provider::new` installs the single-process
  `InMemoryTokenUseStore` by default; multi-replica deployments can supply a
  shared store with `Provider::with_token_use_store` (see ADR 0001/0002).
- Hardening: public code-flow clients (`token_endpoint_auth_method` of
  `none`) must now use PKCE with `S256`; authorization requests with no
  code challenge or the `plain` method are rejected, and legacy codes that
  were issued to a public client without S256 PKCE are refused at the token
  endpoint.
- Hardening: OpenID Federation resolve-response trust chains are now
  validated end to end: required entity-statement claims, `iat`/`exp`
  timestamps, issuer/subject linkage between adjacent statements, trust-
  anchor self-signature, and each statement's signature against the keys of
  its superior.
- Added an optional `redis` feature exposing `RedisStore`, a Redis-backed
  `TokenUseStore` (`SET key 1 EX ttl NX`). Commands run over a shared async
  `ConnectionManager` (tokio-backed, multiplexed, auto-reconnecting), so token
  consumption never blocks the async executor and no per-call connection is
  opened. `RedisStore::from_client` now returns `redis::RedisResult<Self>`.
- **Breaking**: `Provider` gained a `token_use_store` member, which is private
  (set it with `Provider::with_token_use_store`). Code constructing `Provider`
  with struct-literal syntax must switch to `Provider::new`; this also shields
  downstream users from similar breakage when future fields are added.
- Token-use store failures now surface to OAuth clients as a generic
  `server_error` description instead of echoing the underlying store error
  (which could leak infrastructure details such as Redis connection strings);
  the store error is logged via `tracing` instead.
- `InMemoryTokenUseStore::consume` no longer sweeps the whole map on every
  call; expired entries are detected on lookup and full sweeps run at most
  once a minute, keeping consumption O(1) amortized under load.
- The minimum supported Rust version is now 1.88 (required by current
  `redis` crates).

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
