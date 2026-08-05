# ADR 0003: private_key_jwt Client Assertion Expiry, Replay Protection, and Error Hygiene

## Status

Accepted.

## Context

A security audit found that `Provider::verify_private_key_jwt` accepted client
assertions (RFC 7523) without an `exp` claim and without any bound on token
age, and did not track assertion `jti` values. A captured assertion could
therefore be replayed to the token endpoint indefinitely — or, for an
assertion without `exp`, forever. In addition, the `invalid_client` error
embedded the raw jose-rs validation error, leaking library internals to the
caller.

## Decision

`verify_private_key_jwt` now:

- requires `exp` and bounds assertion age via `Validation::require_exp()`
  and `Validation::with_max_age(...)`; the bound defaults to 300 seconds
  (`DEFAULT_CLIENT_ASSERTION_MAX_AGE`) and can be widened with
  `Provider::with_client_assertion_max_age` for clients that cannot mint
  fresh assertions per token request;
- requires a `jti` and consumes it exactly once through the existing
  `TokenUseStore` under the key `assertion:{client_id}:{jti}` with a TTL
  running until the assertion's `exp`, so a captured assertion cannot be
  replayed within its lifetime;
- returns a generic `client_assertion validation failed` description, keeping
  the jose-rs detail for `tracing` logs only (matching the store-error
  handling already used for code/refresh-token consumption).

## Consequences

Deployments using the default in-memory `TokenUseStore` get single-process
replay protection; multi-replica deployments must install a shared store
(e.g. `RedisStore`, ADR 0002) for the protection to hold across replicas — the
same caveat that already applies to authorization codes and refresh tokens.
Assertion issuers must now include `iat`, `exp` (by default at most 300
seconds after `iat`, configurable via `with_client_assertion_max_age`), and
`jti`; `grindvakt::rp::build_client_assertion` already emits all three.
Widening the age bound extends how long a captured assertion stays usable
and how long the `jti` store retains entries; the single-use `jti`
requirement is not configurable.
