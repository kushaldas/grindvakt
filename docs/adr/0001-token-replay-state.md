# ADR 0001: Token Replay State for Authorization Codes and Refresh Tokens

## Status

Accepted.

## Context

`grindvakt` seals authorization codes, access tokens, and refresh tokens as
encrypted self-contained tokens. This keeps endpoint logic runtime-agnostic and
avoids a lookup for ordinary access-token validation.

Authorization codes and refresh tokens have stricter replay requirements:
authorization codes are one-time credentials, and refresh-token rotation only
invalidates the old token if the server remembers that it was consumed.
Without that memory, a captured code or old refresh token can be replayed until
its own expiry.

## Decision

The provider now requires a small `TokenUseStore` for one-time token use:

- authorization codes are consumed during the token exchange;
- refresh tokens are consumed before a rotated refresh token is issued;
- stored values are SHA-256 hashes with a token-kind prefix, retained only until
  the token expiry;
- `Provider::new` installs an in-memory single-process store by default;
- deployments can replace it with `Provider::with_token_use_store`.

## Consequences

Single-process deployments get replay protection without extra setup. Multi-
replica deployments must provide a shared atomic store, such as Redis or a
database table with an insert-if-absent operation, otherwise replay protection
is only per process.

Access tokens remain self-contained and do not require a lookup at userinfo.
