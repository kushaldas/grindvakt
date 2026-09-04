# ADR 0001: Token Replay State for Authorization Codes and Refresh Tokens

## Status

Amended for 0.8.0: the store is now an explicit constructor argument.

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
- `Provider::new` requires the deployment to select a store explicitly;
- deployments can still replace it later with `Provider::with_token_use_store`.

## Consequences

Single-process deployments may explicitly select `InMemoryTokenUseStore`.
Multi-replica deployments must provide a shared atomic store, such as Redis or
a database table with an insert-if-absent operation. Making the choice explicit
prevents a production deployment from silently inheriting process-local replay
protection.

Access tokens remain self-contained and do not require a lookup at userinfo.
