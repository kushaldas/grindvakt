# ADR 0004: Stricter Authorization and Token Request Validation

## Status

Accepted.

## Context

A security audit found three validation gaps in the authorization and token
endpoints:

1. `validate_authorization_request` never compared the requested scope against
   the client's registered scope set for the code flow (the
   `client_credentials` grant already intersected scopes).
2. Implicit and hybrid response types (`id_token token`, `code id_token`) were
   accepted without a `nonce`, which OIDC Core requires, and the hybrid
   `code id_token` flow defaulted to the query response mode, leaking the
   id_token into URLs (browser history, logs, Referer headers).
3. At the token endpoint, a code could be redeemed without echoing the
   `redirect_uri` (RFC 6749 §4.1.3 requires it when the authorization request
   carried one), and the `authorization_code` grant was not checked against
   the client's registered `grant_types`.

## Decision

- `validate_authorization_request` rejects any requested scope outside the
  client's registered scope set with `invalid_scope`, mirroring the
  `client_credentials` allowlist logic; a client with no registered scope
  allows none.
- `validate_authorization_request` rejects implicit/hybrid requests without a
  `nonce` with `invalid_request` (OIDC Core §3.2.2.1 / §3.3.2.1).
- `AuthorizationRequest::use_fragment` defaults to the fragment response mode
  whenever the response type returns an id_token from the authorization
  endpoint, including hybrid flows (OIDC Core §3.3.2.5). An explicit
  `response_mode` still wins.
- `handle_authorization_code` requires the token request to echo the exact
  `redirect_uri` sealed in the code (`invalid_grant` otherwise), and rejects
  clients not registered for the `authorization_code` grant, mirroring the
  `client_credentials` and `refresh_token` grant gates.

## Consequences

Client registrations without a `scope` field can no longer obtain codes for
any scope — deployments must register the scopes each client may request
(including `openid`). Hybrid clients must send a nonce and now receive the
authorization response in the fragment by default. RPs that previously omitted
`redirect_uri` from the token request must echo it.
