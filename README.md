# grindvakt

A reusable, **runtime-agnostic** OAuth 2.0 / OpenID Connect / OpenID Federation
protocol library for Rust, built on [`jose-rs`](https://crates.io/crates/jose-rs).

`grindvakt` is independent of any web framework and of any particular identity
proxy. The OP (provider) engine and the RP (client) flow are pure logic;
outbound HTTP is injected through the `http::HttpClient` trait, so the same code
runs under actix-web, axum, or anything else.

## What's inside

- **OP / provider** (`provider::Provider`) — discovery, JWKS, authorization,
  token endpoint (`authorization_code`, `client_credentials`, `private_key_jwt`,
  DPoP-bound), userinfo. Tokens are stateless (codes/access tokens as JWE,
  id_tokens as signed JWTs), so the token/userinfo endpoints do no server lookups.
- **RP / client** (`rp`) — discovery, authorization request, code exchange,
  id_token verification, userinfo.
- **OpenID Federation 1.1** (`federation`).
- **DPoP** (`dpop`) — RFC 9449 sender-constrained tokens, with a pluggable
  replay store and optional stateless server nonces.
- **Foundational primitives** — `error`, `http`, `keys` (PEM/DER/JWK signing-key
  loading), `mac` and `util`, re-used by downstream crates.

## License

BSD-2-Clause. Copyright (c) 2026, Kushal Das.
