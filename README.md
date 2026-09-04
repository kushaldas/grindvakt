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

## HSM / PKCS#11 signing (optional)

Enable the `pkcs11` feature to keep signing keys on a hardware token (SoftHSM2,
Kryoptic, …) so the private key never leaves the module. All asymmetric signing
flows — id_tokens, federation entity statements, RP client assertions and signed
request objects — then sign over PKCS#11 (`C_Sign`). Symmetric token sealing
(access/refresh/authorization codes) stays software-only.

```toml
grindvakt = { version = "0.6", features = ["pkcs11"] }
```

```rust
use grindvakt::{signing_key_from_pkcs11, Pkcs11KeyConfig};
use grindvakt::jose_rs::algorithm::JwsAlgorithm;

let key = signing_key_from_pkcs11(&Pkcs11KeyConfig {
    module_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
    pin: std::env::var("PKCS11_PIN").unwrap(),
    key_label: "op-signing-key".into(), // CKA_LABEL of the key pair
    alg: JwsAlgorithm::ES256,
    kid: Some("op-key-1".into()),
})?;
// `key` is an asymmetric SigningKey:
// Provider::new(metadata, key, ...)?, federation, and rp all work.
```

Supported algorithms: RSA (`RS256/384/512`), EC `ES256`/`ES384`, and `EdDSA`
(Ed25519). The public key is read back from the token and published through
`key.to_public_jwks()`. **Limitation:** grindvakt's current `Pkcs11KeyConfig`
uses kryptering's default provider selection, which accepts exactly one
initialized token. Keys are then identified by `CKA_LABEL`.

## License

BSD-2-Clause. Copyright (c) 2026, Kushal Das.
