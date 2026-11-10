# Dependency ecosystem status

**Last reviewed:** 2026-11-10  
**Tool:** `cargo outdated --depth 1` against the top-level `Cargo.toml`  
**Scope:** direct dependencies only

This document records dependency updates, remaining upstream blockers, and
verification evidence for grindvakt releases.

## Updates applied for 0.11.0 on 2026-11-10

The RustCrypto migration described in the historical sections below was
completed in 0.10.0. The current stack uses `digest` 0.11, `signature` 3,
`sha2` 0.11, `hkdf` 0.13, `p256`/`p384` 0.14 and `ed25519-dalek` 3.

### Current dependency status

`jose-rs` 0.11.0 requires `kryptering` 0.7.1 and stable `rsa` 0.10,
resolving the exact RSA prerelease pin in jose-rs 0.10.0. The three crates
have been upgraded together. Their published manifests use the same
`digest` 0.11 and `signature` 3 generation. Jose-rs 0.11.0 declares Rust
1.89, matching grindvakt's existing minimum.

No direct dependency upgrades remain blocked.

### Applied updates

- `jose-rs` 0.10.0 → 0.11.0, `kryptering` 0.7.0 → 0.7.1,
  `rsa` 0.10.0-rc.19 → stable 0.10.0; removed duplicate `base64` 0.22.1.
  Key loading uses RSA's renamed `PrivateKey` and `PublicKey` types.
- `redis` 1.8.0 → 1.8.1; normal and development manifests now both require
  at least 1.8.1.
- `aes` 0.9.3 → 0.9.4, `arc-swap` 1.9.3 → 1.9.5,
  `async-lock` 3.4.2 → 3.5.0, `crypto-bigint` 0.7.10 → 0.7.11,
  `ctutils` 0.4.6 → 0.4.8, `inout` 0.2.5 → 0.2.6,
  `itoa` 1.0.18 → 1.0.19, `log` 0.4.34 → 0.4.35,
  `ml-dsa` 0.1.1 → 0.1.2, `ml-kem` 0.3.3 → 0.3.4,
  `module-lattice` 0.2.3 → 0.2.4, `pkcs1` 0.8.0-rc.5 → 0.8.0,
  `smallvec` 1.16.4 → 1.16.5, `syn` 3.0.9 → 3.0.10,
  `utf8_iter` 1.0.4 → 1.1.0; added its new dependency `utf_types` 1.0.0.

### Verification

- `cargo outdated --depth 1` — all dependencies are up to date, with no
  exclusions needed.
- `cargo test --locked --all-features` — 228 unit tests, 44 integration
  tests and 3 documentation tests passed.
- `cargo test --locked --all-features --test redis_store -- --ignored` —
  both tests passed against an isolated temporary Redis server.
- `cargo +1.89.0 check --locked --all-features` — passed, preserving the
  declared minimum Rust version.
- `cargo clippy --locked --all-features --all-targets -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- `cargo audit --deny warnings` — passed with no advisories or warnings.

## Historical reviews

## Status at a glance

| Crate | Current | Latest | Blocker |
|---|---:|---:|---|
| `ed25519-dalek` | 2.2.0 | 3.0.0 | `signature` 2 → 3 and `rand_core` 0.6 → 0.10 wave |
| `hkdf` | 0.12.4 | 0.13.0 | `digest` 0.10 → 0.11 wave |
| `p256` | 0.13.2 | 0.14.0 | `digest` 0.10 → 0.11 and `signature` 2 → 3 wave |
| `p384` | 0.13.1 | 0.14.0 | `digest` 0.10 → 0.11 and `signature` 2 → 3 wave |
| `sha2` | 0.10.9 | 0.11.0 | `digest` 0.10 → 0.11 wave |

## RustCrypto trait wave

The new releases use mutually incompatible generations of the `digest`,
`signature`, and `rand_core` traits. Grindvakt also passes key material through
`jose-rs` and `kryptering`, so upgrading only the direct leaf crates would leave
duplicate cryptographic stacks in the lockfile. The direct key loader now uses
provider-neutral PKCS#8/SPKI encodings at the `kryptering` boundary, but the
dependency graph should still move as one coordinated wave.

### Upstream pins on the current stack

| Consumer | Relevant exact pins |
|---|---|
| `jose-rs` 0.7.1 | `kryptering = "0.6"`, `sha2 = "0.10"`, `p256 = "0.13"`, `p384 = "0.13"`, `ed25519-dalek = "2.1"`, `pkcs8 = "0.10"` |
| `kryptering` 0.6.0 | `digest = "0.10"`, `sha2 = "0.10"`, `hmac = "0.12"`, `ecdsa = "0.16"`, `signature = "2"`, `p256 = "0.13"`, `p384 = "0.13"`, `ed25519-dalek = "2.1"`, `pkcs8 = "0.10"` |

The latest leaves require the new traits: `sha2` 0.11 uses `digest` 0.11;
`hkdf` 0.13 uses `hmac` 0.13; `p256`/`p384` 0.14 use `sha2` 0.11; and
`ed25519-dalek` 3 uses `sha2` 0.11, `signature` 3, and `rand_core` 0.10.

### Unblock condition

Upgrade these direct crates together after `jose-rs` and `kryptering` release
versions based consistently on the new `digest`, `signature`, and `rand_core`
traits. Then rebuild and test the full feature set before accepting the new
lockfile.

## Updates applied for 0.8.2 on 2026-09-28

- `jose-rs` 0.7.0 → 0.7.1.
- `kryptering` 0.5.0 → 0.6.0, matching jose-rs and removing the duplicate
  0.5 backend from the lockfile. Both upstream crates declare Rust 1.88.
- Compatible direct updates: `async-trait` 0.1.91 → 0.1.92, `base64` 0.23.0 →
  0.23.1, `redis` 1.5.0 → 1.7.1, and `thiserror` 2.0.19 → 2.0.21.
- Refreshed compatible transitive dependencies in `Cargo.lock`, except `aes`:
  0.9.3 declares Rust 1.89, so the lockfile retains 0.9.2 (Rust 1.85) to
  preserve grindvakt's Rust 1.88 minimum. Future lockfile updates must retain
  an MSRV-compatible version or deliberately raise the minimum.
- The five deferred direct upgrades in the table above still depend on a
  coordinated RustCrypto migration. Pins were checked in the downloaded
  crates.io manifests for jose-rs 0.7.1 and kryptering 0.6.0; no compile probe
  was needed. Existing mixed trait generations inside the upstream backends
  remain upstream implementation details.

Verification:

- `cargo build --all-features` — passed before the MSRV compatibility pin.
- `cargo +1.88.0 check --locked --all-features` — passed on the final lockfile.
- `cargo test --locked --all-features` — 125 passed; 2 server tests ignored.
- `cargo test --locked --all-features --test redis_store -- --ignored` — both
  passed against an isolated temporary Redis server on the final lockfile.
- `cargo clippy --locked --all-features --all-targets -- -D warnings` — passed.
- `cargo audit --deny warnings` — passed with no advisories or warnings.

## Updates applied for 0.6.2 on 2026-08-04

- `jose-rs` 0.5.1 → 0.6.0 from crates.io.
- `kryptering` 0.4.1 → 0.5.0.
- `base64` 0.22.1 → 0.23.0 and `pem` 3.0.6 → 4.0.0.
- Compatible direct updates: `async-trait` 0.1.89 → 0.1.91, `redis` 1.3.0 →
  1.5.0, `serde` 1.0.228 → 1.0.229, `serde_json` 1.0.150 → 1.0.151,
  `thiserror` 2.0.18 → 2.0.19, `time` 0.3.53 → 0.3.55, and `tokio` 1.52.3 →
  1.53.1.
- Removed redundant direct `pkcs8` and `sec1` dependencies; the algorithm
  crates' re-exported encoding traits provide the APIs grindvakt uses.
- Refreshed all compatible transitive dependencies in `Cargo.lock`.

Verification:

- `cargo build --all-features` — clean
- `cargo test --all-features` — 71 passed, 2 Redis-server tests ignored
- `cargo clippy --all-features --all-targets -- -D warnings` — clean
- `cargo audit --deny warnings` — no advisories

## How to re-evaluate

Run `cargo outdated --depth 1`, then inspect the `jose-rs` and `kryptering`
manifests. Once both have moved to the new trait versions, update the whole wave
and repeat the verification commands above.
