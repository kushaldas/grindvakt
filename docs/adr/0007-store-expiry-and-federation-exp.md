# ADR 0007: Store Expiry Hygiene and Federation Statement Expiry

## Status

Accepted.

## Context

A security audit found two expiry-handling gaps:

1. `InMemoryClientStore` hid expired entries on read but never removed them,
   so a federation frontend auto-registering RPs with TTLs grew the map
   unboundedly — a memory-exhaustion vector.
2. Federation trust-anchor entity configurations and resolve responses were
   verified without requiring `exp` (OpenID Federation 1.0 requires it on
   entity statements and resolve responses); a statement without an expiry
   could be replayed indefinitely.

## Decision

- `InMemoryClientStore::get` now takes the write lock and removes an expired
  entry on lookup, and `put_with_ttl` opportunistically sweeps all expired
  entries before inserting. This mirrors the existing
  `InMemoryTokenUseStore` purge approach (ADR 0001): correctness never depends
  on the sweep; it only bounds memory growth.
- `federation::verify_typed` — the single verification path for entity
  statements, trust-anchor entity configurations, and resolve responses — now
  uses `Validation::require_exp()`.

## Consequences

Memory use of the in-memory client store stays proportional to live
registrations. Federation entities must publish `exp` on their statements and
resolve responses, as the specification already requires; the trust-chain
statement validation added in 0.6.0 enforced the same requirement for chain
members.
