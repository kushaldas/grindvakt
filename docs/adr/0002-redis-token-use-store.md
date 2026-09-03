# ADR 0002: Optional Redis Token-Use Store

## Status

Amended for 0.8.0: the token-use store is now an explicit constructor argument.

## Context

ADR 0001 introduced `TokenUseStore` so authorization codes and refresh tokens
can be consumed exactly once. The in-memory implementation is useful for tests
and single-process deployments, but it is not enough for providers running more
than one process or replica. Since 0.8.0, callers select the store explicitly.

Those deployments need a shared store with an atomic insert-if-absent operation
and automatic expiry. Redis is a common fit for this specific shape of state:
small keys, short lifetimes, and a single command that can record first use and
reject replays.

## Decision

`grindvakt` provides an optional `redis` feature exposing `RedisStore`.

`RedisStore` implements `TokenUseStore` by writing replay markers with:

```text
SET <key> 1 EX <ttl-seconds> NX
```

This keeps the first successful token use atomic across provider replicas. A
nil Redis response is treated as an already-consumed token. Replay markers use
the same token hash values as other `TokenUseStore` implementations and are
kept only until the original token expiry.

The feature is optional so library users that do not deploy Redis do not pull in
Redis dependencies. `Provider::new` requires a `TokenUseStore`; Redis-backed
deployments pass `RedisStore` there, while a single-process deployment may pass
`InMemoryTokenUseStore`.

## Consequences

Multi-replica providers can use a maintained shared replay store without writing
their own adapter. Single-process and non-Redis users keep the existing optional
dependency footprint while making the process-local choice explicit.

Redis availability becomes part of the token endpoint's availability for
deployments that choose `RedisStore`. If Redis rejects the command or cannot be
reached, token exchange fails closed with a server error rather than allowing a
possible replay.

Integration tests that require a live Redis server are ignored by default and
run explicitly through the `redis-test` Justfile target or CI Redis service.
