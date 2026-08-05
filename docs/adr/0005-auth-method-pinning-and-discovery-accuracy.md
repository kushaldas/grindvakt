# ADR 0005: Client Authentication Method Pinning and Discovery Accuracy

## Status

Accepted.

## Context

A security audit found two related registration-honesty issues:

1. `authenticate_client` verified the client secret regardless of the client's
   registered `token_endpoint_auth_method`: a client registered for
   `client_secret_basic` could authenticate with `client_secret_post` (and
   vice versa). The registered method is a security property of the
   registration and must pin the presented one.
2. The discovery document advertised `request_parameter_supported: true` and
   `claims_parameter_supported: true`, but neither the `request` (RFC 9101)
   nor the `claims` authorization parameter is implemented. Advertising
   unimplemented parameters misleads RPs into relying on behavior the OP does
   not enforce.

## Decision

- `check_secret` now takes the presented method and rejects authentication
  when it differs from the registered `token_endpoint_auth_method`
  (`invalid_client`).
- `ProviderMetadata::new` defaults both `request_parameter_supported` and
  `claims_parameter_supported` to `false`.

## Consequences

Clients must authenticate with the exact method they registered. RPs parsing
discovery will no longer attempt request objects or `claims` parameters
against a default-configured provider; deployments that later implement either
parameter can flip the corresponding flag.
