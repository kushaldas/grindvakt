# ADR 0006: Relying-Party Side Verification and Discovery Hardening

## Status

Accepted.

## Context

A security audit found three weaknesses on the relying-party (client) side of
the crate:

1. `verify_id_token` did not require `exp` (or `iat`), so an id_token without
   an expiry — valid forever — would be accepted.
2. `discover` accepted plain-http issuer URLs and never checked that the
   issuer returned in the metadata matches the requested issuer, which OIDC
   Discovery §4.3 mandates; a spoofed or misdirected discovery response could
   silently re-point the RP at an attacker's endpoints.
3. `exchange_code` embedded the raw upstream token-endpoint error body in the
   returned error, letting a hostile or broken OP inject control characters
   (log/terminal injection) or unbounded text into logs and error responses.

## Decision

- `verify_id_token` uses `Validation::require_exp().require_iat()`.
- `discover` rejects non-https issuer URLs (plain http is allowed only for
  loopback hosts — localhost, 127.0.0.0/8, ::1 — for local development) and
  rejects metadata whose `issuer` does not match the requested issuer.
  Metadata endpoints inherit the plain-http exception only when that issuer
  is itself a loopback HTTP origin; remote issuers cannot redirect requests
  to local plaintext endpoints.
- `exchange_code` strips control characters from the upstream error body and
  truncates it to 512 characters before embedding it in the error.

## Consequences

RP deployments must use https issuers outside local development, and upstreams
whose discovery document issuer differs (even by normalization) from the
configured issuer are rejected. id_tokens without `exp`/`iat` are refused; all
spec-compliant OPs emit both.
