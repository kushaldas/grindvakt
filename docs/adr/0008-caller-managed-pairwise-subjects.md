# ADR 0008: Caller-Managed Pairwise Subject Identifiers

## Status

Accepted for 0.8.1, 2026-09-23.

## Context

Grindvakt receives a final subject identifier from its embedding application
when creating an authorization response. Identity proxies can already have an
established subject derivation or persistent mapping outside the protocol
library. Preserving those identifiers matters because relying parties use
the issuer and subject together to identify existing accounts.

Before 0.8.0, the provider accepted `pairwise` registrations without deriving or
checking pairwise subjects itself. That did not establish privacy guarantees,
although an application could correctly supply an externally derived subject.
Version 0.8.0 limited discovery and authorization to `public` subjects, preventing
unsupported guarantees but also rejecting those valid external implementations.

OIDC Core section 8.1 requires pairwise identifiers to be stable within a sector,
different across sectors, and non-reversible by relying parties. Grindvakt does
not currently own sector registration validation, a derivation secret, or a
persistent subject mapping. Silently accepting `pairwise` for every caller would
misrepresent the default provider's capabilities. Automatically introducing a
new derivation would also change existing subjects and could break account links.

## Decision

Add `Provider::with_caller_managed_pairwise_subjects()` as an explicit startup
opt-in for trusted embedding applications.

- `Provider::new` continues to accept and advertise only `public` subjects.
- Opt-in advertises exactly `public` and `pairwise`. Calling the builder more
  than once does not duplicate metadata entries.
- A private provider flag enables the exact registered `pairwise` subject type.
  Discovery metadata is not an authorization switch. Unknown or incorrectly
  cased subject types remain rejected with `unauthorized_client`.
- Both authorization response methods revalidate the request before minting,
  retaining the subject-type gate even when callers skip initial validation.
- The caller supplies the final subject through the existing `sub` argument.
  No new hashing or normalization is applied. Empty subjects remain rejected,
  and released attributes or extra claims cannot overwrite `sub`.
- Authorization artifacts, code exchange, refresh rotation, and UserInfo retain
  the supplied subject using the existing token representation.

The application must inspect the validated client's registration and implement
the appropriate public or pairwise subject policy. For pairwise registrations,
it owns sector selection and validation, stable derivation or storage, secret
management, and separation between sectors. A user-controlled request must not
enable the provider option or choose an unchecked sector. An upstream subject
must not be passed through as pairwise merely because its source labels it so.

This contract is intentionally caller-managed. The flag acknowledges an
application capability; it does not prove that an arbitrary supplied string is
pairwise. Grindvakt cannot establish that property from the final identifier.

## Alternatives

- **Unconditionally restore acceptance:** rejected because it would again
  advertise pairwise support without requiring an application implementation.
- **Derive inside Grindvakt now:** deferred. A built-in resolver would require
  sector metadata, validated sector registration, derivation/storage policy, and
  migration controls. A new algorithm must not silently replace existing IDs.
- **Change client registrations to public:** valid only when the deployment
  accepts public-subject semantics; it does not preserve a pairwise contract.

## Consequences

Correct external implementations can restore pairwise registration acceptance
without changing their users' subjects. Integrations must retain their original
algorithm, secret, sector mapping, and stored values when enabling the option.
The default remains public-only, and the runtime-agnostic library gains no new
network, storage, or cryptographic dependencies.

Misuse by a trusted embedding application can still disclose a shared identifier
across sectors. This remains the caller's responsibility and is documented on
the builder and authorization methods. Applications should test their own
derivation for stability, sector separation, and existing-account continuity.

Grindvakt's regression tests cover default rejection at validation and issuance,
metadata-only changes not enabling pairwise, explicit opt-in and unknown-type
rejection, and preservation of supplied subjects across code/implicit/hybrid
responses, token exchange, repeated refresh rotation, and UserInfo. These tests
verify the library contract, not an application's derivation algorithm.

## References

- [OIDC Core 1.0 section 8: Subject Identifier Types](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
- [OIDC Core 1.0 section 8.1: Pairwise Identifier Algorithm](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
- `src/provider.rs`, `src/client.rs`, and `tests/op_flow.rs`
