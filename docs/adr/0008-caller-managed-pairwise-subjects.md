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

Client registrations can be replaced while an interactive login is in progress.
Revalidating a request against a fresh registration while accepting a subject
chosen from an earlier registration can reinterpret a public identifier as
pairwise. Subject derivation and issuance must share the validated registration.

## Decision

Add `Provider::with_caller_managed_pairwise_subjects()` as an explicit startup
opt-in for trusted embedding applications.

- `Provider::new` continues to accept and advertise only `public` subjects.
- Opt-in advertises exactly `public` and `pairwise`. Calling the builder more
  than once does not duplicate metadata entries.
- A private provider flag enables the exact registered `pairwise` subject type.
  Discovery metadata is not an authorization switch. Unknown or incorrectly
  cased subject types remain rejected with `unauthorized_client`.
- All authorization response methods revalidate the request before minting,
  retaining the subject-type gate even when callers skip initial validation.
- Pairwise issuance requires `authorization_redirect_with_subject_resolver` or
  `authorization_redirect_with_claims_and_subject_resolver`. A synchronous
  callback receives the registration validated at issuance and returns the
  final subject. The string-subject methods accept only public registrations,
  even after opt-in, so they cannot bypass the derivation boundary.
- After resolution, compare the complete serialized registration with the
  current store entry. Reject any observed change or removal with
  `unauthorized_client`; then mint synchronously using the same snapshot without
  further registration lookups. Structural JSON equality includes JWKs, whose
  upstream types do not implement equality, and future serialized fields.
  Compare flattened JWK extensions separately so they cannot mask changes to
  dedicated fields in programmatically constructed keys.
- No new hashing or normalization is applied. Empty subjects remain rejected,
  resolver errors propagate unchanged, and released attributes or extra claims
  cannot overwrite `sub`.
- Authorization artifacts, code exchange, refresh rotation, and UserInfo retain
  the supplied subject using the existing token representation.

The application must inspect the resolver's supplied registration and implement
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
Existing public-subject callers can keep their string-subject API. Pairwise
callers must migrate to a resolver that selects the subject using its supplied
registration. Applications needing asynchronous mapping lookups must preload
trusted data and select the mapping inside that synchronous callback.
The default remains public-only, and the runtime-agnostic library gains no new
network, storage, or cryptographic dependencies.

The final registration read is a snapshot check, not transactional exclusion of
later writes. Issued artifacts retain that snapshot's subject; later registration
changes do not reinterpret it. External sector policy is application-owned and
is outside this comparison. Even a benign registration edit during resolution
aborts issuance conservatively; the caller can restart with fresh validation.

Misuse by a trusted embedding application can still disclose a shared identifier
across sectors. This remains the caller's responsibility and is documented on
the builder and authorization methods. Applications should test their own
derivation for stability, sector separation, and existing-account continuity.

Grindvakt's regression tests cover default rejection at validation and issuance,
metadata-only changes not enabling pairwise, explicit opt-in and unknown-type
rejection, rejection through the precomputed-subject APIs after registration
replacement, resolution against the current snapshot, changes/removal during
resolution (including redirect and JWK changes), resolver errors, and
preservation of supplied subjects across code/implicit/hybrid
responses, token exchange, repeated refresh rotation, and UserInfo. These tests
verify the library contract, not an application's derivation algorithm.

## References

- [OIDC Core 1.0 section 8: Subject Identifier Types](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
- [OIDC Core 1.0 section 8.1: Pairwise Identifier Algorithm](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)
- `src/provider.rs`, `src/client.rs`, and `tests/op_flow.rs`
