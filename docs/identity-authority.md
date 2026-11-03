# Identity authority (LFCP-04-404 / R2)

The normative reference is the `spec-pr2` export of openlfcp/spec#2:
LFCP-WIRE-01 §§7.3, 15, 17.2–17.5, 18.1, 23.3, 25.2, 41, 62, 79 and 80.1.
The published vector pin is unchanged. Task 403 supplies the full identity
corpora and the updated baseline.

## Validation and signatures

Use `authority::validate_authorized` for a whole Resource chain, or resume it
from a previously derived `ControlState`. `propose_transition` adds the
coordinator's expected-head check. Accepted exact-byte repeats remain no-ops;
a fresh Device Grant carrying the previous leaf certificate is rejected.
Competing valid records remain `ControlConflict`; no branch is chosen.

`validate_chain` checks full structure, placement, all dependencies, and all
signatures before `ChainPolicy::authorize`. Device Grant issuers may be resolved
from any certificate in the body. Genesis uses its owner or, with field 5, the
required leaf. A transfer learns its new root from the offer and, with field 2,
requires the leaf to sign both accept and commit. All certificates, offers and
accepts are verified even with `SignaturesOnly`/`ResolveWith`; those policies
intentionally skip authority. They are insufficient for accepting a Resource.

`CertificateChain::require_root` is the dependency phase;
`verify_signatures(&PrincipalDescriptor)` is the signature phase. Passing the
wrong root descriptor is a local API error (`DeviceRootDescriptorMismatch`),
not `INVALID_SIGNATURE`. Device Grant roots must be known in the Resource's
previous state; external `CapabilityEngine::knowing` descriptors do not create
that dependency or standing. At forks, both directory and engine lookups use
the common prefix, never descriptors or authority from its later suffix.

`authority::apply` also validates placement, dependencies and **all** outer and
embedded signatures before applying one transition. `ControlRecord::sign` or
`ReceivedControlRecord::verify` alone checks only the outer signature. The
capability engine uses a private transition primitive after `validate_chain`
has completed these checks, without duplicating signature verification.

## Derived state

`ControlState` exposes read-only queries/iterators for:

| API | Meaning |
| --- | --- |
| `role`, `roles` | Permanent `Role::Device` or `Role::NonDevice` |
| `device`, `devices`, `bound` | Bindings, including intermediate-only and out-of-scope devices |
| `revocation`, `revocations` | Permanent revocations of exact `(root, device)` pairs |
| `root_standing` | Owner or subject of an active grant not listing `invite/claim` |
| `active_device` | Registered, with standing, neither leaf nor any current issuer revoked |
| `holds`, `abilities` | Root authority intersected with mask, or owning root's `owner/act` exception |
| `owner_action` | Owner or its active device with `owner/act` |
| `acts_for` | Active device's root, otherwise the Principal itself |
| `root_of` | Bound device's root even when inactive, otherwise the Principal itself |
| `same_root` | Equal `acts_for`, with at least one active device |

Bindings fix root, kind, mask and scope forever. Mask and scope equality is set
equality; scope is exposed sorted by raw Resource-ID bytes because Resource IDs
do not implement `Ord`. Exact received certificate bytes remain in `chain`.
Every chain device is bound and learned, but only the in-scope leaf is registered.
Re-certification changes only the leaf's current chain, leaf ID and issuers;
intermediates retain their own registration and current leaf chains. Transfer
field 2 leaves an already registered same-certificate-ID leaf unchanged.

Revoking a manager suspends descendants through their current issuer lists.
A new path can restore suspended devices; a revoked pair can never return.
Revocation of an unbound device creates neither a binding nor a role. Losing
standing deactivates devices without discarding registration; standing restored
by a later grant reactivates them if their chains are unrevoked. These facts are
Resource-local; no clock, profile document, server table or other Resource is read.

Capability Grants record `Grant::issuer_root` at the previous head. Parent-subject
and revoke-coverage comparisons use `acts_for`, letting siblings revoke grants
their root issued through another device. A non-owner-acting device cannot
delegate codes 1–10 outside its mask, in either ability list; parent bounds still
apply. Codes 11–13 and unknown codes pass through the delegation-mask bound.

Reason 3 revocations store the approved **payload digest**, before a prospective
leaf has been signed. An approved Device Grant must name the consumed kind-2
session of the same root and match that digest. A second consumption fails;
exact-byte replay is distinguished from a fresh proposal. The client remains
responsible for unsigned preflight, journal persistence and waiting for the
accepted consume record before signing (IDENTITY-PROFILE-01 §5.3, §9).

## Read, key and epoch integration

`ControlState::may_read` returns:

- `ReadAccess::Full`: ordinary reader or active invitation-subject exception.
- `ReadAccess::ControlPrefix(head)`: the registered device held `data/read`
  immediately before its direct Device Revoke. Only the Control prefix through
  that record is readable. A cascade alone, lost standing, intermediate-only
  binding or a mask that never conferred read gives no proof access.
- `ReadAccess::Denied`: no read access.

The prefix decision is retained in state and survives validator resume. The
server's existing `coordinator::Chain::may_read -> bool` belongs to the server
repository, not this SDK. V2 should consume this enum: prefix RESOURCE_OPENED
has just the revocation head, empty Have, no Snapshot or live subscription;
CONTROL_HAVE/GET stop at that head, all other reads fail. Full and prefix access
must never collapse to one boolean. Upload validation stays independent of the
session's read authority (§84).

`last_exposing_revocation` identifies the latest accepted Device Revoke that
removed any registered reader, directly or by cascade. Compare its sequence
with the current epoch's rotation for the profile's rotation policy. This is
a deterministic effect indicator, not automatic key rotation.

`can_distribute_key` accepts `key/distribute` or `same_root`, and still requires
a reading recipient or the invitation exception. Historical packages remain
valid and their epoch must exist at the referenced head. The existing Data Unit
and Snapshot policy hooks use device-aware `holds` at their referenced heads.
Later revocation does not rewrite history: the existing epoch cutoff bounds
old-head data and snapshots after rotation.

## Tests and R3 handoff

`tests/support/identity.rs` exposes `validate(&[Vec<u8>])` and
`transition(&ControlState, &[u8])`, plus deterministic local builders. R3 can
feed corpus bytes directly, assert `ChainFailure.index`, the exact error or
wire code, and compare public state queries without introducing a second
authority implementation. `Fixture::replay` checks equality between whole-chain
reconstruction and repeated resume transitions. No new vector schema is imposed.

`identity_authority.rs` covers the state and historical-object scenarios;
`identity_ordering.rs` covers compound failures and forks; `identity_wire_codecs.rs`
retains the R1 structural, signature and intrinsic-chain tests. Structural error
variants remain those of R1 (P3-2); state failures have distinct `AuthorityRule`
variants. All suites run offline using the existing locked spec for legacy vectors.

## Clarifications for the spec/corpus owners

1. WIRE §7.3 says mask codes 9 and 11 confer nothing, whereas §80.1's pseudocode
   appears to permit masked 11 when `direct(root, 11)`. This implementation follows
   §7.3 for an ordinary device; owning-root `owner/act` still confers all effective
   standard abilities per §80.1. Please clarify this edge explicitly in vectors.
2. WIRE §62 verifies the accept under its required signer before authority, even
   without field 2. Thus a wrong accept `kid` gives `INVALID_SIGNATURE`, while a
   correctly signed accept with a wrong root ID gives `AUTHORIZATION_FAILED`.
   The older §23.3 general failure sentence can be read differently; the new
   ordering tests follow §62. No pinned corpus bytes were changed.
3. The existing MVP refusal of Coordinator Recovery and Resource Tombstone
   remains outside R2. Their eventual transitions must use `owner_action` and
   `holds(..., 10)` respectively. No new wire code is introduced here.
