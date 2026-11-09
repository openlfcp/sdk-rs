# Identity authority (LFCP-04-404 / R2)

The normative reference is openlfcp/spec at the `mvp-0.4-baseline.5` candidate `1dc648b`:
LFCP-WIRE-01 §§7.3, 15, 17.2–17.5, 18.1, 23.3, 25.2, 41, 62, 79 and 80.1.
`spec.lock` pins the normative text and the published identity corpora together.
The corpus runners also retain the existing Wire/profile vector verdicts.

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
accepts are checked even with `SignaturesOnly`/`ResolveWith` (the §62 offer
signer selection below applies); those policies
intentionally skip authority. They are insufficient for accepting a Resource.

`CertificateChain::require_root` is the dependency phase;
`verify_signatures(&PrincipalDescriptor)` is the signature phase. Passing the
wrong root descriptor is a local API error (`DeviceRootDescriptorMismatch`),
not `INVALID_SIGNATURE`. Device Grant roots must be known in the Resource's
previous state; external `CapabilityEngine::knowing` descriptors do not create
that dependency or standing. Device Grant/Revoke issuers also require a
Resource-local descriptor (or a descriptor in the grant's chain); external
knowledge cannot change their dependency error. At forks, both directory and engine lookups use
the common prefix, never descriptors or authority from its later suffix.

`authority::apply` also validates placement, dependencies and **all** outer and
embedded signatures before applying one transition. `ControlRecord::sign` or
`ReceivedControlRecord::verify` alone checks only the outer signature. The
capability engine uses a private transition primitive after `validate_chain`
has completed these checks, without duplicating signature verification.

An offer signer is never a missing dependency (§23.3). An unknown signer fails
with `AUTHORIZATION_FAILED`, after the outer, certificate and accept signatures
have been checked; signature-only policies also refuse that unverifiable offer.
The offer signature is checked only for the current owner or a device bound
to it, even if suspended, revoked or lacking owner/act. Other signers fail AUTH
regardless of external knowledge or their signature bytes. For a bound owner
device, activity and owner/act are checked in the authority class.
A wrong accept signer is `INVALID_SIGNATURE`, before an
acceptor-ID mismatch in a correctly signed payload (`AUTHORIZATION_FAILED`).
`ChainPolicy::resolve_offer_signer` selects the owner/bound-device descriptor
at the predecessor. Its default derives that relationship from the supplied
prefix; custom policies resuming without that prefix must override it using
their prior state. `CapabilityEngine` handles resume and forks directly.

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

All growing state maps use `PersistentMap`, a compressed binary trie sharing
nodes and values across historical heads. `DeviceBinding::chain` is an
`Option<Arc<CertificateChain>>`; updating one binding does not copy other
certificates. Public epoch maps retain lookup, ordered iteration and mutation
APIs but are no longer `BTreeMap`. Record IDs index predecessor positions;
parent-grant traversal is iterative. These changes remove whole-state copying,
not the costs of arbitrary grant scans or scanning affected readers on revoke.

Device Grants enforce §17.4 rule 8 after standing, chain, issuer and approval:
at most 32 **live** bindings per root, counting new intermediates, out-of-scope
leaves and suspended devices whose own `(root, device)` pair is not revoked;
at most eight accepted Device Grants per root/leaf pair. `grants_accepted`
records that count. A direct revocation frees a live slot, including cancelled
and consumed pairing devices; a cascade does not free its descendants' slots.
Genesis and transfer bindings contribute to subsequent Device Grant checks,
but transfer commits with field 2 are not themselves subject to rule 8 and do
not consume or reset the Device Grant allowance.

Device Revoke limits only pre-emptive revocations: at most 64 pairs per root
whose targets currently have no `devices` entry (§17.5 rule 5). Revoking a bound
device, including an inactive or intermediate-only one, never spends or checks
that quota. If a pre-emptively revoked Principal later binds to another root,
it no longer occupies a pre-emptive slot; the original tombstone still exists.
All three limits return `AUTHORIZATION_FAILED`, with distinct `AuthorityRule`
diagnostics. Cached counters and a persistent reverse index of pre-emptive
revokers survive resume/forks and avoid scanning revoked history on binding.
These limits bound live state; history can grow through device replacement,
subject to the owner's grant revocations and hosting quotas (§84).

Revoking a manager suspends descendants through their current issuer lists.
A root or active managing device can submit a new path to restore a suspended
device; a revoked pair can never return. A personal device can submit its own
first leaf registration when it has no current chain, including an
intermediate-only binding. Once it has a chain it cannot re-certify itself,
even with a different older certificate, a management mask or owner/act.
Revocation of an unbound device creates neither a binding nor a role. Losing
standing deactivates devices without discarding registration; standing restored
by a later grant reactivates them if their chains are unrevoked. These facts are
Resource-local; no clock, profile document, server table or other Resource is read.

Capability Grants record `Grant::issuer_root` at the previous head. Parent-subject
and revoke-coverage comparisons use `acts_for`, letting siblings revoke grants
their root issued through another device. A non-owner-acting device cannot
delegate codes 1–10 outside its mask, in either ability list; parent bounds still
apply. Codes 11–13 and unknown codes pass through the delegation-mask bound.
Every bound device has `holds(device, 11) == false`, including owner-acting
devices whose root has an invitation grant. Unbound roots retain §80 behavior:
the owner holds 11, but this never substitutes for an explicit invitation grant.

Reason 3 revocations store the approved **payload digest**, before a prospective
leaf has been signed. An approved Device Grant must name the consumed kind-2
session of the same root and match that digest. A second consumption fails;
exact-byte replay is distinguished from a fresh proposal. The client remains
responsible for unsigned preflight, journal persistence and waiting for the
accepted consume record before signing (IDENTITY-PROFILE-01 §5.3, §9).
The profile's pairing flow also requires verified root Data Unit sequence 1
and all epoch DEKs before offering a link; every epoch is sealed to the pairing
device and that unit made retrievable. At the live-device limit no link is offered;
preflight counts the pairing device as consumed, and if a concurrent binding
takes that place the client retries the same approved certificate after a
revocation frees a slot. This SDK supplies authority and codecs;
session bootstrap, document loading and certificate-result reconciliation are
client responsibilities, not additional Control validation predicates.

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
retains the R1 structural, signature and intrinsic-chain tests. `identity_limits.rs`
covers the live 32 / per-pair 8 / pre-emptive 64 boundaries, pairing slot reuse,
uncapped bound-device revocation, foreign-root bindings, transfer exceptions,
resume and forks.
`identity_perf.rs` is an ignored release benchmark retaining all historical heads;
it distributes 400/800/1600 device records across read-only roots within the
normative limits. Stateful fuzzing compares replay/resume, history immutability,
permanent bindings and revocations, exposure and repeated bytes; see
[fuzz instructions](../fuzz/README.md). Structural error
variants remain those of R1 (P3-2); state failures have distinct `AuthorityRule`
variants. All suites run offline using the existing locked spec for legacy vectors.
`AuthorityRule` is non-exhaustive: downstream matches need a wildcard arm. Cross-SDK
comparisons use the wire error code, not the Rust diagnostic within that class.

## Server rollout and remaining scope

The SDK bump changes server validation verdicts and must be released with task
408's `identity-01` negotiation, owner-based hosting and proof-prefix reads.
A server not advertising `identity-01` must reject identity-only inputs as a
pre-identity receiver (§37, §100.1): `INVALID_CONTROL_CHAIN` for types 9/10,
`MALFORMED_MESSAGE` for Genesis field 5 or commit field 2, and
`AUTHORIZATION_FAILED` for same-root-only Key Packages. This belongs at the
server boundary; the SDK has no implicit opt-in gate.

The existing MVP refusal of Coordinator Recovery and Resource Tombstone remains
outside R2. Their eventual transitions must use `owner_action` and
`holds(..., 10)` respectively. No new wire code is introduced here.

## Baseline.1 follow-up

The baseline corpus explicitly rejects self-recertification by an active managing
leaf (`device_grant_self_recertify_active_managing`), matching the first-registration
rule above. KEY_EPOCH checks its epoch number in class 2, before dependencies,
signatures and authority, including when resuming or validating a fork competitor.

For signature-only suffix validation, use `ResolveWith(resolver).after(state)`
with the previously validated `ControlState`. It supplies the starting epoch,
owner and bindings, and follows transfers in the suffix at the candidate's actual
prefix. Bare `ResolveWith` has no preceding state; use `validate_authorized` for
complete validation and authority enforcement.

Revocation exposure uses a persistent issuer-to-leaf index. Unbound tombstones
visit no devices; a bound revocation visits only indexed dependents, checking
their current chains so superseded issuing paths cannot cause exposure. Historical
Control states retain their own index and remain unchanged.
