# Identity wire codecs (LFCP-04-402)

Implementation reference: `identity-spec-draft.md`, revision 3 (2026-11-03),
MVP 0.4 inputs, §§2.1–2.6, 2.10, 3.2 and 3.10; implementation map R1.
The repository's published spec pin remains unchanged until task 401 publishes
the normative baseline and vectors.

The codec boundary includes Device Certificates, certificate chains, Control
types 9/10, Genesis field 5 and transfer commit field 2. Type 11 remains an
unknown core type. Revoke field 3 is reserved and rejected; field 4 is present
exactly for reason 3. Unknown reason and mask codes are preserved.

Verification must complete structure checks for every embedded object before
dependencies, all signatures before authority, and must preserve exact signed
bytes. Chain length, mask and scope limits must be checked before allocating
their decoded collections. Roles, bindings, revocations, standing, registration
and Control Chain transitions belong to LFCP-04-404.

`wire::control::device` exposes `DeviceCertificatePayload` (including an
unsigned approval digest), `DeviceCertificate`, `CertificateChain`,
`verify_chain` and `preflight_issuance`. Mask/scope order and exact nested
COSE bytes are preserved. Unknown codes are never filtered or promoted to
abilities. The decoder shares the existing strict CBOR head/length/depth
checks and scans schema bounds without allocating, including chains inside
Control Records. Allocation-counting tests cover both ordinary and managing
depth limits, mask length and scope length.

`verify_chain` takes the root descriptor, Resource ID and read-only
`ChainStateChecks` predicates. It checks all signatures, then c3/c4/c6, then
the root predicate, every binding predicate and every revocation predicate.
`EmptyChainState` represents Genesis only; the 404 engine must supply the
actual previous state for other records. It must compare mask/scope as sets.
The successful result retains all certificates (binding inputs), leaf
metadata, issuer IDs and `in_scope`; it does not apply a transition. Separate
signature, intrinsic-authority and state methods let 404 interleave outer
record and transfer-object checks in the §3.10 classes.

Until 404 implements identity transitions, `validate_chain` has one admission
gate immediately after full structural parsing, before placement, replay/fork
handling, issuer resolution or any policy hook. Correctly shaped types 9/10
return `ControlUnknownCoreType` (`INVALID_CONTROL_CHAIN`, §2.7 and §3.10
class 2); Genesis field 5 and commit field 2 return `ControlRecordMalformed`
(`MALFORMED_MESSAGE`, unsupported closed-map fields in §3.10 class 1). These
results do not depend on the signer, signature validity or policy, including
`SignaturesOnly` and `ResolveWith`. Malformed embedded objects still fail
first during parsing. 404 must remove the gate when it implements the effects.
The existing `UnsupportedInMvp` guards remain defense for callers invoking
the authority engine's `apply` directly, outside Control Chain validation.
No `holds`, role storage, standing, registration or revocation transitions
are added here. Genesis/commit leaf kind, `owner/act`, required signers and
record-issuer resolution also remain part of that integration. Legacy Rust
struct literals need `device_chain: None`; their wire bytes stay unchanged.

Both embedded transfer objects are now structurally parsed with the body,
including commits without field 2, so malformed nested objects cannot be
hidden by an outer signature failure.

Integration notes for 404/R3 (review P3-1/P3-2): `verify_signatures` currently
combines requiring the root descriptor with signature verification. Resolve
**all** dependencies, including both the outer issuer and chain root, before
calling `record.verify` or `chain.verify_signatures(Some(root))`; otherwise a
bad outer signature could hide a missing root. A follow-up should split the
dependency and signature methods and give a mismatched supplied descriptor
an explicit caller-error diagnostic. Structural failures currently share
`DeviceCertificateMalformed`, and the borrowed scanner can report a generic
`ControlRecordMalformed`; both map to `MALFORMED_MESSAGE`. A coordinated
`DeviceRule` diagnostic API for 404/R3 is deferred rather than changing error
variants in this admission fix. Scanner/full-parser fuzz assertions compare
acceptance, parsed values and wire codes, not these local diagnostic variants.

Task 401 follow-up: review R20's negative vectors need fresh outer records and
transfer offers at the stated head to reach their intended authority failure.
Review N07 requires preflight of an unsigned prospective leaf and its issuer
chain before consuming a pairing session: reject managing depth 4 and an empty
service scope. The codec must not relax these rules while wording is pending.
R13, R16, R17, N01, N06 and N08 concern profile, flow, state or server behavior
outside this codec task.

Two legacy error classifications need a normative update:

1. Baseline.12's `unknown_core_type_C1` uses type **9** with a Capability Grant
   body. These exact bytes still fail, now with `MALFORMED_MESSAGE`, because
   the codec knows 9 and the body is not a Device Grant. The local test records
   the changed expectation; official bytes and `spec.lock` are unchanged. A
   fresh local type-11 vector checks `INVALID_CONTROL_CHAIN`.
2. A legacy transfer commit **without field 2** containing a malformed offer
   or accept now fails with `MALFORMED_MESSAGE` before placement or dependency
   checks (§3.10 explicitly includes transfers without field 2). For example,
   offer = COSE(null) plus incorrect prev/seq previously yielded
   `INVALID_CONTROL_CHAIN`; the same malformed offer with correct placement
   but an unknown issuer previously yielded `MISSING_DEPENDENCY`. Both now
   yield `MALFORMED_MESSAGE`. No baseline.12 vector covered that combination;
   local tests now cover both nested objects and both competing error classes.

Task 401 must add/update those vectors and reconcile both changes with the
draft's promise of an empty `value-changes.json`. A baseline.12 sdk-ts still
returns the old codes; do not label this interim implementation conformant
to baseline.12 until the updated normative baseline is published.

The `device_certificate` fuzz target exercises certificate, chain and Control
Record parsing, exact-byte round trips, digest consistency and deterministic
verification. See [the fuzz instructions](../fuzz/README.md) for libFuzzer and
the standalone mutation smoke run when its toolchain is unavailable.
