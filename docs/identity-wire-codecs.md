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

The existing authority engine explicitly refuses types 9/10 and device-chain
Genesis/commit with `UnsupportedInMvp` until 404 implements their effects.
No `holds`, role storage, standing, registration or revocation transitions
are added here. Genesis/commit leaf kind, `owner/act`, required signers and
record-issuer resolution also remain part of that integration. Legacy Rust
struct literals need `device_chain: None`; their wire bytes stay unchanged.

Both embedded transfer objects are now structurally parsed with the body,
including commits without field 2, so malformed nested objects cannot be
hidden by an outer signature failure.

Task 401 follow-up: review R20's negative vectors need fresh outer records and
transfer offers at the stated head to reach their intended authority failure.
Review N07 requires preflight of an unsigned prospective leaf and its issuer
chain before consuming a pairing session: reject managing depth 4 and an empty
service scope. The codec must not relax these rules while wording is pending.
R13, R16, R17, N01, N06 and N08 concern profile, flow, state or server behavior
outside this codec task.

One old vector expectation needs a normative update: baseline.12's
`unknown_core_type_C1` uses type **9** with a Capability Grant body. These
exact bytes still fail, now with `MALFORMED_MESSAGE`, because 9 is known and
the body is not a Device Grant. The local test records that one explicit
reclassification; the source corpus and `spec.lock` are not edited. A fresh
local type-11 vector checks `INVALID_CONTROL_CHAIN`. Task 401 must reconcile
this with the draft's promise of an empty `value-changes.json`.

The `device_certificate` fuzz target exercises certificate, chain and Control
Record parsing, exact-byte round trips, digest consistency and deterministic
verification. See [the fuzz instructions](../fuzz/README.md) for libFuzzer and
the standalone mutation smoke run when its toolchain is unavailable.
