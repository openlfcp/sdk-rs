# Identity wire codecs (LFCP-04-402)

Implementation reference: openlfcp/spec main at `d9f2873`,
WIRE §§7.3, 15, 17.4–17.5, 23.3 and 62. The original 402 codec implementation
used `identity-spec-draft.md` revision 3; LFCP-04-404 integrates it with the
Resource-local authority engine ([authority API](identity-authority.md)).
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

LFCP-04-404 removes the temporary admission gate: types 9/10 and the optional
Genesis/commit chains now have real transitions in `CapabilityEngine`.
`validate_chain` resolves all dependencies and checks outer and embedded
signatures before calling the authority policy. `SignaturesOnly` and `ResolveWith`
check all these signatures but deliberately do not establish authority; callers
accepting a Control Chain use `validate_authorized` or `CapabilityEngine`.

Both embedded transfer objects are now structurally parsed with the body,
including commits without field 2, so malformed nested objects cannot be
hidden by an outer signature failure.

Integration notes for 404/R3 (review P3-1/P3-2): root dependency resolution is
now `CertificateChain::require_root(Option<&PrincipalDescriptor>)`; signature
verification is `verify_signatures(&PrincipalDescriptor)`. Resolve **all**
dependencies before any signature. A mismatched supplied root descriptor reports
the local `DeviceRootDescriptorMismatch` caller error, with no wire code.
Structural failures still share `DeviceCertificateMalformed`, and the borrowed
scanner can report a generic `ControlRecordMalformed`; both map to
`MALFORMED_MESSAGE`. Fine-grained structural `DeviceRule` diagnostics remain for
R3 to coordinate with its corpus; scanner/full-parser assertions compare
acceptance, parsed values and wire codes. State transitions have separate
`AuthorityRule` diagnostics.

Task 401 follow-up: review R20's negative vectors need fresh outer records and
transfer offers at the stated head to reach their intended authority failure.
Review N07 requires preflight of an unsigned prospective leaf and its issuer
chain before consuming a pairing session: reject managing depth 4 and an empty
service scope. The normative profile §5.3 step 4 now explicitly requires this preflight.
R13, R16, R17, N01, N06 and N08 concern profile, flow, state or server behavior
outside this codec task.

The identity baseline resolves two legacy error classifications:

1. `unknown_core_type_C1` now uses reserved type **31**, preserving its
   `INVALID_CONTROL_CHAIN` verdict. Baseline.12 used type 9, which identity
   assigns to DEVICE_GRANT. The temporary local malformed-body expectation
   is removed; the test uses the pinned corpus's error code directly.
2. A legacy transfer commit **without field 2** containing a malformed offer
   or accept now fails with `MALFORMED_MESSAGE` before placement or dependency
   checks (§3.10 explicitly includes transfers without field 2). For example,
   offer = COSE(null) plus incorrect prev/seq previously yielded
   `INVALID_CONTROL_CHAIN`; the same malformed offer with correct placement
   but an unknown issuer previously yielded `MISSING_DEPENDENCY`. Both now
   yield `MALFORMED_MESSAGE`. No baseline.12 vector covered that combination;
   local tests now cover both nested objects and both competing error classes.

The normative migration records these byte changes in `value-changes.json`;
`spec.lock` pins `mvp-0.4-baseline.1`. The
§62 signature-first checks also classify a wrong transfer accept signer as
`INVALID_SIGNATURE` before payload acceptor mismatch; see the authority notes.
The offer signer is never a dependency: an unknown signer gives
`AUTHORIZATION_FAILED` after the checkable signatures, as does a known signer
unrelated to the owner even if its signature is broken (§23.3/§62). Offer
signatures are checked only for the current owner and its bound devices;
activity and owner/act remain authority checks. Device limits and
the first-registration-only self-submission rule are authority predicates,
not additional codec bounds. Pairing key bootstrap belongs to the profile
client flow; see [authority integration](identity-authority.md).

The `device_certificate` fuzz target exercises certificate, chain and Control
Record parsing, exact-byte round trips, digest consistency and deterministic
verification. See [the fuzz instructions](../fuzz/README.md) for libFuzzer and
the standalone mutation smoke run when its toolchain is unavailable.
