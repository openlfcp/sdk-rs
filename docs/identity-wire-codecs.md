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

Task 401 follow-up: review R20's negative vectors need fresh outer records and
transfer offers at the stated head to reach their intended authority failure.
Review N07 requires preflight of an unsigned prospective leaf and its issuer
chain before consuming a pairing session: reject managing depth 4 and an empty
service scope. The codec must not relax these rules while wording is pending.
R13, R16, R17, N01, N06 and N08 concern profile, flow, state or server behavior
outside this codec task.
