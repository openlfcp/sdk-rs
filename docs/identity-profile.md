# Identity Resource profile

Feature `identity` enables `lfcp::identity` and the Shared Objects Automerge
engine. It implements IDENTITY-PROFILE-01 §§2–4 independently from the pinned
specification and corpora, plus pairing URIs and fingerprints (§5.2).

`IdentityReplica::receive` takes plaintext and `UnitContext` from a verified
Data Unit. Derive `WriterClass::at` from the validated Control state at that
unit's `control_ref`, using the Genesis owner. The caller still enforces Wire
signatures, authorization, epochs and equivocation; document metadata never
confers authority. Dependency waits retain this original context.

Admission reuses the Shared Objects engine's canonical bytes, operation
references, sequence, expansion and depth checks. AI0 eligibility runs before a
taken-sequence hold. AI1–AI4 inspect the operations against their causal history,
including the creator and previous pairing value of a request map. Refused
changes are not applied; their dependants wait. Concurrent request maps remain
conflicted and are omitted by readers.

`IdentityDoc` validates the root and each entry. `entries` omits invalid entries,
preserves unknown fields, and unions concurrent `missing_keys` hints. `plain`
and `automerge` expose raw state for diagnostics and round trips, not trusted
requests. `inspect` performs state validation only. `receive_snapshot` conservatively
requires verified unit witnesses for every Snapshot change, including the root's
unit 1, then replays them through admission. Missing witnesses return `false`
without modifying the replica; fetch the units before using the Snapshot.

Owner decision I8 is enabled by default. The provisional receive diagnostic is
`MISSING_KEYS_WRITER_MISMATCH`. Until a normative diagnostic and vectors land,
`with_missing_keys_check(false)` on a new replica selects baseline.1 behavior.
The baseline's `device_entry_missing_keys_union` deliberately includes OWNER
writing DEV_B's hints; it passes only with this check disabled. Baseline verdicts
are not changed. Changing policy requires rebuilding from the verified units.

`PairingLink` parses only `lfcp://pair/`, recomputes the Principal from its secret,
and rejects a mismatched `device`. Secret storage and returned URI strings are
zeroized on drop; Debug and errors redact them. Before using a parsed link, the
client must verify the Genesis profile and active kind-2 registration (§5.2).
The SDK does not perform networking, show approval UI, or persist a pairing
journal. Those client contracts remain in IDENTITY-PROFILE-01 §§5–9.
