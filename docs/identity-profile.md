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
taken-sequence hold. AI1–AI5 inspect the operations against their causal history,
including the creator and previous pairing value of a request map. Refused
changes are not applied; their dependants wait. Concurrent request maps remain
conflicted and are omitted by readers.

AI2 protects entry maps and maps/lists in their immediate fields (depths 2–3),
checking the objects named as predecessors. A list held directly at an entry
key (`devices[k] = [...]`) is not an entry map: a scalar over it is admitted
and the entry is left to state validation. A scalar beside a list with no
object predecessor replaces nothing. Deeper replacements are outside AI2 and
remain subject to the other admission rules and state validation. AI5 restricts
every operation on
`devices[k].missing_keys` and its descendants to the Principal named by `k`.
Both rules use object-creation history, including objects created earlier in the
same change and hidden, replaced or deleted objects. AI5 reports
`UNAUTHORIZED_WRITER` at the same priority as AI4, before `INVALID_FIELD_TYPE`.
AI3 (decision I27) type-checks only the positions IDENTITY-PROFILE-01 §2.1
defines, located by object-creation history: an entry, a named field of an
entry map, a key of `devices[k].missing_keys`, and an element of a list held in
`endpoints`, `scope` or `missing_keys[X]`. A list element admits only a string,
boolean or uint; the other positions also a map or a list. Values of
`extensions[ns]`, unknown fields and anything below a map or list held where a
scalar or list is defined are not checked; state validation judges the field.
Deleting a device entry, or replacing its map without writing `missing_keys`,
does not violate AI5.

`IdentityDoc` validates the root and each entry. `entries` omits invalid entries,
preserves unknown fields, and unions concurrent `missing_keys` hints. `plain`
and `automerge` expose raw state for diagnostics and round trips, not trusted
requests. `inspect` performs state validation only. `receive_snapshot` conservatively
requires verified unit witnesses for every Snapshot change, including the root's
unit 1, then replays them through admission. Missing witnesses return `false`
without modifying the replica; fetch the units before using the Snapshot.

Invalid extension namespaces are reported by `extension_diagnostic(key)`.
They leave the root and other entries usable; raw state preserves those keys.

Baseline.2 makes I8 normative as AI5. The provisional
`MissingKeysWriterMismatch` diagnostic and `with_missing_keys_check` switch have
been removed; every replica uses the same admission rules. The corpus's
`device_entry_missing_keys_union` is a state-validation fixture: `inspect`
checks its conflict union, while `receive_snapshot` refuses its historical
foreign hints. State inspection does not establish admission.

`PairingLink` parses only `lfcp://pair/`, recomputes the Principal from its secret,
and rejects a mismatched `device`. An endpoint is checked as a receiver checks
it (W §16): `ws` or `wss` in any case, followed by `://` and an authority, so a
link to a loopback server (`ws://127.0.0.1:8787`) parses. `PairingLink::new`
applies the writer's rule instead: `wss`, or `ws` to a loopback address. Secret storage and returned URI strings are
zeroized on drop; Debug and errors redact them. Before using a parsed link, the
client must verify the Genesis profile and active kind-2 registration (§5.2).
The SDK does not perform networking, show approval UI, or persist a pairing
journal. Those client contracts remain in IDENTITY-PROFILE-01 §§5–9.
