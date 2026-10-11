# diff_ts re-run on mvp-0.2-baseline.6

sdk-rs b31e313 against `@openlfcp/*@0.2.0-beta.1` from npm (dist-tag
`beta`), spec `mvp-0.2-baseline.6` (73c0e80), `LFCP_FUZZ_ALL=1`. The
repro-b6 inputs D1–D8 all agree. 60 minutes, `-fork=6`: 1,659,608
executions, 17 crashes, all one class, C1.

Replay one input:

    LFCP_SDK_TS_NPM=<dir with the packages installed> LFCP_FUZZ_ALL=1 \
    LFCP_FUZZ_TRACE=1 target-b/x86_64-unknown-linux-gnu/release/diff_ts repro-b7/<file>

## C1: a change refused for its checksum stays refused when it comes with the right one

A receiver names refused bytes by the SHA-256 of the chunk from its type
byte on (SHARED-SECTIONS-PROFILE-01 §14.1), without the checksum. A change
chunk whose checksum is wrong is refused (`INVALID_AUTOMERGE_BYTES`) and
named by the hash its intact copy has. When the same Principal then sends
the intact copy, sdk-rs answers with the refusal it remembers, and so do
the changes that depend on it; sdk-ts checks the intact copy and applies
it.

| File | Records | sdk-rs | sdk-ts |
| --- | --- | --- | --- |
| `C1-sections-checksum-twin` | genesis; change X with a flipped checksum byte; X, both signed by signer 0 | applied, refused, **refused:INVALID_AUTOMERGE_BYTES** | applied, refused, **applied** |
| `C1b-sections-checksum-twin-other-signer` | the same, the broken copy signed by signer 1 | applied, refused, applied | applied, refused, applied |
| `C2-sections-checksum-twin-actor` | the form the fuzzer found: X with a wrong checksum, then X, whose actor is not the signer's | refused, **refused:INVALID_AUTOMERGE_BYTES** | refused, **refused:CHANGE_ACTOR_MISMATCH** |

C1b agrees: since b31e313 sdk-rs keeps the refusal only for the Principal
that signed it. A Data Unit is signed, so only the author can make the
broken copy reach a receiver; the case is an author's own corrupted unit
followed by its correct resend (or the same hash from a different encoding
step). The profile does not say whether a hash named by a refusal stays
refused for later bytes with that hash, so which side is right is a spec
decision.

## Refusal names (since sdk-rs a3b78c8)

diff_ts now compares the name a Shared Sections refusal gives the bytes
(the change hash, SS §14.1) as well as its diagnostic: sdk-rs by the hash
the refusal adds to `SectionsReplica::refused`, sdk-ts by
`SectionRefusal.hash`. On mvp-0.2-baseline.7, against sdk-ts 0.2.0-beta.2:

| File | sdk-rs a3b78c8 | sdk-ts 0.2.0-beta.2 | Spec (baseline.7) |
| --- | --- | --- | --- |
| `C1-…`, `C1b-…`, `C2-…` | the copy with the wrong checksum is unnamed | named by its intact copy's hash | unnamed: sdk-rs |
| `C3-sections-unnamed-header-past-end` | named `07d2f99c…` | unnamed (`refusedChangeHash` is undefined: "a length runs past the end") | named: a type 1 chunk, its length field exact and its checksum matching, is named without decoding; sdk-rs |

C3 is one record: a type 1 chunk whose length field and checksum are
right but whose header holds a length running past its end. sdk-ts names
a refused chunk only when it can read its header, which the profile does
not ask for.

`LFCP_FUZZ_SKIP_NAMES=1` takes these two kinds (one side names, the other
does not, the diagnostic the same) as equal, for a run against an sdk-ts
that has not fixed them.

## The 60-minute run: sdk-rs a3b78c8 against sdk-ts 0.2.0-beta.2

`LFCP_FUZZ_ALL=1 LFCP_FUZZ_SKIP_NAMES=1`, `-fork=6`, the corpus with the
baseline.7 vectors: 1,632,601 executions, 2 crashes, two classes. In both
the spec sides with sdk-ts.

| File | Records | sdk-rs | sdk-ts | Spec |
| --- | --- | --- | --- | --- |
| `E1-sections-equivocation-vs-structural` | genesis; another change of the same actor at sequence 1, which also writes `section.ready` against §12.1 | applied, **refused:IMMUTABLE_FIELD_MUTATED** | applied, **held** (ACTOR_EQUIVOCATION) | SS §14.1 checks the sequence (SOP §14.1) before the structural rules: held |
| `E2-sections-scalar-node-text` | genesis; SS40's `initial-content` with one node's key `kind` turned into `text`, so the change writes a scalar string to a node's `text` | applied, **applied** | applied, **refused:INVALID_FIELD_TYPE** | A5: "writes a scalar to a node's `text`": refused |

## baseline.9: sdk-rs 82901af against sdk-ts 0.2.0-beta.4

The inputs above all agree, names included, but E1 and E2 (not fixed in
82901af). diff_ts now also names a refusal of bytes already refused: the
hash sdk-rs keeps them under (before, a second refusal of the same change
looked unnamed on the sdk-rs side).

| File | Records | sdk-rs | sdk-ts | Spec (baseline.9) |
| --- | --- | --- | --- | --- |
| `F1-sections-unnamed-unreadable-header` | one framed type 1 chunk, its length field exact and its checksum matching, whose body `e9 ff ff` is an unterminated dependency count | refused:INVALID_AUTOMERGE_BYTES, unnamed | refused:INVALID_AUTOMERGE_BYTES `0624759c…` | SS §14.1: "the change header is not read, and a chunk whose header is malformed … is named all the same": sdk-ts. sdk-rs `refused_change_key` (framing.rs) reads the dependencies and the actor and names nothing when it cannot |

The 60-minute run (`LFCP_FUZZ_ALL=1`, no `LFCP_FUZZ_SKIP_NAMES`, `-fork=6`,
the corpus with the baseline.9 vectors): 1,041,344 executions, 1213
crashes. Replayed on the final harness: 1121 are F1, 1 is E1, 3 are E2
(genesis `initial-content`, applied against refused:INVALID_FIELD_TYPE),
and 88 agree (the repeated-refusal harness artifact, written before the
fix above). No new class.

## baseline.10: sdk-rs cf8dcb6 against sdk-ts 0.2.0-beta.4

Every input above agrees, names included (E1, E2, F1 fixed in cf8dcb6),
and so do the SS88–SS91 seeds of spec 0c3ee19 in their order and reversed
(SS88: held when the genesis comes first, refused:IMMUTABLE_FIELD_MUTATED
when the twin does, on both sides). The 60-minute run (`LFCP_FUZZ_ALL=1`,
no `LFCP_FUZZ_SKIP_NAMES`, `-fork=6`): 1,473,601 executions, no crash.
