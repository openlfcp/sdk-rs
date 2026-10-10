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
