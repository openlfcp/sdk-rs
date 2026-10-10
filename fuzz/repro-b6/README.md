# Divergences between sdk-rs and sdk-ts (diff_ts)

sdk-rs 2147246 against sdk-ts 81ddb09 (its public npm API only, through
`../ts-oracle/oracle.mjs`), spec fcb92bc (baseline.5 prepared). Each file is
an input of the `diff_ts` target: `[mode][records]` (mode bit 0: Shared
Sections, else Shared Objects). Run one with every divergence reported:

```sh
LFCP_SDK_TS_DIR=<built sdk-ts> LFCP_FUZZ_ALL=1 \
  fuzz/target/x86_64-unknown-linux-gnu/release/diff_ts fuzz/repro-b6/<file>
```

| ID | Files | sdk-rs | sdk-ts | By the spec text |
| --- | --- | --- | --- | --- |
| D1 | `D1-sections-table`, `D8-sections-table-node` | refuses (`INVALID_AUTOMERGE_BYTES`): its engine guard catches automerge 0.12's abort on a write into a table | throws the engine's error (`Obj … Missing from Index`, Shared Objects: `the replica could not be restored`) and keeps the change: the replica holds it, and the next honest change of that actor is refused (`duplicate seq 1`); D8: refuses by a section rule (`PLACEMENT_NOT_ATOMIC`) before its engine | §11.3 and §11.4 R3 admit a write into a table, which automerge 0.12 cannot apply at all (its own writer panics on it): a spec gap. sdk-rs is the safe side; sdk-ts must not merge or throw |
| D2 | `D2-objects-seq-2pow53`, `D2b-…`, `D6-…`, `D7-…` | applies, or waits for a missing dependency (§14.1), a change whose sequence number or time is 2^53 or more | refuses it at once (`INVALID_AUTOMERGE_BYTES`), before the dependency or actor check | sdk-rs: §14.1 checks the sequence once every dependency is present, §11.3 allows 64-bit numbers; §11.1's "2^53 or more" is about expansion counts. The spec should bound header numbers below 2^53 if JavaScript cannot represent them |
| D3 | `D3-sections-field-type` | admits collaborative Text in a node field the profile does not define (`texr`) | refuses it (`INVALID_FIELD_TYPE`, A5) | leans sdk-ts: A5 refuses "Text where a scalar is required (SOP §30)", and SOP §30 makes every profile string scalar (its corpus flags Text in unknown fields); a node's `text` is the only Text field |
| D4 | `D4-sections-immutable` | admits a change that creates the section with `ready` = a string | refuses it (`IMMUTABLE_FIELD_MUTATED`) | sdk-ts: §12.1 refuses a change that writes `ready` other than `true`. sdk-rs checks readiness only when the section existed before the change (`shared_sections.rs` A3 block under `if let (Some(ps), Some(ns))`) |
| D5 | `D5-sections-author-assert` | refuses (`INVALID_AUTOMERGE_BYTES`) a change with an Automerge author and a sequence number other than 1 (`document.rs` admit) | throws automerge's assertion (`change.seq() == 1`); its replica stays usable | the spec does not mention the author (§11.3 rule 4 allows any extra bytes): a gap; sdk-ts must not throw |
