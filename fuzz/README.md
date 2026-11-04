# Admission fuzz targets

cargo-fuzz (libFuzzer) targets for the admission paths of `lfcp`:
SHARED-OBJECTS-PROFILE-01 §§7-18 (framing, checksum, §11.1 expansion
limits, §11.2 depth, §11.3 canonical encoding, §11.4 operation
references, §8 actor binding, §14.1 sequence and held changes, §13.1
Snapshots) and SHARED-SECTIONS-PROFILE-01 §7.6 and §14.1 (A1-A5).

This crate is not a member of the repository's workspace: normal builds and
CI never compile it. It needs a nightly toolchain and `cargo-fuzz`.

| Target | Input | Checks beyond "no panic" |
| --- | --- | --- |
| `identity_authority` | bounded signed identity programs or raw candidate bytes | full replay equals resume, deterministic errors, immutable historical heads, permanent bindings/revocations, ability 11 exclusion, grant counts, exposure and exact-byte replays |
| `device_certificate` | arbitrary certificate, certificate-chain or Control Record bytes | scanner/full-parser agreement on parsed values and wire errors, deterministic parse/verification, exact COSE bytes and chain round trips, unsigned/signed payload digest agreement, typed Control bodies round trip |
| `plaintext` | arbitrary bytes as a Data Unit and a Snapshot plaintext | each verdict twice the same; `SectionsReplica::receive` refuses what `decode_change` refuses; a repeat has no second effect |
| `objects_admission` | records (see `src/lib.rs`) into one `SharedObjects` | deterministic run; a refused or duplicate change leaves the replica unchanged; a held one changes only `held()`; a repeat is a Duplicate after an Applied, else the same verdict; a document of admitted changes within the §13.1 floor saves to a valid Snapshot |
| `sections_receive` | records into one `SectionsReplica` | deterministic run; only an Applied change moves the heads; a repeat as above; no refused change is in the document |
| `canonical` | `[flags][bytes]`, a change chunk (flag bit 0: the harness writes the header around `[type][body]`) | what §11.3 accepts the engine parses and writes back to the same bytes; what the engine round-trips and a committing writer could have made, §11.3 accepts; `decode_change` accepts nothing §11.3 refuses |
| `objects_gen` | a program three Automerge writers run (every object and value type, list and text edits, increments, marks, blocks, merges, empty changes) | every change is admitted, one at a time in an input-chosen order and as one batch; both replicas end on the writers' heads; the save loads |
| `sections_gen` | a program three writers run with the Shared Sections authoring API, merging now and then | every change, signed by its writer, is received without a refusal; the replica ends on the writers' heads; a node whose lifecycle has concurrent values is blocked (§7.6); the replica's view and a loaded document project the same tree |
| `diff_ts` | `[mode][records]`: Data Unit plaintexts for a Shared Objects (mode bit 0 clear) or Shared Sections replica | the same bytes on sdk-ts (its public npm API, `ts-oracle/oracle.mjs`, needs `LFCP_SDK_TS_DIR` and `node`): after each change the two verdicts (applied, duplicate, missing, held, or the refusal and its diagnostic) and the two replicas' heads are equal; known divergences (repro-b6) end the comparison unless `LFCP_FUZZ_ALL=1` |
| `snapshot` | `[flags][bytes]`, a Snapshot save | deterministic; monotone in the limits; `decode_snapshot` agrees with the limit and depth checks plus the load; an accepted Snapshot loads in both profiles and its re-save is accepted |

The stateful targets read records `[ctl][len u16 LE][bytes]`: the low two
`ctl` bits choose the signer among the corpus Principals; bit 2 makes the
harness write the chunk header (so a mutated body keeps a valid checksum);
bit 3 makes it frame the chunk as `[1, bstr]`.

## Running

Identity authority (WIRE §17.4–17.5, §23.3, §80.1):

```sh
CARGO_BUILD_JOBS=3 CARGO_TARGET_DIR="$PWD/target/lfcp-04-404" \
  cargo +nightly fuzz run identity_authority -- \
  -max_total_time=10 -rss_limit_mb=1024 -max_len=193
```

The dependency-free driver runs the same assertions on signed program mutations,
raw record mutations and deterministic random programs. It is an offline smoke
test, not coverage-guided fuzzing. Build the default library first and set
`LFCP_RLIB` to that build's `liblfcp-*.rlib`:

```sh
CARGO_BUILD_JOBS=3 CARGO_TARGET_DIR="$PWD/target/lfcp-04-404" cargo build --offline -p lfcp
rustc --edition=2021 -C opt-level=1 --extern "lfcp=$LFCP_RLIB" \
  -L dependency=target/lfcp-04-404/debug/deps \
  fuzz/identity_authority_smoke.rs -o target/lfcp-04-404/identity-authority-smoke
target/lfcp-04-404/identity-authority-smoke
```

Device codecs (identity draft §§2.1–2.6, 3.2, 3.10):

```sh
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$PWD/target/identity-wire-codecs-fuzz" \
  cargo +nightly fuzz run device_certificate -- \
  -max_total_time=10 -rss_limit_mb=1024 -max_len=16384
```

When nightly/cargo-fuzz/libfuzzer-sys are unavailable, the same assertions
can run against every single-bit mutation and truncation of valid certificate,
chain and Control Record seeds for all three device kinds, including CBOR
integer-head boundaries in masks. This is a deterministic smoke test, not
coverage-guided fuzzing. First build `lfcp`, then compile and run the driver
against that build's rlib (set `LFCP_RLIB` to the matching filename):

```sh
CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$PWD/target/identity-wire-codecs" cargo build -p lfcp
rustc --edition=2021 -C opt-level=1 \
  --extern "lfcp=$LFCP_RLIB" -L dependency=target/identity-wire-codecs/debug/deps \
  fuzz/device_certificate_smoke.rs -o target/identity-wire-codecs/device-certificate-smoke
target/identity-wire-codecs/device-certificate-smoke
```

```sh
# Seeds from the spec corpora at the spec.lock pin ($LFCP_SPEC_DIR or ../spec).
python3 fuzz/seed.py
cargo +nightly fuzz run sections_receive fuzz/corpus/sections_receive -- \
  -rss_limit_mb=2048 -timeout=10 -max_len=65536 -fork=2 -ignore_crashes=1
# The generators: long programs from the start.
cargo +nightly fuzz run objects_gen fuzz/corpus/objects_gen -- \
  -rss_limit_mb=2048 -timeout=10 -max_len=2048 -len_control=0 -fork=2 -ignore_crashes=1
```

`sections_gen` and `objects_gen` run at a few executions a second (each
one authors and admits a whole multi-writer history); `canonical` at
thousands.

`LFCP_FUZZ_QUIET=1` silences the per-panic line. libfuzzer-sys aborts on
every panic, including those the library catches as defense in depth; the
targets restore a printing hook so only an uncaught panic is a crash, and
`LFCP_FUZZ_STRICT=1` keeps abort-on-any-panic.

## Known findings

| Variable | Finding |
| --- | --- |
| `LFCP_FUZZ_N1=1` | `canonical` reports N1 (repro-b3/README.md): a change without operations whose start op is 2^32 keeps §11.3 rule 8, but automerge refuses it |

## Fixed findings

F1-F4 of the first campaign are fixed (sdk-rs 4d187ac, 60dc68a, 25e45ae,
2fc9fa5); the targets no longer skip their inputs, and their reproducers
replay clean.

The `objects_admission` target also runs `lfcp_fuzz::identity_profile::check`.
Its identity variant derives the ID-05 Resource and Principals from the corpus's
published labels; control bits 0–1 select OWNER, DEV_B, PAIR_J or an unknown
Principal, bit 4 selects a personal writer, and bit 5 gives the change a different
Data Unit sequence. Otherwise the unit sequence is its Automerge sequence.
`seed.py` adds ID-05 admission histories without copying corpus files into Git.

On hosts with only stable Rust, `cargo build --manifest-path fuzz/Cargo.toml
--bin objects_admission` and `target/debug/objects_admission
fuzz/corpus/objects_admission -max_total_time=30` provide a bounded libFuzzer smoke
run. This has no sanitizer or coverage instrumentation and does not replace a
nightly cargo-fuzz campaign. Set `CARGO_TARGET_DIR` to the repository's absolute
`target/` path when using the separate fuzz workspace.
