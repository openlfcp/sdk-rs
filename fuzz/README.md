# Admission fuzz targets

cargo-fuzz (libFuzzer) targets for the admission paths of `lfcp`:
SHARED-OBJECTS-PROFILE-01 §§7-18 (framing, checksum, §11.1 expansion
limits, §11.2 depth, §8 actor binding, §14.1 sequence and held changes,
§13.1 Snapshots) and SHARED-SECTIONS-PROFILE-01 §14.1 (A1-A5).

This crate is not a member of the repository's workspace: normal builds and
CI never compile it. It needs a nightly toolchain and `cargo-fuzz`.

| Target | Input | Checks beyond "no panic" |
| --- | --- | --- |
| `plaintext` | arbitrary bytes as a Data Unit and a Snapshot plaintext | each verdict twice the same; `SectionsReplica::receive` refuses what `decode_change` refuses; a repeat has no second effect |
| `objects_admission` | records (see `src/lib.rs`) into one `SharedObjects` | deterministic run; a refused or duplicate change leaves the replica unchanged; a held one changes only `held()`; a repeat is a Duplicate after an Applied, else the same verdict; a document of admitted changes within the §13.1 floor saves to a valid Snapshot |
| `sections_receive` | records into one `SectionsReplica` | deterministic run; only an Applied change moves the heads; a repeat as above; no refused change is in the document |
| `snapshot` | `[flags][bytes]`, a Snapshot save | deterministic; monotone in the limits; `decode_snapshot` agrees with the limit and depth checks plus the load; an accepted Snapshot loads in both profiles and its re-save is accepted |

The stateful targets read records `[ctl][len u16 LE][bytes]`: the low two
`ctl` bits choose the signer among the corpus Principals; bit 2 makes the
harness write the chunk header (so a mutated body keeps a valid checksum);
bit 3 makes it frame the chunk as `[1, bstr]`.

## Running

```sh
# Seeds from the spec corpora at the spec.lock pin ($LFCP_SPEC_DIR or ../spec).
python3 fuzz/seed.py
cargo +nightly fuzz run sections_receive fuzz/corpus/sections_receive -- \
  -rss_limit_mb=2048 -timeout=10 -max_len=65536 -fork=2 -ignore_crashes=1
```

`LFCP_FUZZ_QUIET=1` silences the per-panic line. libfuzzer-sys aborts on
every panic, including those the library catches as defense in depth; the
targets restore a printing hook so only an uncaught panic is a crash, and
`LFCP_FUZZ_STRICT=1` keeps abort-on-any-panic.

## Known findings

The targets skip inputs of findings not fixed yet, so they do not mask
other paths. Set the variable to deliver them again (for example to check
a fix):

| Variable | Finding |
| --- | --- |
| `LFCP_FUZZ_F2=1` | `decode_change` panics in automerge's `OpId::new` on a counter above `u32::MAX` |
| `LFCP_FUZZ_F3=1` | admitted changes Automerge cannot reproduce make the document's save fail to load ("mismatching heads") |
