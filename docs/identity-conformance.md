# Identity conformance and differential output

The test suite reads all three identity corpora using `git show` at `spec.lock`'s
commit, after checking the annotated tag's peeled commit. No corpus or sdk-ts
source is copied into this repository.

```sh
export CARGO_BUILD_JOBS=4
export CARGO_TARGET_DIR="$PWD/target"
export LFCP_SPEC_DIR=/path/to/openlfcp/spec
export LFCP_IDENTITY_REPORT_DIR=target/identity-report
cargo test --all-features --test identity_vectors --test identity_flows -- --test-threads=2
```

The report directory is relative to the repository root unless absolute.
`identity-wire.json`, `identity-profile.json` and `identity-flows.json` use
`lfcp-identity-outcomes/1`: a spec pin and a map keyed by corpus case ID. Wire and
profile outcomes contain `outcome` (accept or a code), `diagnostic` when relevant,
`accepted_ids` and `post_state`. Flow outcomes include each executed step, its
accepted IDs/state, and `not_applicable` with specific spec citations. Hashes use
lowercase hex. Control state uses the corpus's human-readable Principal and
certificate names; stored history is independent of those labels.

`identity_vectors` checks 381 ID-01–ID-04 cases and 127 ID-05 cases, including
all post-state assertions, the Key Package matrix, HPKE opening, immutable unit
metadata for initialisation, concurrent requests and Snapshot equivalence.
I8 is disabled only for the baseline corpus; separate tests verify its default
receive-side refusal (`MISSING_KEYS_WRITER_MISMATCH`). No expected verdict is
changed. Unknown runner kinds, cases or unaccounted flow assertions fail tests.

`identity_flows` executes every fixture's supplied Wire and profile case. It
also exercises actual CAS and exact-byte replay, epochs and quarantine/rebuild,
verified-sequence frontiers, certificate signing from journal payloads, service
approval provenance and fork detection. Phase classification, ledger receipts
and client scheduling are local simulations of §§7–9; they are not a persistent
client implementation or evidence of network delivery.

The following external parts are N/A, with the remaining steps still checked:

- F07 step 6: the client roster update in DAVE's separate Identity Resource
  (§7.2); the fixture supplies no document/units for that Resource.
- F09 steps 4 and 16: offline reachability and persisted candidates (§5.3).
- F10: human re-confirmation, preset UI and fresh client planning (§5.3).
- F17 step 5: server subscription removal before pushes (WIRE §69).
- F18: pre-identity/herald validators and persisted blocked-client UI
  (WIRE §100.1). This SDK's identity-aware and stale-head outcomes are checked.

`objects_admission` also runs an identity variant. It checks deterministic
replay, no state mutation on refusal, duplicate behavior, retained dependency
waits, and Snapshot reconstruction from verified witnesses. `fuzz/seed.py`
includes identity histories from the pinned corpus. A coverage-guided run
requires the usual nightly toolchain and cargo-fuzz described in `fuzz/README.md`.
