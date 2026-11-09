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
profile outcomes contain `outcome` (accept, a code, or explicit N/A), `diagnostic`
when relevant, `accepted_ids` and `post_state`. Profile N/A includes a
`not_applicable` reason. Flow outcomes include each executed step, its
accepted IDs/state, and `not_applicable` with specific spec citations. Hashes use
lowercase hex. Control state uses the corpus's human-readable Principal and
certificate names; stored history is independent of those labels.

`identity_vectors` covers 424 ID-01–ID-04 cases and 303 ID-05 cases, including
all post-state assertions, the Key Package matrix, HPKE opening, immutable unit
metadata for initialisation, concurrent requests and Snapshot equivalence.
AI5 is mandatory. The union fixture is inspected as state and refused as a
Snapshot; its expected state-validation verdict is unchanged. Document results
compare every expected field, including admitted/refused/pending changes,
entry validity, Snapshot initial change, and distinct conflict sets. READY is
decoded as a complete typed message. Unknown expected fields fail tests.
The invitation-parser rejection case is N/A: sdk-rs has no invitation-URI
parser (IDENTITY-PROFILE-01 §5.2 / WIRE §18.2). The pairing-parser cases execute.
The pairing-link checks of §5.2 (`pair_uri_*` with a binding head) are composed
from `PairingLink::parse` (check 1), `ControlState::may_read` at the binding
head (check 2, the WIRE §41 open as J), the Genesis Data Profile (check 3) and
the device binding (check 4); sdk-rs has no client that runs them over a
session. The revoked-reader reads of WIRE §41 (`RESOURCE_OPENED`, ranged
`CONTROL_GET`, presence) are modelled on `may_read` and the message codecs; an
inverted `CONTROL_GET` range is refused by the decoder (§45).
`KEY_PACKAGE_PUT_same_root_without_identity_01` is N/A: a server without
`identity-01` refuses a same-root Key Package as a pre-identity receiver does
(WIRE §37, §100.1), and sdk-rs's authority has no pre-identity mode.

`identity_flows` executes every fixture's supplied Wire and profile case. It
also exercises actual CAS and exact-byte replay, epochs and quarantine/rebuild,
verified-sequence frontiers, certificate signing from journal payloads, service
approval provenance and fork detection. Phase classification, ledger receipts
and client scheduling are local simulations of §§7–9, marked `simulation: true`
in the flow export; they are not a persistent client implementation or evidence
of network delivery.

The following parts are N/A, with the remaining steps still checked:

- F07 step 6: the client roster update in DAVE's separate Identity Resource
  (§7.2); the fixture supplies no document/units for that Resource.
- F09 steps 4 and 16: offline reachability and persisted candidates (§5.3).
- F10 step 3: human re-confirmation (§5.3). Steps 7–8, offered presets and the
  final feasibility assertion: the SDK lacks an API for building and checking
  future certificate chains, trimming scope and rechecking at a new head
  (§5.3 step 4). This is an SDK coverage gap, not merely missing UI.
- F14's `frontier_rule`: explanatory prose, explicitly accounted for in N/A;
  the actual frontier and hole/cutoff outcomes are checked from verified units.
- F17 step 5: server subscription removal before pushes (WIRE §69).
- F18: pre-identity/herald validators and persisted blocked-client UI
  (WIRE §100.1), the client's READY check before a same-root Key Package
  (step 6, WIRE §37) and the pre-identity server's refusal of it (step 7). This
  SDK's identity-aware and stale-head outcomes and both Key Package controls are
  checked.
- Reconciliation (IDENTITY-PROFILE-01 §7.1, §8.4): sdk-rs has no
  reconciliation implementation, by design. The case-less steps of F05 (step 3),
  F05.sixty_five_sessions (5, 10), F05.display_data (2, 5, 9) and F09 (7, 11),
  and the fields `proposals`, `not_propagated`, `reported`, `pair_state`,
  `rotation`, `writes`, `metadata_changes` and the display-entry finals are N/A.
  The Wire records reconciliation proposes, the target states after them, the
  W §17.5 rule 5 count of unbound revoked pairs, the pairing devices bound in I
  and the pairing tombstones in X are checked on Control state.
- F07.read_device_cannot_claim step 2 and its final count: the claim decision
  is client orchestration; `holds(D, 2)` in I is checked for DEV_R and DEV_B.
- F08.link_rejected (`request_written`, `sent_as_pairing_device_after_rejection`,
  `reported`, final) and F08.missing_material (steps 2–3, final): what a
  pairing client writes or offers; the link checks and I's epochs are decided.

Register phases take the issuers from the planned `chain` of the phase input
(built with `CertificateChain::new`, which checks c1, c5 and c7), not from the
current binding (F13.issuer_revoked_before_resume).

`objects_admission` also runs an identity variant. It checks deterministic
replay, no state mutation on refusal, duplicate behavior, retained dependency
waits, and Snapshot reconstruction from verified witnesses. `fuzz/seed.py`
includes identity histories from the pinned corpus. A coverage-guided run
requires the usual nightly toolchain and cargo-fuzz described in `fuzz/README.md`.
