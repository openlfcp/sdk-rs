<picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/openlfcp/.github/main/docs/assets/brand/openlfcp-mark-dark.svg"><img src="https://raw.githubusercontent.com/openlfcp/.github/main/docs/assets/brand/openlfcp-mark.svg" width="64" height="64" alt="OpenLFCP"></picture>

# openlfcp/sdk-rs

Website: [openlfcp.org](https://openlfcp.org)

Independent Rust implementation of LFCP.

It exists to prove that LFCP is an interoperable protocol rather than a
TypeScript convention, so it is written against the specifications and
test vectors in `openlfcp/spec`, not ported from `sdk-ts`.

## Scope

sdk-rs implements the OpenLFCP MVP 0.1 subset of LFCP-WIRE-01
at `mvp-0.1-baseline.9`, not every deferred WIRE-01 feature; it has no
invitation URI codec yet. See
`.github: docs/release/deferred-wire-01-features.md` (in [openlfcp/.github](https://github.com/openlfcp/.github)). It does not claim
full LFCP-WIRE-01 conformance.

## Status

Implemented and checked against the official vectors:

- protocol primitives (LFCP-041): identifiers, deterministic CBOR,
  Principals and canonical COSE_Sign1;
- Data Plane crypto (LFCP-042a): DEK commitments, actor and Snapshot
  keys, Data Units, canonical frontiers and Snapshots;
- Control Plane structure (LFCP-042b1): typed Control Records, Control
  Chain validation and fork detection;
- HPKE Key Packages (LFCP-042c);
- wire messages and the session handshake (LFCP-043a): the envelope, every
  typed message body and HELLO / CHALLENGE / AUTH / READY, without I/O;
- anti-entropy (LFCP-043b): Have Vectors, their difference in both
  directions (what to request and what to offer, §68.1), Control sync
  decisions and the §63–§65 state machines;
- the server's `previous` link check for a `DATA_PUT` (§51.1,
  `UNKNOWN_PREVIOUS`);
- capabilities (LFCP-042b2): the capability engine, ownership transfer
  verification and the coordinator's Control transition check;
- Data Epochs (LFCP-042b3): epoch rotation and the strict previous-epoch
  cutoff, with quarantine and `STALE_DATA_EPOCH`.

- the Shared Objects profile (LFCP-069): actor IDs, framing, profile
  validation with its diagnostics, Task intents as Automerge changes,
  conflict exposure, add-wins tags and assignees, tombstones,
  preservation of unknown fields and types, and holding a change whose
  actor sequence is taken until a rebuild frees it (§14.1); checked against
  SHARED-OBJECTS-TEST-VECTORS-01 and the Automerge reference corpus.

In progress for MVP 0.2, feature `shared-sections`:

- the Shared Sections profile (LFCP-02-019): dispatch on the Genesis
  profile, actor IDs with the profile's domain, the typed view of a
  section document (section, nodes, placements, Text versus scalar
  fields, readiness) and the per-node problems of
  SHARED-SECTIONS-PROFILE-01 §14.2; checked against
  SHARED-SECTIONS-TEST-VECTORS-01 at the `spec.lock` pin;
- nodes and structure (LFCP-02-020): the effective tree of §7 with its
  conflicts and visibility, and authoring of the section, Task, paragraph,
  item and raw nodes, moves and explicit placement resolution, one change
  per intent;
- lifecycle and Text (LFCP-02-021): delete and restore as fresh
  assignments (automerge 0.12 skips a same-value write), retained edits
  under a deleted ancestor, Text edits in Unicode scalar indices against a
  base, split and join;
- admission (LFCP-02-022): `SectionsReplica` receives Data Unit plaintexts
  through SHARED-OBJECTS-PROFILE-01's admission (the same engine as Shared
  Objects, not a copy) and then the structural rules A1-A5 against each
  change's causal history; every corpus case replays in order and in
  reverse with duplicates to the corpus's refusals, held changes, heads
  and tree.

The LFCP protocol layer of this SDK (LFCP-041 to LFCP-043) is complete
for MVP 0.1: every LFCP-TEST-VECTORS-01 case is decided in scope.

## Independence rule

This SDK is implemented only from the specification text, the CDDL and the
test vectors at the pinned spec tag. Do not read, port or copy `sdk-ts`
source or tests. Where the specification is unclear, report a spec gap
instead of matching another implementation. A disagreement between this
SDK and `sdk-ts` is a finding to report, not a difference to smooth over.

## Layout

One crate, `lfcp` (`crates/lfcp`), with one module per layer. A module only
uses the modules listed above it.

| Module | Responsibility |
| --- | --- |
| `base` | 32-byte ID types, UUIDv7 Object IDs, hex and base64url, the error type with wire codes |
| `crypto` | SHA-256, HKDF-SHA256, ChaCha20-Poly1305, Ed25519 (strict verification), X25519 and HPKE Base-mode wrappers; no primitive is implemented here |
| `cbor` | Hand-written deterministic CBOR codec (WIRE §5.2) |
| `principal` | Principal IDs, descriptors and keys (WIRE §7) |
| `cose` | Canonical untagged COSE_Sign1: sign, parse, verify (WIRE §10) |
| `wire` | LFCP Wire structures: Data Epoch keys, Data Units, frontiers, Snapshots, Control Records, the Control Chain, Key Packages, messages, the handshake, Have Vectors, state machines, the capability engine and Data Epochs |
| `shared_objects` | Feature `shared-objects` only. The Shared Objects profile on Automerge: actor IDs, plaintext framing, validation and diagnostics, the document and its Task intents |

The crate has no application or editor dependency, and it forbids `unsafe`
code. Its runtime dependencies are `sha2`, `hkdf`, `chacha20poly1305`,
`ed25519-dalek`, `x25519-dalek`, `hpke` and `zeroize`, with default
features off;
`Cargo.toml` justifies each enabled feature.

Cargo features:

| Feature | Default | Adds |
| --- | --- | --- |
| `shared-objects` | off | `lfcp::shared_objects` and `automerge` (pinned at 0.12.0, the core of the profile's reference `@automerge/automerge` 3.5.0) |

The default build is the LFCP protocol core only. The reference server
depends on it that way and never links Automerge or Task semantics
(AGENT-OPERATING-GUIDE §6.4). Clients that use the profile enable
`shared-objects`. There is no CBOR dependency.
Secret keys redact themselves in `Debug` and are wiped on drop. The crate
builds on the stable Rust toolchain; no older minimum version is promised.

## Specification pin

`spec.lock` pins the specification this SDK implements:

```json
{ "tag": "mvp-0.2-baseline.2", "commit": "4198c43ea89d681efa5654a020b2f7b578f90df7" }
```

`mvp-0.2-baseline.2` is the MVP 0.1 baseline `mvp-0.1-baseline.10`
unchanged, plus the shared sections profile, its Markdown grammar, the SDK
integration contracts and their corpus (in `lfcp-vector-format/1`), with
the canonical change encoding and operation references of SPEC-PATCH-10
(SHARED-OBJECTS-PROFILE-01 §11.3, §11.4).

Vectors are never copied into this repository. The tests read them from a
checkout of `openlfcp/spec` with `git show <commit>:<path>`, so the state of
that checkout's working tree does not matter. Before reading, they check
that the tag in `spec.lock` still resolves to the locked commit, and fail
with a clear message if not.

The checkout is found at `$LFCP_SPEC_DIR`, or at `../spec` next to this
repository by default. A relative `LFCP_SPEC_DIR` is resolved against this
repository's root. Moving to a new baseline is a deliberate change to
`spec.lock`.

## Build from a clean checkout

With `openlfcp/spec` cloned next to this repository (as `../spec`,
including its tags), or `LFCP_SPEC_DIR` pointing at it:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
```

These are the same commands CI runs; CI also checks out the spec at the
locked tag. `rust-toolchain.toml` selects the stable channel with rustfmt
and clippy, so rustup installs what is needed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
