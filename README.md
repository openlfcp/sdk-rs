# openlfcp/sdk-rs

Independent Rust implementation of LFCP.

It exists to prove that LFCP is an interoperable protocol rather than a
TypeScript convention, so it is written against the specifications and
test vectors in `openlfcp/spec`, not ported from `sdk-ts`.

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
- anti-entropy (LFCP-043b): Have Vectors, their difference, Control sync
  decisions and the §63–§65 state machines;
- capabilities (LFCP-042b2): the capability engine, ownership transfer
  verification and the coordinator's Control transition check;
- Data Epochs (LFCP-042b3): epoch rotation and the strict previous-epoch
  cutoff, with quarantine and `STALE_DATA_EPOCH`.

- the Shared Objects profile (LFCP-069): actor IDs, framing, profile
  validation with its diagnostics, Task intents as Automerge changes,
  conflict exposure, add-wins tags and assignees, tombstones and
  preservation of unknown fields and types; checked against
  SHARED-OBJECTS-TEST-VECTORS-01 and the Automerge reference corpus.

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
| `shared_objects` | The Shared Objects profile on Automerge: actor IDs, plaintext framing, validation and diagnostics, the document and its Task intents |

The crate has no application or editor dependency, and it forbids `unsafe`
code. Its runtime dependencies are `sha2`, `hkdf`, `chacha20poly1305`,
`ed25519-dalek`, `x25519-dalek`, `hpke`, `zeroize` and `automerge`
(pinned at 0.12.0, the core of the profile's reference
`@automerge/automerge` 3.5.0), with default features off;
`Cargo.toml` justifies each enabled feature. There is no CBOR dependency.
Secret keys redact themselves in `Debug` and are wiped on drop. The crate
builds on the stable Rust toolchain; no older minimum version is promised.

## Specification pin

`spec.lock` pins the specification this SDK implements:

```json
{ "tag": "mvp-0.1-baseline.3", "commit": "4a558fb39ebb13da5b479989491c18ecaf9258da" }
```

Vectors are never copied into this repository. The tests read them from a
checkout of `openlfcp/spec` with `git show <commit>:<path>`, so the state of
that checkout's working tree does not matter. Before reading, they check
that the tag in `spec.lock` still resolves to the locked commit, and fail
with a clear message if it does not.

The checkout is found at `$LFCP_SPEC_DIR`, or at `../spec` next to this
repository by default. A relative `LFCP_SPEC_DIR` is resolved against this
repository's root. Moving to a new baseline is a deliberate change to
`spec.lock`.

## Build from a clean checkout

With `openlfcp/spec` cloned next to this repository (as `../spec`,
including its tags), or `LFCP_SPEC_DIR` pointing at it:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

These are the same commands CI runs; CI also checks out the spec at the
locked tag. `rust-toolchain.toml` selects the stable channel with rustfmt
and clippy, so rustup installs what is needed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
