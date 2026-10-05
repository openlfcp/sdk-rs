# openlfcp/sdk-rs

Independent Rust implementation of LFCP.

It exists to prove that LFCP is an interoperable protocol rather than a
TypeScript convention, so it is written against the specifications and
test vectors in `openlfcp/spec`, not ported from `sdk-ts`.

## Status

The protocol primitives are implemented and checked against the official
vectors (LFCP-041): identifiers, deterministic CBOR, Principals and
canonical COSE_Sign1. Control Plane, Data Plane, AEAD, HKDF and HPKE are
LFCP-042; the wire session is LFCP-043.

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
| `crypto` | SHA-256, Ed25519 (strict verification) and X25519 wrappers; no primitive is implemented here |
| `cbor` | Hand-written deterministic CBOR codec (WIRE §5.2) |
| `principal` | Principal IDs, descriptors and keys (WIRE §7) |
| `cose` | Canonical untagged COSE_Sign1: sign, parse, verify (WIRE §10) |
| `wire` | LFCP Wire structures, messages and validation (empty until LFCP-042) |

The crate has no application or editor dependency, and it forbids `unsafe`
code. Its runtime dependencies are `sha2`, `ed25519-dalek` and
`x25519-dalek`, with default features off; `Cargo.toml` justifies each
enabled feature. There is no CBOR dependency. It builds on the stable Rust toolchain; no older minimum version is
promised.

## Specification pin

`spec.lock` pins the specification this SDK implements:

```json
{ "tag": "mvp-0.1-baseline.2", "commit": "1527feda3f4cc3accb62b3fe0ea3ab2e0d40c0f6" }
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
