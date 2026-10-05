# openlfcp/sdk-rs

Independent Rust implementation of LFCP.

It exists to prove that LFCP is an interoperable protocol rather than a
TypeScript convention, so it is written against the specifications and
test vectors in `openlfcp/spec`, not ported from `sdk-ts`.

## Status

Bootstrapped (LFCP-040): the crate layout, lints, CI and access to the
official vectors are in place. The modules are documented placeholders;
the protocol primitives arrive in LFCP-041.

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
| `core` | Identifiers (Resource, Principal, …), errors, byte helpers |
| `crypto` | Thin wrappers over established cryptographic crates; no primitive is implemented here |
| `cbor` | Hand-written deterministic CBOR codec |
| `cose` | Canonical COSE structures |
| `wire` | LFCP Wire structures, messages and validation |

The crate has no application or editor dependency, and it forbids `unsafe`
code. It builds on the stable Rust toolchain; no older minimum version is
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
