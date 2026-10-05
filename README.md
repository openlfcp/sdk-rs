# openlfcp/sdk-rs

Independent Rust implementation of LFCP.

It exists to prove that LFCP is an interoperable protocol rather than a
TypeScript convention, so it is written against the specifications and
test vectors in `openlfcp/spec`, not ported from `sdk-ts`.

## Status

Repository scaffold only. The Rust SDK bootstrap is LFCP-040.

## Build from a clean checkout

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

These are the same commands CI runs. `rust-toolchain.toml` selects the
stable channel with rustfmt and clippy, so rustup installs what is needed.

## License

Apache License 2.0. See [LICENSE](LICENSE).
