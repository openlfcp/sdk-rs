# openlfcp/sdk-rs

Independent Rust implementation of LFCP.

It exists to prove that LFCP is an interoperable protocol rather than a
TypeScript convention, so it is written against the specifications and
test vectors in `openlfcp/spec`, not ported from `sdk-ts`.

## Status

Repository scaffold only. The Rust SDK bootstrap is LFCP-040.

## Build from a clean checkout

```sh
cargo test --workspace
```

Requires a stable Rust toolchain.

## License

Apache License 2.0. See [LICENSE](LICENSE).
