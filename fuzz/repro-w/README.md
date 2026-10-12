# diff_wire: sdk-rs against sdk-ts, the Wire codec

sdk-rs 74c3a71 (mvp-0.2-baseline.10) against `@openlfcp/wire`,
`@openlfcp/core` and `@openlfcp/shared-objects` 0.2.0-beta.5 from npm
(`LFCP_SDK_TS_NPM`), sdk-ts a black box. Seeds: the messages and COSE
objects of LFCP-TEST-VECTORS-01 at baseline.10.

Each file is a `diff_wire` input; `LFCP_FUZZ_TRACE=1` prints both sides,
`LFCP_FUZZ_ALL=1` crashes on W1 and W2 too.

| File | Input | sdk-rs | sdk-ts | Spec |
| --- | --- | --- | --- | --- |
| `W1-hello-invalid-descriptor` | HELLO whose Principal Descriptor's ID does not match its keys | `Message::decode_frame`: MALFORMED_MESSAGE | `decodeFrame`: AUTH_FAILED | §7: AUTH_FAILED in HELLO and AUTH. The same verdict at another layer: the server answers this HELLO with ERROR(AUTH_FAILED) and closes. 472 of the run's crashes |
| `W2-genesis-control-seq` | a Genesis Record at `control_seq` 2 with a null `prev_control_id` | `ReceivedControlRecord::parse`: ok | `parseControlRecord`: INVALID_CONTROL_CHAIN | §13.1: INVALID_CONTROL_CHAIN. sdk-rs refuses it when it places the record (`chain.rs` `check_placement`, GenesisMissing): the same verdict, another step. 10 crashes, `control_seq` 1, 2, 4 and 8 |
| `W3-unassigned-type-no-message-id` | an envelope of type 117 (unassigned) without field 1 (Message ID) | PROTOCOL_UNSUPPORTED | MALFORMED_MESSAGE | Open: §32 makes the missing Message ID MALFORMED_MESSAGE and §33 the type PROTOCOL_UNSUPPORTED, and neither says which comes first. sdk-rs decodes the body by type before it reads the Message ID (`message.rs` `Message::decode`); sdk-ts checks the envelope first. 1 crash |

## The 60-minute runs, 2026-10-12

- `diff_wire`, `-fork=6`: 6,751,704 executions, 482 crashes: 472 W1,
  10 W2, 1 W3. No other class.
- `diff_ts` with `LFCP_FUZZ_OBJECTS_ONLY=1 LFCP_FUZZ_ALL=1` (Shared
  Objects, no name skipping), `-fork=6`, the shared-objects-01 seeds of
  baseline.10: 1,114,801 executions, no crash.
