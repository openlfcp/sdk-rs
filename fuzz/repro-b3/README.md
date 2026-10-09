# Reproducers of the baseline.3 admission campaign

Against sdk-rs 5d4a806, spec mvp-0.2-baseline.3 (8076d89).

## T1: Shared Sections admission is quadratic in a children list (time)

`structural_refusal` (crates/lfcp/src/shared_sections.rs, the A1/A2 loop
over `lanes`) reads every children list a change touches whole, before and
after the change (`list_values` / `list_strings`, one `AutoCommit::get` per
index), and compares them as sequences. A section of N nodes under one
parent therefore costs O(N) per received change and O(N²) to receive.
Honest history, one writer, every node an item appended to the section,
release build:

| nodes | receive all |
| ---: | ---: |
| 500 | 0.86 s |
| 1,000 | 3.1 s |
| 2,000 | 13.7 s |
| 2,500 | 29.8 s |

`t1_section_admission_scale.rs` prints those numbers: copy it to
`crates/lfcp/examples/` and run
`cargo run --release --features shared-sections --example t1_section_admission_scale -- 2000`.
Authoring has the same shape (`insertion_index`): 2,000 nodes take 8.8 s.

## T2: Shared Objects `apply_change` is quadratic (time, smaller)

One writer's root puts applied one at a time: 1,000 → 0.13 s, 2,000 →
0.40 s, 4,000 → 1.78 s. Each `apply_change` clones the whole document as a
backup (`engine_apply`, `apply_change_checked`).

## N1: §11.3 rule 8 admits a start op of 2^32 when a change has no operations

`N1-canonical` is an input of the `canonical` target (`[flags][chunk]`):
a change without operations whose start op is 2^32. Rule 8 bounds "the
change's last operation counter (start op + N - 1)", which is then
2^32 - 1, so `canonical::check` accepts it; automerge 0.12 refuses the start
op itself (`CounterTooLarge`), and `decode_change` refuses the change. No
harm on the receiver; the spec and the engine disagree at the edge. The
target skips this class unless `LFCP_FUZZ_N1=1`.
