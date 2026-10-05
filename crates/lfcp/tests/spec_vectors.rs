//! Smoke test for reading official vectors at the pinned spec commit.

mod support;

use support::spec::Spec;

#[test]
fn wire_vectors_load_at_the_locked_commit() {
    let spec = Spec::open();
    assert_eq!(spec.lock().tag, "mvp-0.1-baseline.5");

    let vectors = spec.read_json("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json");
    assert_eq!(vectors["format"], "lfcp-vector-format/1");
    assert_eq!(vectors["suite"]["id"], "LFCP-TEST-VECTORS-01");
    assert_eq!(vectors["suite"]["specification"]["id"], "LFCP-WIRE-01");
}
