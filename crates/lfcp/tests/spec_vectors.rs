//! Smoke test for reading official vectors at the pinned spec commit.

mod support;

use support::spec::Spec;

#[test]
fn wire_vectors_load_at_the_locked_commit() {
    let spec = Spec::open();
    assert_eq!(spec.lock().tag.as_deref(), Some("mvp-0.2-baseline.2"));

    let vectors = spec.read_json("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json");
    assert_eq!(vectors["format"], "lfcp-vector-format/1");
    assert_eq!(vectors["suite"]["id"], "LFCP-TEST-VECTORS-01");
    assert_eq!(vectors["suite"]["specification"]["id"], "LFCP-WIRE-01");
}

#[test]
fn the_baseline_holds_the_shared_sections_corpus() {
    // mvp-0.2-baseline.2: the MVP 0.1 baseline plus the shared sections files.
    let spec = Spec::open();
    let vectors = support::sections::read_sections_corpus(&spec);
    assert_eq!(vectors["suite"], "SHARED-SECTIONS-TEST-VECTORS-01");
    assert_eq!(vectors["profile"], "org.openlfcp.shared-sections.v1");
}
