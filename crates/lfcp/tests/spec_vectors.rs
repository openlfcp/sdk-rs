//! Smoke test for reading official vectors at the pinned spec commit.

mod support;

use support::spec::Spec;

#[test]
fn wire_vectors_load_at_the_locked_commit() {
    let spec = Spec::open();
    assert_eq!(spec.lock().tag.as_deref(), Some("mvp-0.1-baseline.9"));

    let vectors = spec.read_json("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json");
    assert_eq!(vectors["format"], "lfcp-vector-format/1");
    assert_eq!(vectors["suite"]["id"], "LFCP-TEST-VECTORS-01");
    assert_eq!(vectors["suite"]["specification"]["id"], "LFCP-WIRE-01");
}

#[test]
fn the_sections_dev_pin_reads_the_shared_sections_corpus() {
    // spec-sections.lock: a commit pin of the MVP 0.2 shared sections files
    // before their baseline is tagged.
    let spec = Spec::open_sections();
    assert!(spec.lock().tag.is_none());
    let vectors =
        spec.read_json("test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json");
    assert_eq!(vectors["suite"], "SHARED-SECTIONS-TEST-VECTORS-01");
    assert_eq!(vectors["profile"], "org.openlfcp.shared-sections.v1");
}
