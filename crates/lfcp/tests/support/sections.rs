//! The shared sections corpus in the shape these tests read (LFCP-02-107).
//! SHARED-SECTIONS-TEST-VECTORS-01 moved to `lfcp-vector-format/1` after
//! mvp-0.2-baseline.1: every value moved without changing (spec
//! `migrations/vector-format-1/shared-sections-01.mapping.json`), and its
//! byte records went from standard base64 to unpadded base64url. A suite in
//! that format is read back into the earlier shape, so one test runs at
//! either baseline.

use serde_json::{json, Map, Value as Json};

use super::spec::Spec;

pub const SECTIONS_CORPUS: &str =
    "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

/// The corpus of the pinned spec, in the mvp-0.2-baseline.1 shape.
pub fn read_sections_corpus(spec: &Spec) -> Json {
    legacy_sections(spec.read_json(SECTIONS_CORPUS))
}

/// Every `{ "b64url": … }` byte record, at any depth, as `{ "base64": … }`.
fn to_base64_records(value: Json) -> Json {
    match value {
        Json::Array(items) => Json::Array(items.into_iter().map(to_base64_records).collect()),
        Json::Object(fields) => Json::Object(
            fields
                .into_iter()
                .map(|(k, v)| match (k.as_str(), &v) {
                    ("b64url", Json::String(text)) => {
                        let mut std: String = text
                            .chars()
                            .map(|c| match c {
                                '-' => '+',
                                '_' => '/',
                                c => c,
                            })
                            .collect();
                        while !std.len().is_multiple_of(4) {
                            std.push('=');
                        }
                        ("base64".to_owned(), Json::String(std))
                    }
                    _ => (k, to_base64_records(v)),
                })
                .collect(),
        ),
        other => other,
    }
}

/// A suite in `lfcp-vector-format/1` in the mvp-0.2-baseline.1 shape (the mapping, inverted).
pub fn legacy_sections(suite: Json) -> Json {
    if suite["format"] != "lfcp-vector-format/1" {
        return suite;
    }
    let c = &suite["suite"]["conventions"];
    let cases: Vec<Json> = suite["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|k| {
            let mut out = Map::new();
            out.insert("id".into(), k["id"].clone());
            out.insert("title".into(), k["description"].clone());
            let (i, e) = (&k["inputs"], &k["expected"]);
            for (old, new) in [
                ("coverage", &e["coverage"]),
                ("notes", &e["notes"]),
                ("base_snapshot", &i["base_snapshot"]),
                ("base_changes", &i["base_changes"]),
                ("branches", &i["branches"]),
                ("after_merge", &i["after_merge"]),
                ("assertions", &e["requirements"]),
                ("expected", &e["state"]),
                ("expected_heads", &e["heads"]),
                ("reference_snapshot", &e["reference_snapshot"]),
                (
                    "reference_snapshot_plaintext",
                    &e["reference_snapshot_plaintext"],
                ),
            ] {
                if !new.is_null() {
                    out.insert(old.into(), new.clone());
                }
            }
            Json::Object(out)
        })
        .collect();
    to_base64_records(json!({
        "schema_version": 1,
        "suite": suite["suite"]["id"],
        "date": c["date"],
        "status": c["status"],
        "profile": suite["suite"]["specification"]["profile"],
        "engine": { "package": c["engine_package"], "version": c["engine_version"], "role": c["engine_role"] },
        "wire_coverage": c["wire_coverage"],
        "identities": suite["fixtures"]["identities"],
        "cases": cases,
    }))
}
