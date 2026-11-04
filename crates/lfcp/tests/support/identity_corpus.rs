//! Pinned identity corpora and shared differential result helpers.
#![allow(dead_code)]
use super::spec::Spec;
use lfcp::base::{from_b64url, from_hex};
use serde_json::{json, Value as J};
use std::collections::BTreeMap;

pub const WIRE: &str = "test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json";
pub const PROFILE: &str = "test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.json";
pub const FLOWS: &str = "test-vectors/identity-01/IDENTITY-FLOW-FIXTURES-01.json";
pub fn s(j: &J) -> &str {
    j.as_str().expect("string")
}
pub fn bytes(j: &J) -> Vec<u8> {
    if let Some(h) = j.get("hex") {
        from_hex(s(h)).unwrap()
    } else {
        from_b64url(s(&j["b64url"])).unwrap()
    }
}
pub struct Corpus {
    pub data: J,
    pub cases: BTreeMap<String, J>,
}
impl Corpus {
    pub fn load(path: &str) -> Self {
        let data = Spec::open().read_json(path);
        let cases = data["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (s(&c["id"]).to_string(), c.clone()))
            .collect();
        Self { data, cases }
    }
    pub fn case(&self, id: &str) -> &J {
        self.cases
            .get(id)
            .unwrap_or_else(|| panic!("unknown case {id}"))
    }
    pub fn resolve<'a>(&'a self, r: &'a J) -> &'a J {
        if let Some(case) = r.get("case") {
            let c = self.case(s(case));
            &c[r.get("in").map(s).unwrap_or("expected")][s(&r["field"])]
        } else {
            r
        }
    }
    pub fn ref_bytes(&self, r: &J) -> Vec<u8> {
        bytes(self.resolve(r))
    }
}
pub fn check(c: &J, result: &J) {
    let id = s(&c["id"]);
    let e = &c["expected"];
    if let Some(valid) = e["valid"].as_bool() {
        assert_eq!(
            result["outcome"],
            if valid {
                json!("accept")
            } else {
                e["error"]["code"].clone()
            },
            "{id}: {result}"
        );
        if let Some(d) = e["error"].get("diagnostic") {
            assert_eq!(&result["diagnostic"], d, "{id}");
        }
    }
}
pub fn accepted(ids: Vec<String>, state: J) -> J {
    json!({"outcome":"accept","accepted_ids":ids,"post_state":state})
}
pub fn refused(code: &str, diagnostic: Option<&str>) -> J {
    json!({"outcome":code,"diagnostic":diagnostic,"accepted_ids":[],"post_state":null})
}
pub fn export(name: &str, results: &BTreeMap<String, J>) {
    if let Some(dir) = std::env::var_os("LFCP_IDENTITY_REPORT_DIR") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(dir);
        std::fs::create_dir_all(&path).unwrap();
        let pin = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec.lock"),
        )
        .unwrap();
        std::fs::write(path.join(format!("{name}.json")),serde_json::to_vec_pretty(&json!({"format":"lfcp-identity-outcomes/1","implementation":"sdk-rs","spec":serde_json::from_str::<J>(&pin).unwrap(),"cases":results})).unwrap()).unwrap();
    }
}
