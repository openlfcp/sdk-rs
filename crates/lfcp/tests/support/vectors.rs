//! The LFCP-TEST-VECTORS-01 suite, read at the pinned spec commit.

use std::collections::BTreeMap;

use lfcp::base::{self, PrincipalId};
use lfcp::principal::PrincipalKeys;
use serde_json::Value as Json;

use super::spec::Spec;

pub const VECTORS: &str = "test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json";

pub struct Suite {
    pub json: Json,
}

impl Suite {
    pub fn load() -> Suite {
        Suite {
            json: Spec::open().read_json(VECTORS),
        }
    }

    pub fn cases(&self) -> impl Iterator<Item = &Json> {
        self.json["cases"].as_array().expect("cases array").iter()
    }

    pub fn case(&self, id: &str) -> &Json {
        self.cases()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("vector case {id} is missing"))
    }

    /// Principal keys from the `principal_*` cases, by fixture name
    /// (`OWNER`, `BOB`, …).
    pub fn principals(&self) -> BTreeMap<String, PrincipalKeys> {
        self.cases()
            .filter(|case| case["kind"] == "principal" && case["type"] == "bytes")
            .map(|case| {
                let id = id_of(case);
                let name = id.trim_start_matches("principal_").to_uppercase();
                let inputs = &case["inputs"];
                let keys = PrincipalKeys::from_secrets(
                    &hex32(id, &inputs["ed25519_seed"]),
                    hex32(id, &inputs["x25519_private"]),
                );
                (name, keys)
            })
            .collect()
    }
}

pub fn id_of(case: &Json) -> &str {
    case["id"].as_str().expect("case id")
}

/// The bytes of a `{"hex": …}` field.
pub fn hex(case_id: &str, field: &Json) -> Vec<u8> {
    let text = field["hex"]
        .as_str()
        .unwrap_or_else(|| panic!("{case_id}: field is not {{\"hex\": …}}: {field}"));
    base::from_hex(text).unwrap_or_else(|err| panic!("{case_id}: bad hex: {err}"))
}

pub fn hex32(case_id: &str, field: &Json) -> [u8; 32] {
    base::fixed(&hex(case_id, field)).unwrap_or_else(|err| panic!("{case_id}: {err}"))
}

pub fn principal_by_id<'a>(
    principals: &'a BTreeMap<String, PrincipalKeys>,
    case_id: &str,
    id: &PrincipalId,
) -> &'a PrincipalKeys {
    principals
        .values()
        .find(|keys| keys.descriptor().id() == id)
        .unwrap_or_else(|| panic!("{case_id}: no fixture Principal has ID {id:?}"))
}
