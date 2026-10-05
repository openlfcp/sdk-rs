//! Profile values: plain values read from Automerge, and the grammars of
//! Local Dates (SHARED-OBJECTS-PROFILE-01 §35), timestamps (§28),
//! reverse-domain names (§18) and the `lifecycle`, `status` and `priority`
//! values (§26, §33, §38).

use std::collections::BTreeMap;

use automerge::{ObjId, ObjType, ReadDoc, ScalarValue, Value};

use crate::shared_objects::ProfileError;

/// A value of the document as plain data.
///
/// Scalar strings and collaborative Text stay distinct: the profile writes
/// every string as a scalar (PROVISIONAL, G-SC3), so a [`Plain::Text`] is a
/// representation the validator reports.
#[derive(Clone, Debug, PartialEq)]
pub enum Plain {
    /// `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A signed integer (Automerge `int`).
    Int(i64),
    /// An unsigned integer (Automerge `uint`).
    Uint(u64),
    /// A float.
    F64(f64),
    /// A scalar string.
    Str(String),
    /// Collaborative Text, as its current string.
    Text(String),
    /// Bytes.
    Bytes(Vec<u8>),
    /// A counter's value.
    Counter(i64),
    /// A timestamp (milliseconds).
    Timestamp(i64),
    /// A map.
    Map(BTreeMap<String, Plain>),
    /// A list.
    List(Vec<Plain>),
    /// A scalar of a type from a future Automerge version.
    Unknown,
}

impl Plain {
    /// The string of a scalar string, and of nothing else.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Plain::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The entries of a map.
    pub fn as_map(&self) -> Option<&BTreeMap<String, Plain>> {
        match self {
            Plain::Map(m) => Some(m),
            _ => None,
        }
    }

    /// A map value from `(key, value)` pairs.
    pub fn map<K: Into<String>>(entries: impl IntoIterator<Item = (K, Plain)>) -> Plain {
        Plain::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// A scalar string.
    pub fn str(s: impl Into<String>) -> Plain {
        Plain::Str(s.into())
    }
}

impl From<&ScalarValue> for Plain {
    fn from(value: &ScalarValue) -> Plain {
        match value {
            ScalarValue::Bytes(b) => Plain::Bytes(b.clone()),
            ScalarValue::Str(s) => Plain::Str(s.to_string()),
            ScalarValue::Int(i) => Plain::Int(*i),
            ScalarValue::Uint(u) => Plain::Uint(*u),
            ScalarValue::F64(f) => Plain::F64(*f),
            ScalarValue::Counter(c) => Plain::Counter(i64::from(c)),
            ScalarValue::Timestamp(t) => Plain::Timestamp(*t),
            ScalarValue::Boolean(b) => Plain::Bool(*b),
            ScalarValue::Unknown { .. } => Plain::Unknown,
            ScalarValue::Null => Plain::Null,
        }
    }
}

/// Read the value `value` with ID `id` from `doc` as plain data. A map
/// with conflicting keys shows each key's Automerge-selected value; use
/// `get_all` to see the others.
pub fn read(doc: &impl ReadDoc, value: &Value<'_>, id: &ObjId) -> Result<Plain, ProfileError> {
    Ok(match value {
        Value::Scalar(scalar) => Plain::from(scalar.as_ref()),
        Value::Object(ObjType::Map | ObjType::Table) => {
            let mut map = BTreeMap::new();
            for key in doc.keys(id) {
                if let Some((child, child_id)) = doc.get(id, key.as_str())? {
                    map.insert(key, read(doc, &child, &child_id)?);
                }
            }
            Plain::Map(map)
        }
        Value::Object(ObjType::List) => {
            let mut list = Vec::new();
            for index in 0..doc.length(id) {
                if let Some((child, child_id)) = doc.get(id, index)? {
                    list.push(read(doc, &child, &child_id)?);
                }
            }
            Plain::List(list)
        }
        Value::Object(ObjType::Text) => Plain::Text(doc.text(id)?),
    })
}

fn digits(s: &str) -> Option<u32> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

/// Whether `year-month-day` is a Gregorian calendar date.
fn is_date(year: u32, month: u32, day: u32) -> bool {
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn date_part(s: &str) -> Option<(u32, u32, u32)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, m, d) = (digits(&s[0..4])?, digits(&s[5..7])?, digits(&s[8..10])?);
    is_date(y, m, d).then_some((y, m, d))
}

/// A Local Date: `YYYY-MM-DD`, a valid Gregorian date (§35).
pub fn is_local_date(s: &str) -> bool {
    date_part(s).is_some()
}

/// An RFC 3339 UTC timestamp with `Z` (§28):
/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, with a valid date, hour 00–23,
/// minute 00–59 and second 00–60 (a leap second).
pub fn is_utc_timestamp(s: &str) -> bool {
    let Some((date, time)) = s.split_once('T') else {
        return false;
    };
    let Some(time) = time.strip_suffix('Z') else {
        return false;
    };
    let (hms, fraction) = match time.split_once('.') {
        Some((hms, fraction)) => (hms, Some(fraction)),
        None => (time, None),
    };
    let b = hms.as_bytes();
    let time_ok = b.len() == 8
        && b[2] == b':'
        && b[5] == b':'
        && digits(&hms[0..2]).is_some_and(|h| h < 24)
        && digits(&hms[3..5]).is_some_and(|m| m < 60)
        && digits(&hms[6..8]).is_some_and(|s| s <= 60);
    let fraction_ok =
        fraction.is_none_or(|f| !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit()));
    date_part(date).is_some() && time_ok && fraction_ok
}

/// A `reverse-domain` name (§18): at least two dot-separated labels of
/// lowercase letters, digits and inner hyphens.
pub fn is_reverse_domain(s: &str) -> bool {
    let label_ok = |label: &str| {
        let b = label.as_bytes();
        let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        !b.is_empty()
            && alnum(&b[0])
            && alnum(&b[b.len() - 1])
            && b.iter().all(|c| alnum(c) || *c == b'-')
    };
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| label_ok(l))
}

/// A namespaced extension value `x/<reverse-domain>/<value>`, value
/// non-empty and without `/` (§33).
pub fn is_namespaced_value(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("x/") else {
        return false;
    };
    match rest.split_once('/') {
        Some((domain, value)) => {
            is_reverse_domain(domain) && !value.is_empty() && !value.contains('/')
        }
        None => false,
    }
}

/// The standard `lifecycle` values: a closed set (§26).
pub const LIFECYCLES: [&str; 2] = ["active", "deleted"];
/// The standard `status` values (§33).
pub const STATUSES: [&str; 4] = ["todo", "in_progress", "done", "cancelled"];
/// The standard `priority` values (§38).
pub const PRIORITIES: [&str; 5] = ["lowest", "low", "normal", "high", "highest"];

/// A valid `lifecycle` (§26).
pub fn is_lifecycle(s: &str) -> bool {
    LIFECYCLES.contains(&s)
}

/// A valid `status`: standard or a namespaced extension value (§33).
pub fn is_status(s: &str) -> bool {
    STATUSES.contains(&s) || is_namespaced_value(s)
}

/// A valid `priority`: standard or a namespaced extension value (§38).
pub fn is_priority(s: &str) -> bool {
    PRIORITIES.contains(&s) || is_namespaced_value(s)
}

/// A portable tag: non-empty and without a leading `#` (§40).
pub fn is_tag(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('#')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_dates() {
        for ok in ["2026-10-04", "2024-02-29", "2000-02-29", "0001-01-01"] {
            assert!(is_local_date(ok), "{ok}");
        }
        for bad in [
            "2026-13-50",
            "2026-02-29",
            "1900-02-29",
            "2026-1-04",
            "2026-10-04Z",
            "",
            "2026/10/04",
        ] {
            assert!(!is_local_date(bad), "{bad}");
        }
    }

    #[test]
    fn timestamps() {
        for ok in [
            "2026-10-04T05:30:00Z",
            "2026-10-04T23:59:60Z",
            "2026-10-04T05:30:00.123Z",
        ] {
            assert!(is_utc_timestamp(ok), "{ok}");
        }
        for bad in [
            "2026-10-04T05:30:00",
            "2026-10-04T05:30:00+00:00",
            "2026-10-04 05:30:00Z",
            "2026-10-04T24:00:00Z",
            "2026-10-04T05:30:00.Z",
            "2026-02-30T05:30:00Z",
        ] {
            assert!(!is_utc_timestamp(bad), "{bad}");
        }
    }

    #[test]
    fn namespaces_and_enum_values() {
        assert!(is_reverse_domain("com.example.tracker"));
        assert!(is_reverse_domain("org.open-lfcp"));
        for bad in [
            "example",
            "Com.example",
            "com..example",
            "com.-x",
            "com.x-",
            "",
        ] {
            assert!(!is_reverse_domain(bad), "{bad}");
        }
        assert!(is_status("x/com.example/waiting_review"));
        assert!(!is_status("x/com.example/"));
        assert!(!is_status("x/com.example/a/b"));
        assert!(!is_status("waiting"));
        assert!(is_priority("highest") && !is_priority("urgent"));
        assert!(is_lifecycle("deleted") && !is_lifecycle("x/com.example/archived"));
        assert!(is_tag("backend") && !is_tag("") && !is_tag("#backend"));
    }
}
