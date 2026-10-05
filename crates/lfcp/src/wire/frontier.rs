//! Actor Have entries and canonical frontiers (LFCP-WIRE-01 §28).
//!
//! ```text
//! actor-have = {0: principal-id, 1: contiguous, ? 2: [* [start, end]]}
//! canonical-frontier = [* actor-have]
//! ```
//!
//! A frontier inside a persistent object or a cryptographic input must be
//! canonical (§28.1 rules 1–9, §28.2 order); anything else is rejected with
//! `MALFORMED_MESSAGE` (N6). Validation never repairs: [`Frontier::new`]
//! sorts entries by Principal ID, the one change that cannot alter
//! meaning, and rejects everything else that is not canonical.

use crate::base::{Error, FrontierRule, PrincipalId};
use crate::cbor::Value;
use crate::wire::{check_closed_map, principal_field, uint_field};

/// What one Principal's Data Units a replica holds (§28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorHave {
    /// Field 0: the actor.
    pub principal: PrincipalId,
    /// Field 1: the highest sequence up to which every unit is held.
    pub contiguous: u64,
    /// Field 2: further held ranges `(start, end)`, inclusive.
    pub extra: Vec<(u64, u64)>,
}

impl ActorHave {
    /// Check the §28.1 rules for one entry.
    pub fn check_canonical(&self) -> Result<(), Error> {
        let violation = |rule| Err(Error::FrontierNotCanonical(rule));
        let mut previous: Option<(u64, u64)> = None;
        for &(start, end) in &self.extra {
            if start > end {
                return violation(FrontierRule::RangeReversed);
            }
            // Rule 5: strictly above contiguous, and the first range starts
            // at or above contiguous + 2; a range at contiguous + 1 extends
            // the contiguous prefix (§28.1, W3). Later ranges are further
            // up, so checking every range is the same rule.
            if start <= self.contiguous.saturating_add(1) {
                return violation(FrontierRule::RangeNotAboveContiguous);
            }
            if let Some((prev_start, prev_end)) = previous {
                if (start, end) < (prev_start, prev_end) {
                    return violation(FrontierRule::RangesUnsorted);
                }
                if start <= prev_end {
                    return violation(FrontierRule::RangesOverlapping);
                }
                // start > prev_end here, so prev_end + 1 cannot overflow.
                if start == prev_end + 1 {
                    return violation(FrontierRule::RangesAdjacent);
                }
            }
            previous = Some((start, end));
        }
        Ok(())
    }

    /// Decode and check one canonical `actor-have` value.
    pub fn from_value(value: &Value) -> Result<ActorHave, Error> {
        let err = Error::FrontierMalformed;
        if value.as_map().is_none() {
            return Err(err);
        }
        if value.get_uint(0).is_none() || value.get_uint(1).is_none() {
            return Err(Error::FrontierNotCanonical(FrontierRule::MissingKey));
        }
        check_closed_map(value, &[0, 1], &[2], err.clone())?;
        let extra = match value.get_uint(2) {
            None => Vec::new(),
            Some(ranges) => {
                let ranges = ranges.as_array().ok_or(err.clone())?;
                if ranges.is_empty() {
                    return Err(Error::FrontierNotCanonical(FrontierRule::EmptyExtraList));
                }
                ranges
                    .iter()
                    .map(|range| match range.as_array() {
                        Some([start, end]) => Ok((
                            start.as_u64().ok_or(err.clone())?,
                            end.as_u64().ok_or(err.clone())?,
                        )),
                        _ => Err(err.clone()),
                    })
                    .collect::<Result<_, _>>()?
            }
        };
        let have = ActorHave {
            principal: principal_field(value, 0, &err)?,
            contiguous: uint_field(value, 1, &err)?,
            extra,
        };
        have.check_canonical()?;
        Ok(have)
    }

    /// The canonical CBOR value: key 2 only when there are extra ranges.
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (
                Value::Unsigned(0),
                Value::bytes(self.principal.as_bytes().to_vec()),
            ),
            (Value::Unsigned(1), Value::Unsigned(self.contiguous)),
        ];
        if !self.extra.is_empty() {
            let ranges = self
                .extra
                .iter()
                .map(|&(start, end)| {
                    Value::Array(vec![Value::Unsigned(start), Value::Unsigned(end)])
                })
                .collect();
            entries.push((Value::Unsigned(2), Value::Array(ranges)));
        }
        Value::Map(entries)
    }
}

/// A canonical frontier: canonical entries in ascending raw Principal ID
/// order, at most one per Principal (§28.1 rule 9, §28.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier(Vec<ActorHave>);

impl Frontier {
    /// Build a frontier from entries in any order. Entries are sorted by
    /// Principal ID; any other non-canonical input is rejected.
    pub fn new(mut entries: Vec<ActorHave>) -> Result<Frontier, Error> {
        entries.sort_by(|a, b| a.principal.cmp_frontier_order(&b.principal));
        Frontier::check(&entries)?;
        Ok(Frontier(entries))
    }

    /// Decode and check a received frontier. Entry order is checked, not
    /// repaired.
    pub fn from_value(value: &Value) -> Result<Frontier, Error> {
        let entries = value
            .as_array()
            .ok_or(Error::FrontierMalformed)?
            .iter()
            .map(ActorHave::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Frontier::check(&entries)?;
        Ok(Frontier(entries))
    }

    fn check(entries: &[ActorHave]) -> Result<(), Error> {
        for entry in entries {
            entry.check_canonical()?;
        }
        for pair in entries.windows(2) {
            match pair[0].principal.cmp_frontier_order(&pair[1].principal) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(Error::FrontierNotCanonical(
                        FrontierRule::DuplicatePrincipal,
                    ))
                }
                std::cmp::Ordering::Greater => {
                    return Err(Error::FrontierNotCanonical(FrontierRule::EntriesUnsorted))
                }
            }
        }
        Ok(())
    }

    /// The entries, in canonical order.
    pub fn entries(&self) -> &[ActorHave] {
        &self.0
    }

    /// The canonical CBOR value; the empty frontier is the empty array.
    pub fn to_value(&self) -> Value {
        Value::Array(self.0.iter().map(ActorHave::to_value).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;

    fn have(principal: u8, contiguous: u64, extra: &[(u64, u64)]) -> ActorHave {
        ActorHave {
            principal: PrincipalId::from_bytes([principal; 32]),
            contiguous,
            extra: extra.to_vec(),
        }
    }

    fn rule(entries: Vec<ActorHave>) -> Result<Frontier, Error> {
        Frontier::new(entries)
    }

    #[test]
    fn canonical_frontier_round_trips_and_sorts() {
        let frontier = Frontier::new(vec![have(9, 1, &[]), have(2, 100, &[(105, 107)])]).unwrap();
        assert_eq!(
            frontier.entries()[0].principal,
            PrincipalId::from_bytes([2; 32])
        );
        let bytes = cbor::encode(&frontier.to_value()).unwrap();
        assert_eq!(
            Frontier::from_value(&cbor::decode_strict(&bytes).unwrap()),
            Ok(frontier)
        );
        assert_eq!(
            cbor::encode(&Frontier::new(vec![]).unwrap().to_value()).unwrap(),
            [0x80]
        );
    }

    #[test]
    fn range_rules() {
        use FrontierRule::*;
        let cases: [(&[(u64, u64)], FrontierRule); 7] = [
            (&[(107, 105)], RangeReversed),
            (&[(95, 107)], RangeNotAboveContiguous),
            (&[(100, 107)], RangeNotAboveContiguous),
            (&[(101, 107)], RangeNotAboveContiguous),
            (&[(110, 112), (105, 107)], RangesUnsorted),
            (&[(105, 107), (106, 110)], RangesOverlapping),
            (&[(105, 107), (108, 110)], RangesAdjacent),
        ];
        for (extra, expected) in cases {
            assert_eq!(
                rule(vec![have(1, 100, extra)]),
                Err(Error::FrontierNotCanonical(expected)),
                "{extra:?}"
            );
        }
        // Rule 5 (W3): contiguous + 2 is the lowest start.
        assert!(rule(vec![have(1, 100, &[(102, 103), (105, 105)])]).is_ok());
        assert_eq!(
            rule(vec![have(1, u64::MAX, &[(u64::MAX, u64::MAX)])]),
            Err(Error::FrontierNotCanonical(RangeNotAboveContiguous))
        );
    }

    #[test]
    fn entry_rules() {
        assert_eq!(
            rule(vec![have(1, 1, &[]), have(1, 2, &[])]),
            Err(Error::FrontierNotCanonical(
                FrontierRule::DuplicatePrincipal
            ))
        );
        let unsorted = Value::Array(vec![have(2, 1, &[]).to_value(), have(1, 1, &[]).to_value()]);
        assert_eq!(
            Frontier::from_value(&unsorted),
            Err(Error::FrontierNotCanonical(FrontierRule::EntriesUnsorted))
        );
        let empty_list = Value::Map(vec![
            (Value::Unsigned(0), Value::bytes(vec![1; 32])),
            (Value::Unsigned(1), Value::Unsigned(7)),
            (Value::Unsigned(2), Value::Array(vec![])),
        ]);
        assert_eq!(
            ActorHave::from_value(&empty_list),
            Err(Error::FrontierNotCanonical(FrontierRule::EmptyExtraList))
        );
        let missing = Value::Map(vec![(Value::Unsigned(0), Value::bytes(vec![1; 32]))]);
        assert_eq!(
            ActorHave::from_value(&missing),
            Err(Error::FrontierNotCanonical(FrontierRule::MissingKey))
        );
        let extra_key = Value::Map(vec![
            (Value::Unsigned(0), Value::bytes(vec![1; 32])),
            (Value::Unsigned(1), Value::Unsigned(7)),
            (Value::Unsigned(3), Value::Null),
        ]);
        assert_eq!(
            ActorHave::from_value(&extra_key),
            Err(Error::FrontierMalformed)
        );
    }
}
