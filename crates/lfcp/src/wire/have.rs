//! Have Vectors and anti-entropy (LFCP-WIRE-01 §28, §44–§51, §66–§70).
//!
//! | Function | Purpose | § |
//! | --- | --- | --- |
//! | [`HaveVector::insert`] | record one held Data Unit | §28, §68 step 9 |
//! | [`HaveVector::from_wire`] | accept a live Have (normalizing it) | §28, §41, §48 |
//! | [`HaveVector::to_wire`] | emit a normalized live Have | §28, §48 |
//! | [`HaveVector::from_frontier`], [`HaveVector::to_frontier`] | canonical frontier, strict | §28.1, §28.2 |
//! | [`difference`] | ranges to request and to offer | §49, §68 |
//! | [`missing_after`] | catch-up after loading a Snapshot | §29, §66 step 4 |
//! | [`split_requests`] | at most 256 ranges per `DATA_GET` | §49 |
//! | [`control_sync`] | what to do about a peer's Control Heads | §42, §44, §45, §67 |
//!
//! A Have Vector is, per actor, the set of held sequences, kept as sorted,
//! disjoint, non-adjacent inclusive ranges. Every operation is a set
//! operation on those ranges, so merging, re-applying a sync or receiving
//! duplicates (§70) changes nothing.

use std::collections::BTreeMap;

use crate::base::{Error, PrincipalId};
use crate::wire::frontier::{ActorHave, Frontier};
use crate::wire::message::{ControlHead, DataRange, WireActorHave};

/// The most ranges one `DATA_GET` should carry (§49: "SHOULD contain no
/// more than 256 ranges").
pub const MAX_RANGES_PER_GET: usize = 256;

/// Inclusive sequence ranges, sorted, disjoint and non-adjacent, all ≥ 1.
type Ranges = Vec<(u64, u64)>;

/// Sort and merge ranges, joining overlapping and adjacent ones.
fn normalize(mut ranges: Ranges) -> Ranges {
    ranges.sort_unstable();
    let mut out: Ranges = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// The sequences in `a` that are not in `b`. Both are normalized.
fn subtract(a: &Ranges, b: &Ranges) -> Ranges {
    let mut out = Vec::new();
    let mut j = 0;
    for &(start, end) in a {
        let mut cursor = start;
        // Skip ranges of b that end before this range.
        while j < b.len() && b[j].1 < start {
            j += 1;
        }
        let mut k = j;
        while k < b.len() && b[k].0 <= end {
            let (b_start, b_end) = b[k];
            if b_start > cursor {
                out.push((cursor, b_start - 1));
            }
            if b_end >= end {
                cursor = end;
                // Nothing of this range is left.
                break;
            }
            cursor = b_end + 1;
            k += 1;
        }
        let covered = k < b.len() && b[k].0 <= end && b[k].1 >= end;
        if !covered && cursor <= end {
            out.push((cursor, end));
        }
    }
    out
}

/// What a replica holds, per actor (§28).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HaveVector {
    // Keyed by raw Principal ID bytes, which is also the §28.2 order.
    actors: BTreeMap<[u8; 32], Ranges>,
}

impl HaveVector {
    /// An empty Have Vector.
    pub fn new() -> HaveVector {
        HaveVector::default()
    }

    /// Record that the unit `(actor, sequence)` is held. Returns whether it
    /// was new. Sequence 0 does not exist (§8).
    pub fn insert(&mut self, actor: &PrincipalId, sequence: u64) -> Result<bool, Error> {
        if sequence == 0 {
            return Err(Error::DataUnitSequenceZero);
        }
        if self.contains(actor, sequence) {
            return Ok(false);
        }
        let ranges = self.actors.entry(*actor.as_bytes()).or_default();
        ranges.push((sequence, sequence));
        *ranges = normalize(std::mem::take(ranges));
        Ok(true)
    }

    /// Whether `(actor, sequence)` is held.
    pub fn contains(&self, actor: &PrincipalId, sequence: u64) -> bool {
        self.actors
            .get(actor.as_bytes())
            .is_some_and(|ranges| ranges.iter().any(|&(s, e)| s <= sequence && sequence <= e))
    }

    /// Add everything `other` holds.
    pub fn merge(&mut self, other: &HaveVector) {
        for (actor, ranges) in &other.actors {
            let mine = self.actors.entry(*actor).or_default();
            mine.extend_from_slice(ranges);
            *mine = normalize(std::mem::take(mine));
        }
    }

    /// Add the sequences of a range list, such as a `DATA_GET` answer.
    pub fn insert_ranges(&mut self, ranges: &[DataRange]) -> Result<(), Error> {
        for range in ranges {
            if range.start == 0 || range.start > range.end {
                return Err(Error::MessageMalformed);
            }
            let mine = self.actors.entry(*range.principal.as_bytes()).or_default();
            mine.push((range.start, range.end));
            *mine = normalize(std::mem::take(mine));
        }
        Ok(())
    }

    /// Accept a live Have Vector from `DATA_HAVE`, `RESOURCE_OPEN`,
    /// `RESOURCE_OPENED` or a snapshot summary.
    ///
    /// §48: live entries are not persistent objects, so §28.1 does not
    /// apply. Ranges may overlap, touch each other or touch `contiguous`,
    /// be unsorted, and one actor may appear more than once; all of it is
    /// normalized without losing a sequence. A range with start > end, or
    /// one that includes sequence 0, is `MALFORMED_MESSAGE`.
    pub fn from_wire(entries: &[WireActorHave]) -> Result<HaveVector, Error> {
        let mut vector = HaveVector::new();
        for entry in entries {
            let mut ranges = Vec::new();
            if entry.contiguous > 0 {
                ranges.push((1, entry.contiguous));
            }
            for &(start, end) in entry.extra.iter().flatten() {
                if start == 0 || start > end {
                    return Err(Error::MessageMalformed);
                }
                ranges.push((start, end));
            }
            let mine = vector
                .actors
                .entry(*entry.principal.as_bytes())
                .or_default();
            mine.extend(ranges);
            *mine = normalize(std::mem::take(mine));
        }
        vector.actors.retain(|_, ranges| !ranges.is_empty());
        Ok(vector)
    }

    /// The normalized live form: one entry per actor in raw Principal ID
    /// order, ranges touching `contiguous` absorbed into it, and key 2 only
    /// when extra ranges remain. Each entry is also canonical (§28.1).
    pub fn to_wire(&self) -> Vec<WireActorHave> {
        self.entries()
            .map(|have| WireActorHave {
                principal: have.principal,
                contiguous: have.contiguous,
                extra: (!have.extra.is_empty()).then_some(have.extra),
            })
            .collect()
    }

    /// Read a canonical frontier, as a persistent object carries it.
    pub fn from_frontier(frontier: &Frontier) -> HaveVector {
        let wire: Vec<WireActorHave> = frontier
            .entries()
            .iter()
            .map(|have| WireActorHave {
                principal: have.principal,
                contiguous: have.contiguous,
                extra: Some(have.extra.clone()),
            })
            .collect();
        HaveVector::from_wire(&wire).expect("a canonical frontier is a valid Have Vector")
    }

    /// The canonical frontier for a persistent object (§28.1, §28.2).
    pub fn to_frontier(&self) -> Frontier {
        Frontier::new(self.entries().collect()).expect("a normalized Have Vector is canonical")
    }

    fn entries(&self) -> impl Iterator<Item = ActorHave> + '_ {
        self.actors.iter().map(|(actor, ranges)| {
            let (contiguous, extra) = match ranges.first() {
                Some(&(1, end)) => (end, ranges[1..].to_vec()),
                _ => (0, ranges.clone()),
            };
            ActorHave {
                principal: PrincipalId::from_bytes(*actor),
                contiguous,
                extra,
            }
        })
    }

    /// The ranges `self` holds and `other` does not, in raw Principal ID
    /// order, each maximal.
    fn ranges_missing_from(&self, other: &HaveVector) -> Vec<DataRange> {
        let empty = Vec::new();
        let mut out = Vec::new();
        for (actor, ranges) in &self.actors {
            let theirs = other.actors.get(actor).unwrap_or(&empty);
            for (start, end) in subtract(ranges, theirs) {
                out.push(DataRange {
                    principal: PrincipalId::from_bytes(*actor),
                    start,
                    end,
                });
            }
        }
        out
    }
}

/// What two replicas should exchange (§68).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Difference {
    /// Ranges the peer holds and we do not: what to `DATA_GET`.
    pub request: Vec<DataRange>,
    /// Ranges we hold and the peer does not: what we could offer.
    pub offer: Vec<DataRange>,
}

/// The minimal ranges to request from and offer to a peer, given both Have
/// Vectors. Each range is maximal, so no shorter list covers the same
/// sequences.
pub fn difference(ours: &HaveVector, theirs: &HaveVector) -> Difference {
    Difference {
        request: theirs.ranges_missing_from(ours),
        offer: ours.ranges_missing_from(theirs),
    }
}

/// After loading a Snapshot, the ranges to fetch beyond its frontier
/// (§66 step 4): what the peer holds that neither the Snapshot frontier
/// nor our own holdings cover.
pub fn missing_after(
    frontier: &Frontier,
    ours: &HaveVector,
    theirs: &HaveVector,
) -> Vec<DataRange> {
    let mut covered = HaveVector::from_frontier(frontier);
    covered.merge(ours);
    theirs.ranges_missing_from(&covered)
}

/// Split ranges into `DATA_GET` requests of at most
/// [`MAX_RANGES_PER_GET`] ranges each.
pub fn split_requests(ranges: &[DataRange]) -> Vec<Vec<DataRange>> {
    ranges
        .chunks(MAX_RANGES_PER_GET)
        .map(<[DataRange]>::to_vec)
        .collect()
}

/// What to do about a peer's Control Heads (§42, §44, §67).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlSync {
    /// The peer is at our head: nothing to fetch.
    UpToDate,
    /// Fetch this inclusive Control Sequence interval with `CONTROL_GET`.
    /// The fetched records must still continue our chain; a record that
    /// does not is found by chain validation.
    Fetch {
        /// First sequence to request.
        start: u64,
        /// Last sequence to request.
        end: u64,
    },
    /// The peer is behind us; we could offer records with
    /// `CONTROL_BATCH` (§46).
    PeerBehind,
    /// The peer reports more than one head, or a different record at our
    /// own sequence: the Resource is forked. Surfaced, never resolved
    /// (§13.2, §42).
    Fork(Vec<ControlHead>),
}

/// Decide what to request given our head (`None` before Genesis is known)
/// and the heads a peer advertises in `CONTROL_HAVE` or
/// `RESOURCE_OPENED`.
/// An empty list means the peer has no Control Records for the Resource
/// (§44): up to date when we have none either, otherwise behind.
pub fn control_sync(ours: Option<ControlHead>, theirs: &[ControlHead]) -> ControlSync {
    match (ours, theirs) {
        (None, []) => ControlSync::UpToDate,
        (Some(_), []) => ControlSync::PeerBehind,
        (_, [_, _, ..]) => ControlSync::Fork(theirs.to_vec()),
        (None, [head]) => ControlSync::Fetch {
            start: 0,
            end: head.sequence,
        },
        (Some(ours), [head]) => {
            if head.sequence > ours.sequence {
                ControlSync::Fetch {
                    start: ours.sequence + 1,
                    end: head.sequence,
                }
            } else if head.sequence < ours.sequence {
                ControlSync::PeerBehind
            } else if head.id == ours.id {
                ControlSync::UpToDate
            } else {
                ControlSync::Fork(vec![ours, *head])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::ControlRecordId;

    fn p(n: u8) -> PrincipalId {
        PrincipalId::from_bytes([n; 32])
    }

    fn range(n: u8, start: u64, end: u64) -> DataRange {
        DataRange {
            principal: p(n),
            start,
            end,
        }
    }

    fn vector(holdings: &[(u8, &[u64])]) -> HaveVector {
        let mut v = HaveVector::new();
        for (actor, seqs) in holdings {
            for &seq in *seqs {
                v.insert(&p(*actor), seq).unwrap();
            }
        }
        v
    }

    #[test]
    fn subtract_cases() {
        assert_eq!(
            subtract(&vec![(1, 10)], &vec![(3, 4), (7, 7)]),
            vec![(1, 2), (5, 6), (8, 10)]
        );
        assert_eq!(subtract(&vec![(1, 10)], &vec![(1, 10)]), vec![]);
        assert_eq!(
            subtract(&vec![(1, 10)], &vec![(0, 3), (9, 20)]),
            vec![(4, 8)]
        );
        assert_eq!(
            subtract(&vec![(5, 6), (9, 9)], &vec![]),
            vec![(5, 6), (9, 9)]
        );
        assert_eq!(
            subtract(&vec![(1, u64::MAX)], &vec![(2, u64::MAX)]),
            vec![(1, 1)]
        );
    }

    #[test]
    fn section_68_example() {
        // Client: A 1..100, B 1..40. Server: A 1..104, B 1..40, C 1..8.
        let mut client = HaveVector::new();
        client
            .insert_ranges(&[range(1, 1, 100), range(2, 1, 40)])
            .unwrap();
        let mut server = client.clone();
        server
            .insert_ranges(&[range(1, 101, 104), range(3, 1, 8)])
            .unwrap();
        let diff = difference(&client, &server);
        assert_eq!(diff.request, vec![range(1, 101, 104), range(3, 1, 8)]);
        assert!(diff.offer.is_empty());
    }

    #[test]
    fn insert_reports_duplicates_and_rejects_zero() {
        let mut v = HaveVector::new();
        assert_eq!(v.insert(&p(1), 3), Ok(true));
        assert_eq!(v.insert(&p(1), 3), Ok(false));
        assert_eq!(v.insert(&p(1), 0), Err(Error::DataUnitSequenceZero));
    }

    #[test]
    fn live_haves_are_normalized_losslessly() {
        // Unsorted, overlapping, adjacent, touching contiguous, repeated actor.
        let wire = vec![
            WireActorHave {
                principal: p(1),
                contiguous: 3,
                extra: Some(vec![(9, 10), (4, 5), (5, 7), (12, 12)]),
            },
            WireActorHave {
                principal: p(1),
                contiguous: 0,
                extra: Some(vec![(11, 11)]),
            },
            WireActorHave {
                principal: p(2),
                contiguous: 0,
                extra: Some(vec![]),
            },
        ];
        let v = HaveVector::from_wire(&wire).unwrap();
        assert_eq!(
            v.to_wire(),
            vec![WireActorHave {
                principal: p(1),
                contiguous: 7,
                extra: Some(vec![(9, 12)]),
            }]
        );
        for bad in [(0, 2), (5, 4)] {
            let wire = vec![WireActorHave {
                principal: p(1),
                contiguous: 1,
                extra: Some(vec![bad]),
            }];
            assert_eq!(
                HaveVector::from_wire(&wire),
                Err(Error::MessageMalformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn missing_after_snapshot() {
        let snapshot = vector(&[(1, &[1, 2]), (2, &[1])]).to_frontier();
        let ours = vector(&[(1, &[3])]);
        let theirs = vector(&[(1, &[1, 2, 3, 4, 5]), (2, &[1, 2])]);
        assert_eq!(
            missing_after(&snapshot, &ours, &theirs),
            vec![range(1, 4, 5), range(2, 2, 2)]
        );
    }

    #[test]
    fn requests_split_at_256_ranges() {
        let ranges: Vec<DataRange> = (0..600).map(|i| range(1, 2 * i + 1, 2 * i + 1)).collect();
        let requests = split_requests(&ranges);
        assert_eq!(
            requests.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![256, 256, 88]
        );
    }

    #[test]
    fn control_sync_decisions() {
        let head = |sequence, n| ControlHead {
            sequence,
            id: ControlRecordId::from_bytes([n; 32]),
        };
        assert_eq!(
            control_sync(Some(head(10, 1)), &[head(14, 2)]),
            ControlSync::Fetch { start: 11, end: 14 }
        );
        assert_eq!(
            control_sync(None, &[head(6, 2)]),
            ControlSync::Fetch { start: 0, end: 6 }
        );
        assert_eq!(
            control_sync(Some(head(6, 2)), &[head(6, 2)]),
            ControlSync::UpToDate
        );
        assert_eq!(
            control_sync(Some(head(6, 2)), &[head(5, 3)]),
            ControlSync::PeerBehind
        );
        assert_eq!(control_sync(Some(head(6, 2)), &[]), ControlSync::PeerBehind);
        // §44 (G-HV2): an empty list means the peer has no records.
        assert_eq!(control_sync(None, &[]), ControlSync::UpToDate);
        assert_eq!(
            control_sync(Some(head(6, 2)), &[head(6, 3)]),
            ControlSync::Fork(vec![head(6, 2), head(6, 3)])
        );
        assert_eq!(
            control_sync(Some(head(5, 1)), &[head(6, 2), head(6, 3)]),
            ControlSync::Fork(vec![head(6, 2), head(6, 3)])
        );
    }
}
