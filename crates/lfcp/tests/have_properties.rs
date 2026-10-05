//! Property tests for Have Vectors, against a brute-force model: per actor,
//! the plain set of held sequences. A seeded SplitMix64 drives the cases,
//! and every failure names its seed.

use std::collections::{BTreeMap, BTreeSet};

use lfcp::base::PrincipalId;
use lfcp::wire::have::{difference, missing_after, HaveVector};
use lfcp::wire::message::{DataRange, WireActorHave};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

type Model = BTreeMap<u8, BTreeSet<u64>>;

const ACTORS: u8 = 4;
const MAX_SEQ: u64 = 60;
const CASES: u64 = 2000;

fn principal(actor: u8) -> PrincipalId {
    PrincipalId::from_bytes([actor; 32])
}

/// Random holdings: per actor, a dense prefix plus scattered sequences.
fn random_model(rng: &mut Rng) -> Model {
    let mut model = Model::new();
    for actor in 0..ACTORS {
        let prefix = rng.below(MAX_SEQ / 2);
        let mut seqs: BTreeSet<u64> = (1..=prefix).collect();
        for _ in 0..rng.below(12) {
            seqs.insert(1 + rng.below(MAX_SEQ));
        }
        if !seqs.is_empty() {
            model.insert(actor, seqs);
        }
    }
    model
}

fn build(model: &Model, rng: &mut Rng) -> HaveVector {
    // Insert in a random order, sometimes twice.
    let mut items: Vec<(u8, u64)> = model
        .iter()
        .flat_map(|(a, s)| s.iter().map(move |&q| (*a, q)))
        .collect();
    for i in (1..items.len()).rev() {
        items.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let mut v = HaveVector::new();
    for &(actor, seq) in &items {
        v.insert(&principal(actor), seq).unwrap();
        if rng.below(4) == 0 {
            assert!(
                !v.insert(&principal(actor), seq).unwrap(),
                "duplicate insert reported new"
            );
        }
    }
    v
}

/// The model of a Have Vector, read through its normalized wire form.
fn model_of(v: &HaveVector) -> Model {
    let mut model = Model::new();
    for entry in v.to_wire() {
        let actor = entry.principal.as_bytes()[0];
        let set = model.entry(actor).or_default();
        set.extend(1..=entry.contiguous);
        for (start, end) in entry.extra.unwrap_or_default() {
            set.extend(start..=end);
        }
    }
    model
}

fn model_of_ranges(ranges: &[DataRange]) -> Model {
    let mut model = Model::new();
    for r in ranges {
        model
            .entry(r.principal.as_bytes()[0])
            .or_default()
            .extend(r.start..=r.end);
    }
    model
}

fn minus(a: &Model, b: &Model) -> Model {
    let mut out = Model::new();
    for (actor, seqs) in a {
        let rest: BTreeSet<u64> = match b.get(actor) {
            Some(theirs) => seqs.difference(theirs).copied().collect(),
            None => seqs.clone(),
        };
        if !rest.is_empty() {
            out.insert(*actor, rest);
        }
    }
    out
}

fn union(a: &Model, b: &Model) -> Model {
    let mut out = a.clone();
    for (actor, seqs) in b {
        out.entry(*actor).or_default().extend(seqs);
    }
    out
}

/// Ranges are maximal and sorted: within one actor, each starts more than
/// one past the previous end.
fn assert_minimal(ranges: &[DataRange], seed: u64) {
    for pair in ranges.windows(2) {
        if pair[0].principal == pair[1].principal {
            assert!(
                pair[0].end + 1 < pair[1].start,
                "seed {seed}: ranges not maximal"
            );
        } else {
            assert!(
                pair[0]
                    .principal
                    .cmp_frontier_order(&pair[1].principal)
                    .is_lt(),
                "seed {seed}: actors out of order"
            );
        }
    }
}

#[test]
fn insert_matches_the_set_model() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let model = random_model(&mut rng);
        let v = build(&model, &mut rng);
        assert_eq!(model_of(&v), model, "seed {seed}");
        for (actor, seqs) in &model {
            for seq in 1..=MAX_SEQ {
                assert_eq!(
                    v.contains(&principal(*actor), seq),
                    seqs.contains(&seq),
                    "seed {seed}"
                );
            }
        }
    }
}

#[test]
fn difference_is_exact_and_minimal() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let (a, b) = (random_model(&mut rng), random_model(&mut rng));
        let (va, vb) = (build(&a, &mut rng), build(&b, &mut rng));
        let diff = difference(&va, &vb);
        assert_eq!(
            model_of_ranges(&diff.request),
            minus(&b, &a),
            "seed {seed}: request"
        );
        assert_eq!(
            model_of_ranges(&diff.offer),
            minus(&a, &b),
            "seed {seed}: offer"
        );
        assert_minimal(&diff.request, seed);
        assert_minimal(&diff.offer, seed);
    }
}

#[test]
fn exchanging_differences_converges_and_repeats_are_no_ops() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let (a, b) = (random_model(&mut rng), random_model(&mut rng));
        let (mut va, mut vb) = (build(&a, &mut rng), build(&b, &mut rng));

        // Each side fetches what it lacks; delivery may duplicate (§70).
        let diff = difference(&va, &vb);
        va.insert_ranges(&diff.request).unwrap();
        vb.insert_ranges(&diff.offer).unwrap();
        va.insert_ranges(&diff.request).unwrap();

        let all = union(&a, &b);
        assert_eq!(model_of(&va), all, "seed {seed}: A");
        assert_eq!(model_of(&vb), all, "seed {seed}: B");
        assert_eq!(va, vb, "seed {seed}: same representation");
        let again = difference(&va, &vb);
        assert!(
            again.request.is_empty() && again.offer.is_empty(),
            "seed {seed}: second round"
        );
    }
}

/// A random, non-normalized live Have for one model: overlapping, adjacent,
/// unsorted ranges, ranges touching contiguous, and repeated actors.
fn messy_wire(model: &Model, rng: &mut Rng) -> Vec<WireActorHave> {
    let mut entries = Vec::new();
    for (actor, seqs) in model {
        let seqs: Vec<u64> = seqs.iter().copied().collect();
        // Cover the set with random, possibly overlapping, runs.
        let mut i = 0;
        let mut runs = Vec::new();
        while i < seqs.len() {
            let mut j = i;
            while j + 1 < seqs.len() && seqs[j + 1] == seqs[j] + 1 && rng.below(5) != 0 {
                j += 1;
            }
            runs.push((seqs[i], seqs[j]));
            if rng.below(3) == 0 {
                runs.push((seqs[i], seqs[i])); // overlap
            }
            i = j + 1;
        }
        for k in (1..runs.len()).rev() {
            runs.swap(k, rng.below(k as u64 + 1) as usize);
        }
        // Split the runs over one to three entries for the same actor.
        let parts = 1 + rng.below(3) as usize;
        for part in 0..parts {
            let mine: Vec<(u64, u64)> = runs
                .iter()
                .enumerate()
                .filter(|(k, _)| k % parts == part)
                .map(|(_, r)| *r)
                .collect();
            // A contiguous prefix is only claimed when the set really has it.
            let contiguous = if part == 0 && seqs.first() == Some(&1) {
                let mut c = 0;
                while seqs.get(c as usize) == Some(&(c + 1)) && rng.below(4) != 0 {
                    c += 1;
                }
                c
            } else {
                0
            };
            entries.push(WireActorHave {
                principal: principal(*actor),
                contiguous,
                extra: (rng.below(2) == 0 || !mine.is_empty()).then_some(mine),
            });
        }
    }
    for k in (1..entries.len()).rev() {
        entries.swap(k, rng.below(k as u64 + 1) as usize);
    }
    entries
}

#[test]
fn live_normalization_is_lossless_and_idempotent() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let model = random_model(&mut rng);
        let wire = messy_wire(&model, &mut rng);
        let v = HaveVector::from_wire(&wire).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        assert_eq!(model_of(&v), model, "seed {seed}: lossless");

        // Our own output is normalized: canonical per entry, sorted, and
        // a fixed point of normalization.
        let normalized = v.to_wire();
        for entry in &normalized {
            entry
                .canonical()
                .unwrap_or_else(|e| panic!("seed {seed}: not canonical: {e}"));
        }
        assert_eq!(
            HaveVector::from_wire(&normalized).unwrap().to_wire(),
            normalized,
            "seed {seed}"
        );
    }
}

#[test]
fn frontier_round_trip_and_snapshot_catch_up() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let (snap, ours, theirs) = (
            random_model(&mut rng),
            random_model(&mut rng),
            random_model(&mut rng),
        );
        let vs = build(&snap, &mut rng);
        let frontier = vs.to_frontier();
        assert_eq!(
            HaveVector::from_frontier(&frontier),
            vs,
            "seed {seed}: frontier"
        );

        let (vo, vt) = (build(&ours, &mut rng), build(&theirs, &mut rng));
        let missing = missing_after(&frontier, &vo, &vt);
        assert_eq!(
            model_of_ranges(&missing),
            minus(&theirs, &union(&snap, &ours)),
            "seed {seed}: missing_after"
        );
    }
}
