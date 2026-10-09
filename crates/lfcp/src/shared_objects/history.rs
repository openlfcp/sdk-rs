//! Operation references (SHARED-OBJECTS-PROFILE-01 §11.4).
//!
//! An Automerge engine applies a change whose operations refer to
//! operations it should not: a predecessor on another key, an element of
//! another list, an object that is not one. The document then cannot write
//! its changes again (automerge 0.12 panics in `get_changes`, and the save
//! does not load), and some of these make the engine abort during the
//! apply. §11.4 decides them from the change's causal history H, its
//! dependencies and all their ancestors, so that every replica decides the
//! same, whatever else it holds:
//!
//! - R1: a change after its actor's first has the actor's previous change
//!   in H;
//! - R2: its start op is one more than the largest operation counter in H;
//! - R3: an operation writes into the root or an object a make operation
//!   of H (or earlier in the change) created; a map or table takes
//!   property keys, a list or text element keys;
//! - R4: an insertion goes into a list or text, after the head or an
//!   element of the same object, and has no predecessors;
//! - R5: any other operation on a list or text names an element of the
//!   same object;
//! - R6: a predecessor is an operation of H (or earlier in the change),
//!   not a deletion, on the same object and key, where an insertion's key
//!   is its own element;
//! - R7: a deletion has at least one predecessor;
//! - R8: an increment has at least one predecessor, and every one is a
//!   put of a counter value (mvp-0.2-baseline.5);
//! - R9: no operation is a mark (mvp-0.2-baseline.5);
//! - R10: no operation makes a table (mvp-0.2-baseline.5; automerge 0.12
//!   aborts applying a write into one, finding D1).
//!
//! [`History`] keeps what these need: each change's vector clock and
//! largest counter, and the object, key and kind of each operation.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use automerge::{ActorId, AutoCommit, Change, ChangeHash};

use crate::shared_objects::canonical::{self, Content, Key};
use crate::shared_objects::{Diagnostic, ProfileError};

const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

/// An operation ID with the actor interned: (actor, counter).
type Id = (u32, u32);

/// The key an operation writes: a property, or an element (an insertion's
/// own ID).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slot {
    Prop(Box<str>),
    Elem(Id),
}

/// What an operation is, for the operations that refer to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// It creates an object of this type (the action: 0 map, 2 list, 4
    /// text, 6 table).
    Make(u64),
    /// A put of a counter value (action 1, value type 8): what an
    /// increment names (R8).
    CounterPut,
    /// Anything else, except a deletion (deletions are not kept).
    Other,
}

#[derive(Clone, Debug)]
struct Target {
    /// The sequence number of the change that holds it.
    seq: u64,
    /// The object it writes into; `None` is the root.
    obj: Option<Id>,
    slot: Slot,
    kind: Kind,
    /// Whether it inserts a sequence element (a make operation may too).
    insert: bool,
}

#[derive(Clone, Debug)]
struct Entry {
    /// The latest sequence number of each actor in the change's history,
    /// the change included.
    clock: Vec<u64>,
    /// The largest operation counter in that history.
    top: u64,
}

/// What admitting one change adds to a [`History`].
#[derive(Clone, Debug, Default)]
pub(crate) struct Additions {
    entries: Vec<(ChangeHash, Entry)>,
    ops: Vec<(Id, Target)>,
}

/// The §11.4 index of a document's history, and of the changes admitted
/// before a change in a batch ([`History::overlay`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct History {
    actors: Vec<ActorId>,
    index: HashMap<ActorId, u32>,
    entries: HashMap<ChangeHash, Entry>,
    ops: HashMap<Id, Target>,
}

/// Changes admitted earlier in a batch, read on top of a [`History`]. Its
/// actor indices are the history's.
#[derive(Debug, Default)]
pub(crate) struct Overlay {
    entries: HashMap<ChangeHash, Entry>,
    ops: HashMap<Id, Target>,
}

impl Overlay {
    pub(crate) fn add(&mut self, a: &Additions) {
        self.entries.extend(a.entries.iter().cloned());
        self.ops.extend(a.ops.iter().cloned());
    }
}

/// The §11.3 or §11.4 rule a change breaks: "C" (canonical encoding) or
/// "R1" to "R10".
pub type Rule = &'static str;

fn require(ok: bool, rule: Rule) -> Result<(), Rule> {
    if ok {
        Ok(())
    } else {
        Err(rule)
    }
}

impl History {
    fn intern(&mut self, actor: &[u8]) -> u32 {
        let id = ActorId::from(actor);
        if let Some(&i) = self.index.get(&id) {
            return i;
        }
        let i = self.actors.len() as u32;
        self.actors.push(id.clone());
        self.index.insert(id, i);
        i
    }

    pub(crate) fn add(&mut self, a: Additions) {
        self.entries.extend(a.entries);
        self.ops.extend(a.ops);
    }

    /// §11.4: check the change `hash` with content `c` (already canonical,
    /// §11.3) against its causal history, counting the changes of
    /// `overlay` as present. Every dependency must be present. Returns
    /// what admitting it adds.
    pub(crate) fn check(
        &mut self,
        hash: ChangeHash,
        deps: &[ChangeHash],
        c: &Content,
        overlay: &Overlay,
    ) -> Result<Additions, Rule> {
        let own = self.intern(&c.actor);
        let mut locals = vec![own];
        for o in &c.others {
            locals.push(self.intern(o));
        }
        let entry = |h: &ChangeHash| overlay.entries.get(h).or_else(|| self.entries.get(h));
        let mut clock: Vec<u64> = Vec::new();
        let mut top = 0u64;
        for d in deps {
            let e = entry(d).ok_or("R1")?;
            if clock.len() < e.clock.len() {
                clock.resize(e.clock.len(), 0);
            }
            for (i, s) in e.clock.iter().enumerate() {
                clock[i] = clock[i].max(*s);
            }
            top = top.max(e.top);
        }
        let seen = |actor: u32| clock.get(actor as usize).copied().unwrap_or(0);
        // R1, R2.
        require(seen(own) + 1 == c.seq, "R1")?;
        require(c.start_op == top + 1, "R2")?;

        let global = |(a, ctr): canonical::LocalId| -> Id { (locals[a as usize], ctr as u32) };
        let mut mine: HashMap<u32, Target> = HashMap::new();
        let lookup = |id: Id, mine: &HashMap<u32, Target>| -> Option<Target> {
            if id.0 == own {
                if let Some(t) = mine.get(&id.1) {
                    return Some(t.clone());
                }
            }
            let t = overlay.ops.get(&id).or_else(|| self.ops.get(&id))?;
            (t.seq <= seen(id.0)).then(|| t.clone())
        };
        let mut out = Additions::default();
        for (i, op) in c.ops.iter().enumerate() {
            let me: Id = (own, (c.start_op + i as u64) as u32);
            // R3: the object and the keys it takes.
            let (obj, sequence) = match op.obj {
                None => (None, false),
                Some(local) => {
                    let id = global(local);
                    match lookup(id, &mine).map(|t| t.kind) {
                        Some(Kind::Make(0 | 6)) => (Some(id), false),
                        Some(Kind::Make(2 | 4)) => (Some(id), true),
                        _ => return Err("R3"),
                    }
                }
            };
            let element = |local: canonical::LocalId, mine: &HashMap<u32, Target>| {
                let id = global(local);
                match lookup(id, mine) {
                    Some(t) if t.insert && t.obj == obj => Ok(id),
                    _ => Err(if op.insert { "R4" } else { "R5" }),
                }
            };
            let slot = match (&op.key, sequence, op.insert) {
                (Key::Prop(p), false, false) => Slot::Prop(p.as_str().into()),
                // R4.
                (Key::Head, true, true) => Slot::Elem(me),
                (Key::Elem(e), true, true) => {
                    element(*e, &mine)?;
                    Slot::Elem(me)
                }
                // R5.
                (Key::Elem(e), true, false) => Slot::Elem(element(*e, &mine)?),
                (_, false, true) => return Err("R4"),
                (Key::Head, true, false) => return Err("R5"),
                _ => return Err("R3"),
            };
            require(!op.insert || op.preds.is_empty(), "R4")?;
            // R6.
            for p in &op.preds {
                let t = lookup(global(*p), &mine).ok_or("R6")?;
                require(t.obj == obj && t.slot == slot, "R6")?;
            }
            // R7.
            const DELETE: u64 = 3;
            require(op.action != DELETE || !op.preds.is_empty(), "R7")?;
            // R8: an increment names the puts of a counter value it adds to
            // (on the same object and key, by R6): one, or one per counter
            // set concurrently.
            const PUT: u64 = 1;
            const INCREMENT: u64 = 5;
            const MARK: u64 = 7;
            const COUNTER: u8 = 8;
            if op.action == INCREMENT {
                let counters = !op.preds.is_empty()
                    && op.preds.iter().all(|p| {
                        lookup(global(*p), &mine).is_some_and(|t| t.kind == Kind::CounterPut)
                    });
                require(counters, "R8")?;
            }
            // R9.
            require(op.action != MARK, "R9")?;
            // R10.
            const MAKE_TABLE: u64 = 6;
            require(op.action != MAKE_TABLE, "R10")?;
            if op.action != DELETE {
                let kind = match op.action {
                    a @ (0 | 2 | 4 | 6) => Kind::Make(a),
                    PUT if op.value.0 == COUNTER => Kind::CounterPut,
                    _ => Kind::Other,
                };
                let target = Target {
                    seq: c.seq,
                    obj,
                    slot,
                    kind,
                    insert: op.insert,
                };
                mine.insert(me.1, target.clone());
                out.ops.push((me, target));
            }
        }
        if clock.len() <= own as usize {
            clock.resize(own as usize + 1, 0);
        }
        clock[own as usize] = c.seq;
        out.entries.push((
            hash,
            Entry {
                clock,
                top: c.start_op - 1 + c.ops.len() as u64,
            },
        ));
        Ok(out)
    }

    /// Check `change` (§11.3, §11.4) with `overlay` counted as present.
    pub(crate) fn check_change(
        &mut self,
        change: &Change,
        overlay: &Overlay,
    ) -> Result<Additions, ProfileError> {
        self.rule_of(change, overlay).map_err(|_| INVALID)
    }

    /// [`History::check_change`], naming the rule a refused change breaks.
    pub(crate) fn rule_of(
        &mut self,
        change: &Change,
        overlay: &Overlay,
    ) -> Result<Additions, Rule> {
        let content = canonical::check(change.raw_bytes()).map_err(|_| "C")?;
        self.check(change.hash(), change.deps(), &content, overlay)
    }

    /// The history of `doc`, every change checked in causal order. A
    /// document holding a change §11.3 or §11.4 refuses is
    /// `INVALID_AUTOMERGE_BYTES`, and so is one the engine cannot write
    /// back out.
    pub(crate) fn of(doc: &mut AutoCommit) -> Result<History, ProfileError> {
        let changes =
            catch_unwind(AssertUnwindSafe(|| doc.get_changes(&[]))).map_err(|_| INVALID)?;
        let mut history = History::default();
        let none = Overlay::default();
        for change in &changes {
            let added = history.check_change(change, &none)?;
            history.add(added);
        }
        Ok(history)
    }
}
