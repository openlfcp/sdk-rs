//! Data Epochs and the strict previous-epoch cutoff (LFCP-WIRE-01 §11, §19,
//! §19.1, §26.3, §75, §88).
//!
//! | Data Unit | Outcome | § |
//! | --- | --- | --- |
//! | Control Head unknown, or epoch not known at it (a future one included) | reject: `MISSING_DEPENDENCY` ([`Error::UnknownControlHead`], [`Error::UnknownDataEpoch`]) | §26.3 (G-EP2) |
//! | current epoch | accept | §19.1 |
//! | closed epoch, sequence within the actor's final-frontier entry | accept | §19.1 |
//! | closed epoch, sequence beyond the actor's entry | quarantine: [`QuarantineReason::BeyondCutoff`] | §19.1 |
//! | closed epoch, actor absent from the final frontier | quarantine: [`QuarantineReason::ActorAbsent`] | §19.1 |
//!
//! The cutoff applied is the one the latest known Control state records
//! (§19.1, §26.3, G-EP1): once a Key Epoch is known, every closed-epoch unit
//! is held to it, whatever head the unit observed. A quarantined unit is
//! never merged automatically; a client keeps it and should surface it as
//! stale offline work, and a server answers `DATA_PUT` with
//! `NACK(STALE_DATA_EPOCH)` (§19.1, §75, §88 step 7). Stale work an
//! application keeps is re-applied as a new unit of the current epoch
//! (§19.1, G-EP5); rebuilding a replica that had merged a unit now beyond
//! the cutoff (§19.1, G-EP7) is the replica's, not this module's.

use crate::base::{ControlRecordId, Error, QuarantineReason};
use crate::wire::control::authority::{state_at, ControlState};
use crate::wire::data_unit::DataUnitHeader;

/// What a receiver does with a validly signed Data Unit, by epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Eligible for merge, as far as epochs go.
    Accept,
    /// Held back by the strict cutoff: not merged automatically.
    Quarantine(QuarantineReason),
}

/// Classify `header` by its Data Epoch. `at_head` is the state at the
/// unit's referenced Control Head; `latest` is the newest known state.
pub fn classify_data_unit(
    at_head: &ControlState,
    latest: &ControlState,
    header: &DataUnitHeader,
) -> Result<Disposition, Error> {
    let epoch = header.data_epoch;
    if !at_head.dek_commitments.contains_key(&epoch) {
        return Err(Error::UnknownDataEpoch(epoch));
    }
    if epoch == latest.current_epoch {
        return Ok(Disposition::Accept);
    }
    let Some(frontier) = latest.closed_frontiers.get(&epoch) else {
        // Known at the unit's head but neither current nor closed in the
        // latest state: the latest state is older than the unit's head.
        return Err(Error::UnknownDataEpoch(epoch));
    };
    let entry = frontier
        .entries()
        .iter()
        .find(|entry| entry.principal == header.actor);
    Ok(match entry {
        None => Disposition::Quarantine(QuarantineReason::ActorAbsent),
        Some(entry) => {
            let seq = header.sequence;
            let held = seq <= entry.contiguous
                || entry
                    .extra
                    .iter()
                    .any(|&(start, end)| start <= seq && seq <= end);
            if held {
                Disposition::Accept
            } else {
                Disposition::Quarantine(QuarantineReason::BeyondCutoff)
            }
        }
    })
}

/// The states [`classify_data_unit`] needs, from a chain history: the state
/// at the unit's Control Head and the latest state.
fn states<'a>(
    history: &'a [ControlState],
    header: &DataUnitHeader,
) -> Result<(&'a ControlState, &'a ControlState), Error> {
    let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
    let at_head = state_at(history, &head).ok_or(Error::UnknownControlHead)?;
    let latest = history.last().ok_or(Error::UnknownControlHead)?;
    Ok((at_head, latest))
}

/// A server's epoch check for a unit in `DATA_PUT`: a closed-epoch unit
/// beyond the cutoff is `NACK(STALE_DATA_EPOCH)` (§19.1, §75).
pub fn server_accepts_data_put(
    history: &[ControlState],
    header: &DataUnitHeader,
) -> Result<(), Error> {
    let (at_head, latest) = states(history, header)?;
    match classify_data_unit(at_head, latest, header)? {
        Disposition::Accept => Ok(()),
        Disposition::Quarantine(reason) => Err(Error::StaleDataEpoch(reason)),
    }
}

/// A client's epoch check: [`Disposition`] for a unit, using the chain
/// history.
pub fn client_disposition(
    history: &[ControlState],
    header: &DataUnitHeader,
) -> Result<Disposition, Error> {
    let (at_head, latest) = states(history, header)?;
    classify_data_unit(at_head, latest, header)
}
