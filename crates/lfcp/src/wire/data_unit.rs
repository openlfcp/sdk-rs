//! Data Units: the encrypted, signed unit of replication (LFCP-WIRE-01
//! §26).
//!
//! ```text
//! payload = {0: resource-id, 1: data epoch, 2: actor, 3: actor sequence,
//!            4: previous unit id / null, 5: Control Head, 6: ciphertext}
//! aad     = ["LFCP-DATA-v1", resource-id, epoch, actor, sequence, previous, control head]
//! ```
//!
//! The ciphertext is ChaCha20-Poly1305 under the actor key (§12) with the
//! sequence nonce. The payload is signed by the actor (§26), and the Data
//! Unit ID is the object ID of the signed object.
//!
//! A unit goes through two steps on receipt. [`ReceivedDataUnit::parse`]
//! checks the structure, including sequence ≥ 1 (§8, N4).
//! [`ReceivedDataUnit::verify`] checks the signature against the actor and
//! yields a [`DataUnit`], which can then be opened with the epoch's DEK.
//!
//! Epoch validity, the epoch cutoff and `data/write` authorization
//! (§26.3 steps 2–5) need Control Plane state and are not checked here.

use crate::base::{DataUnitId, Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::crypto;
use crate::principal::{PrincipalDescriptor, PrincipalKeys};
use crate::wire::keys::{sequence_nonce, ActorKey, Dek};
use crate::wire::{
    bytes_field, check_closed_map, hash_field, principal_field, resource_field, uint_field,
};

const AAD_LABEL: &str = "LFCP-DATA-v1";

/// The authenticated fields of a Data Unit: payload fields 0 to 5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUnitHeader {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the Data Epoch whose DEK encrypts the unit.
    pub data_epoch: u64,
    /// Field 2: the writing Principal, which must sign the unit.
    pub actor: PrincipalId,
    /// Field 3: the actor sequence, starting at 1.
    pub sequence: u64,
    /// Field 4: the writer's latest own unit for the Resource that it
    /// still holds as accepted, `None` before its first (§26.2). Normally
    /// sequence − 1; after an abandoned sequence, or once a unit of its
    /// own is quarantined (stale, §19.1, or equivocating), an earlier one.
    /// [`DataUnit::seal`] takes it as given: the caller keeps the chain.
    pub previous: Option<DataUnitId>,
    /// Field 5: the Control Head the actor observed.
    pub control_head: Hash32,
}

impl DataUnitHeader {
    /// The deterministic AAD (§26.1).
    pub fn aad(&self) -> Vec<u8> {
        let previous = match &self.previous {
            Some(id) => Value::bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        let aad = Value::Array(vec![
            Value::text(AAD_LABEL),
            Value::bytes(self.resource_id.as_bytes().to_vec()),
            Value::Unsigned(self.data_epoch),
            Value::bytes(self.actor.as_bytes().to_vec()),
            Value::Unsigned(self.sequence),
            previous,
            Value::bytes(self.control_head.as_bytes().to_vec()),
        ]);
        cbor::encode(&aad).expect("the AAD array is always encodable")
    }

    fn payload(&self, ciphertext: Vec<u8>) -> Value {
        let previous = match &self.previous {
            Some(id) => Value::bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(self.resource_id.as_bytes().to_vec()),
            ),
            (Value::Unsigned(1), Value::Unsigned(self.data_epoch)),
            (
                Value::Unsigned(2),
                Value::bytes(self.actor.as_bytes().to_vec()),
            ),
            (Value::Unsigned(3), Value::Unsigned(self.sequence)),
            (Value::Unsigned(4), previous),
            (
                Value::Unsigned(5),
                Value::bytes(self.control_head.as_bytes().to_vec()),
            ),
            (Value::Unsigned(6), Value::Bytes(ciphertext)),
        ])
    }

    /// Decode payload fields 0 to 6 of a closed §26 map.
    fn from_payload(payload: &Value) -> Result<(DataUnitHeader, Vec<u8>), Error> {
        let err = Error::DataUnitMalformed;
        check_closed_map(payload, &[0, 1, 2, 3, 4, 5, 6], &[], err.clone())?;
        let previous = match payload.get_uint(4) {
            Some(Value::Null) => None,
            Some(Value::Bytes(bytes)) => {
                Some(DataUnitId::from_slice(bytes).map_err(|_| err.clone())?)
            }
            _ => return Err(err),
        };
        let header = DataUnitHeader {
            resource_id: resource_field(payload, 0, &err)?,
            data_epoch: uint_field(payload, 1, &err)?,
            actor: principal_field(payload, 2, &err)?,
            sequence: uint_field(payload, 3, &err)?,
            previous,
            control_head: hash_field(payload, 5, &err)?,
        };
        let ciphertext = bytes_field(payload, 6, &err)?.to_vec();
        if header.sequence == 0 {
            return Err(Error::DataUnitSequenceZero);
        }
        Ok((header, ciphertext))
    }

    fn actor_key(&self, dek: &Dek) -> ActorKey {
        ActorKey::derive(dek, &self.resource_id, self.data_epoch, &self.actor)
    }
}

/// A structurally valid Data Unit whose signature is not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedDataUnit {
    object: SignedObject,
    header: DataUnitHeader,
    ciphertext: Vec<u8>,
}

impl ReceivedDataUnit {
    /// Parse a Data Unit from its exact signed-object bytes: canonical
    /// COSE (§10), a closed §26 payload and sequence ≥ 1.
    pub fn parse(bytes: &[u8]) -> Result<ReceivedDataUnit, Error> {
        let object = cose::parse(bytes)?;
        let (header, ciphertext) = DataUnitHeader::from_payload(object.payload())?;
        Ok(ReceivedDataUnit {
            object,
            header,
            ciphertext,
        })
    }

    /// The payload header, unauthenticated until [`verify`](Self::verify).
    pub fn header(&self) -> &DataUnitHeader {
        &self.header
    }

    /// The Data Unit ID.
    pub fn id(&self) -> DataUnitId {
        DataUnitId::from_bytes(*self.object.id().as_bytes())
    }

    /// Verify that the actor signed the unit. `actor` must be the
    /// descriptor of the Principal in payload field 2; any other signer is
    /// [`Error::CoseKidMismatch`] (§10.5, §26).
    pub fn verify(self, actor: &PrincipalDescriptor) -> Result<DataUnit, Error> {
        self.verify_with(actor, |_| Ok(()))
    }

    /// [`verify`](Self::verify), then ask `authorize` whether the actor had
    /// `data/write` at the referenced Control Head (§26.3 steps 2–3).
    pub fn verify_with(
        self,
        actor: &PrincipalDescriptor,
        authorize: impl FnOnce(&DataUnitHeader) -> Result<(), Error>,
    ) -> Result<DataUnit, Error> {
        if actor.id() != &self.header.actor {
            return Err(Error::CoseKidMismatch);
        }
        cose::verify(&self.object, actor)?;
        authorize(&self.header)?;
        Ok(DataUnit {
            object: self.object,
            header: self.header,
            ciphertext: self.ciphertext,
        })
    }
}

/// A Data Unit whose signature by its actor has been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUnit {
    object: SignedObject,
    header: DataUnitHeader,
    ciphertext: Vec<u8>,
}

impl DataUnit {
    /// Encrypt `plaintext` and sign the unit as `signer`, which must be the
    /// header's actor.
    pub fn seal(
        header: DataUnitHeader,
        plaintext: &[u8],
        dek: &Dek,
        signer: &PrincipalKeys,
    ) -> Result<DataUnit, Error> {
        if signer.descriptor().id() != &header.actor {
            return Err(Error::CoseKidMismatch);
        }
        if header.sequence == 0 {
            return Err(Error::DataUnitSequenceZero);
        }
        let ciphertext = crypto::aead_seal(
            header.actor_key(dek).expose_secret(),
            &sequence_nonce(header.sequence),
            plaintext,
            &header.aad(),
        );
        let payload = cbor::encode(&header.payload(ciphertext.clone()))?;
        let object = cose::sign(&payload, signer)?;
        Ok(DataUnit {
            object,
            header,
            ciphertext,
        })
    }

    /// Decrypt the plaintext with the DEK of the unit's epoch. Failure is
    /// [`Error::AeadFailure`], which is client-local (§26.3, N3).
    pub fn open(&self, dek: &Dek) -> Result<Vec<u8>, Error> {
        crypto::aead_open(
            self.header.actor_key(dek).expose_secret(),
            &sequence_nonce(self.header.sequence),
            &self.ciphertext,
            &self.header.aad(),
        )
    }

    /// The Data Unit ID: SHA-256 of the exact signed-object bytes.
    pub fn id(&self) -> DataUnitId {
        DataUnitId::from_bytes(*self.object.id().as_bytes())
    }

    /// The verified header.
    pub fn header(&self) -> &DataUnitHeader {
        &self.header
    }

    /// Payload field 6: ciphertext followed by the Poly1305 tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The signed object, with its exact bytes.
    pub fn signed_object(&self) -> &SignedObject {
        &self.object
    }
}

/// The outcome of checking a unit's place in its actor's hash chain
/// (§26.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
    /// The unit links: its previous unit is the receiver's latest accepted
    /// unit of the actor, or `null` while the receiver has accepted none,
    /// even across a sequence gap (a hole, which never blocks).
    Linked,
    /// The unit does not link. It must be reported to the sync engine and
    /// held, not merged. This is a report, not a rejection.
    Report(ChainReport),
}

/// Why a unit does not link into its actor's hash chain (§26.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainReport {
    /// Sequence 1 with a non-null previous unit (§26.2: "For sequence 1,
    /// `previous` MUST be `null`").
    PreviousAtSequenceOne,
    /// The previous unit is `null` but the receiver has already accepted a
    /// unit of the actor.
    PreviousNullAfterAccepted,
    /// The previous unit is not the receiver's latest accepted unit of the
    /// actor: one it has not accepted (yet), or an older one. A unit of the
    /// first kind links once the named unit is accepted and is the latest.
    PreviousNotLatest,
}

/// Check `unit` against its actor's hash chain. `latest` is the receiver's
/// latest accepted unit for the same Resource and actor (the accepted unit
/// with the highest sequence), if it has accepted any.
///
/// The sequences between `latest` and `unit` do not matter: an abandoned
/// sequence leaves a hole, and the unit after it names the writer's last
/// published unit (§26.2, G-DP1-GAP).
pub fn check_chain(unit: &DataUnit, latest: Option<&DataUnit>) -> ChainStatus {
    check_link(
        unit.header(),
        latest.map(|before| (before.header(), before.id())),
    )
}

fn check_link(
    header: &DataUnitHeader,
    latest: Option<(&DataUnitHeader, DataUnitId)>,
) -> ChainStatus {
    match (header.previous, latest) {
        (Some(_), _) if header.sequence == 1 => {
            ChainStatus::Report(ChainReport::PreviousAtSequenceOne)
        }
        (None, None) => ChainStatus::Linked,
        (None, Some(_)) => ChainStatus::Report(ChainReport::PreviousNullAfterAccepted),
        (Some(previous), Some((before, id)))
            if previous == id
                && before.resource_id == header.resource_id
                && before.actor == header.actor
                && before.sequence < header.sequence =>
        {
            ChainStatus::Linked
        }
        (Some(_), _) => ChainStatus::Report(ChainReport::PreviousNotLatest),
    }
}

/// A receiver's view of one actor's chain in one Resource (§26.2): the
/// latest accepted unit and the units held until they link.
///
/// [`ActorChain::receive`] takes verified, authorized units in any order
/// and returns those that are accepted now, in chain order: the unit if it
/// links, followed by every held unit it releases. A unit that does not
/// link stays held; [`ActorChain::held`] lists them for the sync engine.
/// Equivocation (two units in one slot) is checked separately with
/// [`check_equivocation`]; this type does not resolve it.
#[derive(Clone, Debug, Default)]
pub struct ActorChain {
    latest: Option<(DataUnitHeader, DataUnitId)>,
    held: Vec<DataUnit>,
}

impl ActorChain {
    /// A chain with no accepted unit.
    pub fn new() -> ActorChain {
        ActorChain::default()
    }

    /// A chain whose latest accepted unit is `latest`: restored from a
    /// store, or the actor's latest unit a loaded Snapshot covers (the
    /// Snapshot attests to the units it covers, §29.3).
    pub fn from_latest(latest: &DataUnit) -> ActorChain {
        ActorChain {
            latest: Some((latest.header().clone(), latest.id())),
            held: Vec::new(),
        }
    }

    /// The sequence and ID of the latest accepted unit.
    pub fn latest(&self) -> Option<(u64, DataUnitId)> {
        self.latest
            .as_ref()
            .map(|(header, id)| (header.sequence, *id))
    }

    /// Where `unit` stands against the latest accepted unit.
    pub fn check(&self, unit: &DataUnit) -> ChainStatus {
        check_link(
            unit.header(),
            self.latest.as_ref().map(|(header, id)| (header, *id)),
        )
    }

    /// Receive `unit` and return the units accepted now, in chain order.
    /// A unit that is already held or accepted is ignored.
    pub fn receive(&mut self, unit: DataUnit) -> Vec<DataUnit> {
        let id = unit.id();
        if self
            .latest
            .as_ref()
            .is_some_and(|(_, latest)| *latest == id)
            || self.held.iter().any(|held| held.id() == id)
        {
            return Vec::new();
        }
        if self.check(&unit) != ChainStatus::Linked {
            self.held.push(unit);
            return Vec::new();
        }
        self.latest = Some((unit.header().clone(), unit.id()));
        let mut accepted = vec![unit];
        accepted.extend(self.release());
        accepted
    }

    /// Set the latest accepted unit back to `latest` (`None`: no unit)
    /// after the receiver stopped accepting later units, for example
    /// units a newly known Key Epoch Record places beyond the cutoff
    /// (§19.1, §29.3). The writer's next unit names its latest unit still
    /// accepted, so held units may link now: they are returned, in chain
    /// order, as for [`ActorChain::receive`].
    pub fn rewind(&mut self, latest: Option<&DataUnit>) -> Vec<DataUnit> {
        self.latest = latest.map(|unit| (unit.header().clone(), unit.id()));
        self.release()
    }

    /// Accept every held unit that links, in chain order.
    fn release(&mut self) -> Vec<DataUnit> {
        let mut accepted = Vec::new();
        while let Some(next) = self
            .held
            .iter()
            .position(|held| self.check(held) == ChainStatus::Linked)
        {
            let unit = self.held.remove(next);
            self.latest = Some((unit.header().clone(), unit.id()));
            accepted.push(unit);
        }
        accepted
    }

    /// The units held because they do not link (yet).
    pub fn held(&self) -> &[DataUnit] {
        &self.held
    }
}

/// Detect actor equivocation: two verified units with the same
/// `(resource, actor, sequence)` but different IDs (§26.2). The client must
/// not silently choose one.
pub fn check_equivocation(a: &DataUnit, b: &DataUnit) -> Result<(), Error> {
    let (x, y) = (a.header(), b.header());
    let same_slot =
        x.resource_id == y.resource_id && x.actor == y.actor && x.sequence == y.sequence;
    if same_slot && a.id() != b.id() {
        Err(Error::ActorEquivocation)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bob() -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
    }

    fn header(sequence: u64, previous: Option<DataUnitId>) -> DataUnitHeader {
        DataUnitHeader {
            resource_id: ResourceId::from_bytes([7; 32]),
            data_epoch: 0,
            actor: *bob().descriptor().id(),
            sequence,
            previous,
            control_head: Hash32::from_bytes([8; 32]),
        }
    }

    fn seal(sequence: u64, previous: Option<DataUnitId>, plaintext: &[u8]) -> DataUnit {
        DataUnit::seal(
            header(sequence, previous),
            plaintext,
            &Dek::from_bytes([3; 32]),
            &bob(),
        )
        .unwrap()
    }

    #[test]
    fn seal_parse_verify_open() {
        let unit = seal(1, None, b"hello");
        let received = ReceivedDataUnit::parse(unit.signed_object().bytes()).unwrap();
        assert_eq!(received.id(), unit.id());
        let verified = received.verify(bob().descriptor()).unwrap();
        assert_eq!(verified, unit);
        assert_eq!(verified.open(&Dek::from_bytes([3; 32])).unwrap(), b"hello");
        let err = verified.open(&Dek::from_bytes([4; 32])).unwrap_err();
        assert_eq!(err, Error::AeadFailure);
        assert_eq!(err.wire_code(), None);
    }

    #[test]
    fn verify_requires_the_actor() {
        let unit = seal(1, None, b"x");
        let carol = PrincipalKeys::from_secrets(&[5; 32], [6; 32]);
        let received = ReceivedDataUnit::parse(unit.signed_object().bytes()).unwrap();
        assert_eq!(
            received.verify(carol.descriptor()),
            Err(Error::CoseKidMismatch)
        );
        assert_eq!(
            DataUnit::seal(header(1, None), b"x", &Dek::from_bytes([3; 32]), &carol),
            Err(Error::CoseKidMismatch)
        );
    }

    #[test]
    fn sequence_zero_is_rejected() {
        assert_eq!(
            DataUnit::seal(header(0, None), b"x", &Dek::from_bytes([3; 32]), &bob()),
            Err(Error::DataUnitSequenceZero)
        );
    }

    #[test]
    fn payload_map_is_closed() {
        let unit = seal(1, None, b"x");
        let mut entries = unit.signed_object().payload().as_map().unwrap().to_vec();
        entries.push((Value::Unsigned(7), Value::Null));
        let payload = cbor::encode(&Value::Map(entries)).unwrap();
        let object = cose::sign(&payload, &bob()).unwrap();
        assert_eq!(
            ReceivedDataUnit::parse(object.bytes()),
            Err(Error::DataUnitMalformed)
        );
    }

    #[test]
    fn chain_links_and_reports() {
        let first = seal(1, None, b"1");
        let second = seal(2, Some(first.id()), b"2");
        let unlinked = seal(2, None, b"2");
        let wrong_start = seal(1, Some(first.id()), b"1");

        assert_eq!(check_chain(&first, None), ChainStatus::Linked);
        assert_eq!(check_chain(&second, Some(&first)), ChainStatus::Linked);
        assert_eq!(
            check_chain(&wrong_start, None),
            ChainStatus::Report(ChainReport::PreviousAtSequenceOne)
        );
        // The previous unit has not been accepted.
        assert_eq!(
            check_chain(&second, None),
            ChainStatus::Report(ChainReport::PreviousNotLatest)
        );
        assert_eq!(
            check_chain(&unlinked, Some(&first)),
            ChainStatus::Report(ChainReport::PreviousNullAfterAccepted)
        );
        // The latest accepted unit must come before the unit.
        assert_eq!(
            check_chain(&second, Some(&second)),
            ChainStatus::Report(ChainReport::PreviousNotLatest)
        );
    }

    #[test]
    fn a_unit_links_across_a_hole() {
        // Sequence 3 was reserved and abandoned: 4 names 2 (G-DP1-GAP).
        let first = seal(1, None, b"1");
        let second = seal(2, Some(first.id()), b"2");
        let fourth = seal(4, Some(second.id()), b"4");
        assert_eq!(check_chain(&fourth, Some(&second)), ChainStatus::Linked);
        // Naming 2 is not enough once a later unit is accepted.
        let third = seal(3, Some(second.id()), b"3");
        let other_fourth = seal(4, Some(second.id()), b"4'");
        assert_eq!(
            check_chain(&other_fourth, Some(&third)),
            ChainStatus::Report(ChainReport::PreviousNotLatest)
        );
        // A null previous after an accepted unit is held, at any sequence.
        assert_eq!(
            check_chain(&seal(1, None, b"1'"), Some(&first)),
            ChainStatus::Report(ChainReport::PreviousNullAfterAccepted)
        );
    }

    #[test]
    fn actor_chain_holds_and_releases() {
        let first = seal(1, None, b"1");
        let second = seal(2, Some(first.id()), b"2");
        let third = seal(3, Some(second.id()), b"3");
        let fourth = seal(4, Some(third.id()), b"4");
        let ids = |units: Vec<DataUnit>| units.iter().map(DataUnit::id).collect::<Vec<_>>();

        let mut chain = ActorChain::new();
        assert_eq!(ids(chain.receive(first.clone())), [first.id()]);
        // 4 before 3: 4 names 3, which is not accepted, so 4 is held.
        assert!(chain.receive(fourth.clone()).is_empty());
        assert!(chain.receive(third.clone()).is_empty());
        assert_eq!(ids(chain.held().to_vec()), [fourth.id(), third.id()]);
        // A held unit received again changes nothing.
        assert!(chain.receive(fourth.clone()).is_empty());
        assert_eq!(chain.held().len(), 2);
        // 2 links and releases 3, then 4.
        assert_eq!(
            ids(chain.receive(second.clone())),
            [second.id(), third.id(), fourth.id()]
        );
        assert!(chain.held().is_empty());
        assert_eq!(chain.latest(), Some((4, fourth.id())));
        // The latest unit received again changes nothing.
        assert!(chain.receive(fourth).is_empty());
        assert!(chain.held().is_empty());
    }

    #[test]
    fn actor_chain_keeps_the_held_cases_held() {
        let first = seal(1, None, b"1");
        let mut chain = ActorChain::new();
        // A non-null previous at sequence 1.
        assert!(chain.receive(seal(1, Some(first.id()), b"x")).is_empty());
        assert_eq!(chain.receive(first.clone()).len(), 1);
        // A null previous after an accepted unit.
        assert!(chain.receive(seal(3, None, b"y")).is_empty());
        // A previous the receiver never accepts.
        let unknown = seal(2, Some(first.id()), b"never received");
        assert!(chain.receive(seal(3, Some(unknown.id()), b"z")).is_empty());
        assert_eq!(chain.held().len(), 3);
        assert_eq!(chain.latest(), Some((1, first.id())));
    }

    #[test]
    fn actor_chain_rewinds_past_an_excluded_unit() {
        // The receiver accepted 3 before learning that a Key Epoch Record
        // places it beyond the cutoff. The writer quarantined 3 and links
        // 4 to 2: held until the receiver rebuilds without 3.
        let first = seal(1, None, b"1");
        let second = seal(2, Some(first.id()), b"2");
        let stale = seal(3, Some(second.id()), b"3");
        let fourth = seal(4, Some(second.id()), b"4");
        let mut chain = ActorChain::new();
        for unit in [&first, &second, &stale] {
            assert_eq!(chain.receive(unit.clone()).len(), 1);
        }
        assert!(chain.receive(fourth.clone()).is_empty());
        assert_eq!(
            chain.check(&fourth),
            ChainStatus::Report(ChainReport::PreviousNotLatest)
        );
        assert_eq!(chain.rewind(Some(&second)), std::slice::from_ref(&fourth));
        assert_eq!(chain.latest(), Some((4, fourth.id())));
        assert!(chain.held().is_empty());
        // Rewinding to no unit lets a new sequence 1 link.
        let mut chain = ActorChain::from_latest(&first);
        assert!(chain.receive(seal(1, None, b"again")).is_empty());
        assert_eq!(chain.rewind(None).len(), 1);
    }

    #[test]
    fn actor_chain_resumes_from_its_latest_unit() {
        // Restored from a store, or the latest unit a Snapshot covers.
        let first = seal(1, None, b"1");
        let second = seal(2, Some(first.id()), b"2");
        let fifth = seal(5, Some(second.id()), b"5");
        let mut chain = ActorChain::from_latest(&second);
        assert_eq!(chain.latest(), Some((2, second.id())));
        assert_eq!(chain.receive(fifth.clone()).len(), 1);
        assert_eq!(chain.latest(), Some((5, fifth.id())));
    }

    #[test]
    fn equivocation_needs_the_same_slot_and_different_ids() {
        let first = seal(1, None, b"1");
        let other_first = seal(1, None, b"other");
        let second = seal(2, Some(first.id()), b"2");
        assert_eq!(
            check_equivocation(&first, &other_first),
            Err(Error::ActorEquivocation)
        );
        assert_eq!(check_equivocation(&first, &first.clone()), Ok(()));
        assert_eq!(check_equivocation(&first, &second), Ok(()));
    }
}
