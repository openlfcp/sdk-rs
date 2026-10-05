//! Key Packages: a Resource DEK delivered to one Principal with HPKE
//! (LFCP-WIRE-01 §25).
//!
//! | Value | Formula | § |
//! | --- | --- | --- |
//! | payload | `{0: resource-id, 1: data epoch, 2: recipient, 3: Control Head, 4: sender, 5: enc, 6: ciphertext}` | §25 |
//! | HPKE `info` | det-CBOR `["LFCP-KEY-v1", resource-id, epoch, recipient]` | §25.1 |
//! | HPKE AAD | det-CBOR `[resource-id, epoch, Control Head]` | §25.1 |
//! | HPKE plaintext | the 32-byte DEK | §25.1 |
//! | `enc`, ciphertext | HPKE Base `SealBase(pkR = recipient X25519 key, info, aad, DEK)`: 32 and 48 bytes, else `MALFORMED_MESSAGE` | §9, §25, §25.1 |
//! | ephemeral key | fresh per package; `DeriveKeyPair(ikmE)` from the random source | §25, RFC 9180 §7.1.3 |
//! | signer | the sender, field 4: `kid` = sender, else `INVALID_SIGNATURE` | §25, §10.5 |
//! | package ID | SHA-256 of the exact COSE_Sign1 bytes | §25, §10.6 |
//! | acceptance | a 32-byte plaintext matching `dek_commitment` of its epoch | §11, §25.2 |
//!
//! Every way a package can fail to deliver its key — it names another
//! recipient, HPKE does not open, or the DEK does not match the commitment —
//! is client-local: the package is ignored and should be surfaced, and there
//! is no wire code (§25.2, N5).
//!
//! The sender's `key/distribute` authority and the recipient's `data/read`
//! authority at the referenced Control Head (§25.2) need Control Plane
//! state. [`ReceivedKeyPackage::verify`] takes them as a caller hook.

use crate::base::{Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::crypto;
use crate::principal::{PrincipalDescriptor, PrincipalKeys};
use crate::wire::keys::{dek_commitment, Dek};
use crate::wire::{
    bytes_field, check_closed_map, hash_field, principal_field, resource_field, uint_field,
};

const INFO_LABEL: &str = "LFCP-KEY-v1";

/// Length of payload field 5, the HPKE `enc` (§25).
pub const ENC_BYTES: usize = 32;

/// Length of payload field 6, the HPKE ciphertext: the 32-byte DEK and the
/// 16-byte tag (§25).
pub const CIPHERTEXT_BYTES: usize = 48;

/// Payload fields 0 to 4 of a Key Package (§25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageHeader {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the Data Epoch of the delivered DEK.
    pub data_epoch: u64,
    /// Field 2: the recipient.
    pub recipient: PrincipalId,
    /// Field 3: the Control Head used for authorization.
    pub control_head: Hash32,
    /// Field 4: the sender, which must sign the package.
    pub sender: PrincipalId,
}

impl KeyPackageHeader {
    /// The deterministic HPKE `info` (§25.1).
    pub fn hpke_info(&self) -> Vec<u8> {
        let info = Value::Array(vec![
            Value::text(INFO_LABEL),
            Value::bytes(self.resource_id.as_bytes().to_vec()),
            Value::Unsigned(self.data_epoch),
            Value::bytes(self.recipient.as_bytes().to_vec()),
        ]);
        cbor::encode(&info).expect("the info array is always encodable")
    }

    /// The deterministic HPKE AAD (§25.1).
    pub fn hpke_aad(&self) -> Vec<u8> {
        let aad = Value::Array(vec![
            Value::bytes(self.resource_id.as_bytes().to_vec()),
            Value::Unsigned(self.data_epoch),
            Value::bytes(self.control_head.as_bytes().to_vec()),
        ]);
        cbor::encode(&aad).expect("the AAD array is always encodable")
    }

    fn payload(&self, enc: &[u8], ciphertext: &[u8]) -> Value {
        let id = |bytes: &[u8; 32]| Value::bytes(bytes.to_vec());
        Value::Map(vec![
            (Value::Unsigned(0), id(self.resource_id.as_bytes())),
            (Value::Unsigned(1), Value::Unsigned(self.data_epoch)),
            (Value::Unsigned(2), id(self.recipient.as_bytes())),
            (Value::Unsigned(3), id(self.control_head.as_bytes())),
            (Value::Unsigned(4), id(self.sender.as_bytes())),
            (Value::Unsigned(5), Value::bytes(enc.to_vec())),
            (Value::Unsigned(6), Value::bytes(ciphertext.to_vec())),
        ])
    }

    fn from_payload(payload: &Value) -> Result<(KeyPackageHeader, Vec<u8>, Vec<u8>), Error> {
        let err = Error::KeyPackageMalformed;
        check_closed_map(payload, &[0, 1, 2, 3, 4, 5, 6], &[], err.clone())?;
        let header = KeyPackageHeader {
            resource_id: resource_field(payload, 0, &err)?,
            data_epoch: uint_field(payload, 1, &err)?,
            recipient: principal_field(payload, 2, &err)?,
            control_head: hash_field(payload, 3, &err)?,
            sender: principal_field(payload, 4, &err)?,
        };
        // §25: enc is the 32-byte X25519 ephemeral key; the ciphertext is
        // the 32-byte DEK and the 16-byte tag.
        let enc = bytes_field(payload, 5, &err)?.to_vec();
        let ciphertext = bytes_field(payload, 6, &err)?.to_vec();
        if enc.len() != ENC_BYTES || ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(err);
        }
        Ok((header, enc, ciphertext))
    }
}

/// A structurally valid Key Package whose signature is not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedKeyPackage {
    object: SignedObject,
    header: KeyPackageHeader,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl ReceivedKeyPackage {
    /// Parse a Key Package from its exact signed-object bytes: canonical
    /// COSE (§10) and a closed §25 payload.
    pub fn parse(bytes: &[u8]) -> Result<ReceivedKeyPackage, Error> {
        let object = cose::parse(bytes)?;
        let (header, enc, ciphertext) = KeyPackageHeader::from_payload(object.payload())?;
        Ok(ReceivedKeyPackage {
            object,
            header,
            enc,
            ciphertext,
        })
    }

    /// The payload header, unauthenticated until [`verify`](Self::verify).
    pub fn header(&self) -> &KeyPackageHeader {
        &self.header
    }

    /// Verify that the sender in payload field 4 signed the package, then
    /// ask `authorize` whether the sender and recipient had the §25.2
    /// authority at the referenced Control Head.
    ///
    /// §25: the `kid` must be the sender; any other signer is
    /// [`Error::CoseKidMismatch`] (`INVALID_SIGNATURE`).
    pub fn verify(
        self,
        sender: &PrincipalDescriptor,
        authorize: impl FnOnce(&KeyPackageHeader) -> Result<(), Error>,
    ) -> Result<KeyPackage, Error> {
        if sender.id() != &self.header.sender {
            return Err(Error::CoseKidMismatch);
        }
        cose::verify(&self.object, sender)?;
        authorize(&self.header)?;
        Ok(KeyPackage {
            object: self.object,
            header: self.header,
            enc: self.enc,
            ciphertext: self.ciphertext,
        })
    }
}

/// A Key Package whose signature by its sender has been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackage {
    object: SignedObject,
    header: KeyPackageHeader,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl KeyPackage {
    /// Deliver `dek`, the DEK of `data_epoch`, to `recipient`, sealed with
    /// a fresh HPKE ephemeral key from the operating system's RNG and
    /// signed by `sender`.
    pub fn seal(
        resource_id: ResourceId,
        data_epoch: u64,
        control_head: Hash32,
        dek: &Dek,
        recipient: &PrincipalDescriptor,
        sender: &PrincipalKeys,
    ) -> Result<KeyPackage, Error> {
        Self::seal_inner(
            resource_id,
            data_epoch,
            control_head,
            dek,
            recipient,
            sender,
            crypto::hpke_seal,
        )
    }

    /// [`KeyPackage::seal`] with the ephemeral key drawn from `rng` (see
    /// [`crypto::hpke_seal_with_rng`]): a fixed source yielding a
    /// published `ikmE` reproduces that vector byte for byte (G-KP2). Only
    /// a cryptographically secure source is safe outside tests.
    pub fn seal_with_rng(
        resource_id: ResourceId,
        data_epoch: u64,
        control_head: Hash32,
        dek: &Dek,
        recipient: &PrincipalDescriptor,
        sender: &PrincipalKeys,
        rng: &mut impl hpke::rand_core::CryptoRng,
    ) -> Result<KeyPackage, Error> {
        Self::seal_inner(
            resource_id,
            data_epoch,
            control_head,
            dek,
            recipient,
            sender,
            |pk, info, aad, pt| crypto::hpke_seal_with_rng(pk, info, aad, pt, rng),
        )
    }

    fn seal_inner(
        resource_id: ResourceId,
        data_epoch: u64,
        control_head: Hash32,
        dek: &Dek,
        recipient: &PrincipalDescriptor,
        sender: &PrincipalKeys,
        seal: impl FnOnce(&[u8; 32], &[u8], &[u8], &[u8]) -> Result<([u8; 32], Vec<u8>), Error>,
    ) -> Result<KeyPackage, Error> {
        let header = KeyPackageHeader {
            resource_id,
            data_epoch,
            recipient: *recipient.id(),
            control_head,
            sender: *sender.descriptor().id(),
        };
        let (enc, ciphertext) = seal(
            recipient.x25519_public(),
            &header.hpke_info(),
            &header.hpke_aad(),
            dek.expose_secret(),
        )?;
        let payload = cbor::encode(&header.payload(&enc, &ciphertext))?;
        let object = cose::sign(&payload, sender)?;
        Ok(KeyPackage {
            object,
            header,
            enc: enc.to_vec(),
            ciphertext,
        })
    }

    /// Open the package as `recipient` and check the DEK against
    /// `expected_commitment`, the commitment the Control Plane records for
    /// the package's epoch. Every failure is client-local (§25.2, N5).
    pub fn open(
        &self,
        recipient: &PrincipalKeys,
        expected_commitment: &Hash32,
    ) -> Result<Dek, Error> {
        if recipient.descriptor().id() != &self.header.recipient {
            return Err(Error::KeyPackageRecipientMismatch);
        }
        let plaintext = crypto::hpke_open(
            recipient.agreement_key(),
            &self.enc,
            &self.header.hpke_info(),
            &self.header.hpke_aad(),
            &self.ciphertext,
        )?;
        // §25.1: the plaintext is exactly the 32-byte DEK; §25.2: any other
        // length does not match the commitment.
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::DekCommitmentMismatch)?;
        let dek = Dek::from_bytes(bytes);
        let commitment = dek_commitment(&self.header.resource_id, self.header.data_epoch, &dek);
        if &commitment != expected_commitment {
            return Err(Error::DekCommitmentMismatch);
        }
        Ok(dek)
    }

    /// The package ID: SHA-256 of the exact signed-object bytes.
    pub fn id(&self) -> &Hash32 {
        self.object.id()
    }

    /// The verified header.
    pub fn header(&self) -> &KeyPackageHeader {
        &self.header
    }

    /// Payload field 5: the HPKE encapsulated key.
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    /// Payload field 6: the HPKE ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The signed object, with its exact bytes.
    pub fn signed_object(&self) -> &SignedObject {
        &self.object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[n; 32], [n.wrapping_add(50); 32])
    }

    const RESOURCE: ResourceId = ResourceId::from_bytes([7; 32]);
    const HEAD: Hash32 = Hash32::from_bytes([8; 32]);

    fn sealed(dek: &Dek) -> KeyPackage {
        KeyPackage::seal(RESOURCE, 3, HEAD, dek, keys(2).descriptor(), &keys(1)).unwrap()
    }

    #[test]
    fn seal_parse_verify_open() {
        let dek = Dek::from_bytes([9; 32]);
        let commitment = dek_commitment(&RESOURCE, 3, &dek);
        let package = sealed(&dek);
        let received = ReceivedKeyPackage::parse(package.signed_object().bytes()).unwrap();
        let verified = received.verify(keys(1).descriptor(), |_| Ok(())).unwrap();
        assert_eq!(verified, package);
        let opened = verified.open(&keys(2), &commitment).unwrap();
        assert_eq!(opened.expose_secret(), dek.expose_secret());
    }

    #[test]
    fn fresh_ephemeral_keys_give_different_packages() {
        let dek = Dek::from_bytes([9; 32]);
        assert_ne!(sealed(&dek).enc(), sealed(&dek).enc());
    }

    #[test]
    fn delivery_failures_are_client_local() {
        let dek = Dek::from_bytes([9; 32]);
        let commitment = dek_commitment(&RESOURCE, 3, &dek);
        let package = sealed(&dek);
        let wrong_commitment = dek_commitment(&RESOURCE, 4, &dek);
        for (label, err) in [
            (
                "not the recipient",
                package.open(&keys(3), &commitment).unwrap_err(),
            ),
            (
                "wrong commitment",
                package.open(&keys(2), &wrong_commitment).unwrap_err(),
            ),
        ] {
            assert!(err.is_client_local(), "{label}: {err:?}");
            assert_eq!(err.wire_code(), None, "{label}");
        }
    }

    #[test]
    fn signer_must_be_the_sender_and_authorize_is_consulted() {
        let package = sealed(&Dek::from_bytes([9; 32]));
        let received = ReceivedKeyPackage::parse(package.signed_object().bytes()).unwrap();
        assert_eq!(
            received.clone().verify(keys(2).descriptor(), |_| Ok(())),
            Err(Error::CoseKidMismatch)
        );
        assert_eq!(
            received.verify(keys(1).descriptor(), |_| Err(Error::KeyPackageMalformed)),
            Err(Error::KeyPackageMalformed)
        );
    }

    #[test]
    fn enc_and_ciphertext_sizes_are_fixed() {
        // §25 (G-KP3): enc is 32 bytes and the ciphertext 48, else the
        // payload is MALFORMED_MESSAGE.
        let package = sealed(&Dek::from_bytes([9; 32]));
        assert_eq!((package.enc().len(), package.ciphertext().len()), (32, 48));
        let header = package.header().clone();
        for (enc, ciphertext) in [
            (vec![1; 31], vec![2; 48]),
            (vec![1; 33], vec![2; 48]),
            (vec![1; 32], vec![2; 47]),
            (vec![1; 32], vec![2; 64]),
        ] {
            let payload = cbor::encode(&header.payload(&enc, &ciphertext)).unwrap();
            let object = cose::sign(&payload, &keys(1)).unwrap();
            let err = ReceivedKeyPackage::parse(object.bytes()).unwrap_err();
            assert_eq!(
                err,
                Error::KeyPackageMalformed,
                "{} {}",
                enc.len(),
                ciphertext.len()
            );
            assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
        }
    }

    #[test]
    fn info_and_aad_layouts() {
        let header = sealed(&Dek::from_bytes([9; 32])).header().clone();
        let info = cbor::decode_strict(&header.hpke_info()).unwrap();
        let info = info.as_array().unwrap();
        assert_eq!(info.len(), 4);
        assert_eq!(info[0], Value::text("LFCP-KEY-v1"));
        assert_eq!(info[3], Value::bytes(header.recipient.as_bytes().to_vec()));
        let aad = cbor::decode_strict(&header.hpke_aad()).unwrap();
        assert_eq!(
            aad,
            Value::Array(vec![
                Value::bytes(RESOURCE.as_bytes().to_vec()),
                Value::Unsigned(3),
                Value::bytes(HEAD.as_bytes().to_vec()),
            ])
        );
    }
}
