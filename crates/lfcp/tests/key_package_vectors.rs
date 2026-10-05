//! LFCP-TEST-VECTORS-01 cases for HPKE Key Packages: KP0, KPI, KPC,
//! hpke_recipient_mismatch_KP0 and kp_enc_wrong_size_KP0.
//!
//! The vectors publish the HPKE ephemeral input keying material `ikmE`;
//! the ephemeral key is `DeriveKeyPair(ikmE)` (RFC 9180 §7.1.3, G-KP2).
//! A random source that yields `ikmE` therefore reproduces every package
//! byte for byte through [`KeyPackage::seal_with_rng`], the `hpke` crate's
//! deterministic path. The HPKE intermediates are checked with the same
//! crate: the ephemeral key pair and the KEM shared secret directly, the
//! AEAD key and base nonce by opening the ciphertext under exactly those
//! values. Every expected field is checked; the guard test enforces it.
//! Every assertion names its case.

mod support;

use std::collections::BTreeMap;

use hpke::danger::streaming_enc::{create_receiver_context, AeadKey, AeadNonce, ExporterSecret};
use hpke::{Deserializable as _, Kem as _, Serializable as _};
use lfcp::base::{Error, Hash32};
use lfcp::cose;
use lfcp::crypto::{self, X25519PrivateKey};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::{key_package_policy, validate_authorized};
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::ReceivedControlRecord;
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::Dek;
use support::vectors::{hex, hex32, principal_by_id, Suite};

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

const PACKAGES: [&str; 3] = ["KP0_bob_epoch0", "KPI_invite_epoch0", "KPC_carol_epoch1"];

/// Every expected field of a package case; each is compared byte for byte.
const CHECKED: &[&str] = &[
    "hpke_ephemeral_private",
    "hpke_info_cbor",
    "hpke_aad_cbor",
    "hpke_enc",
    "hpke_shared_secret",
    "hpke_key",
    "hpke_base_nonce",
    "hpke_ciphertext",
    "payload_cbor",
    "cose_sign1",
    "package_id",
];

/// A random source that yields fixed bytes: the vector's `ikmE`.
struct FixedRng(Vec<u8>);

impl hpke::rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!("HPKE only fills bytes")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!("HPKE only fills bytes")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let bytes: Vec<u8> = self.0.drain(..dst.len()).collect();
        dst.copy_from_slice(&bytes);
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for FixedRng {}

/// The DEK commitment the Control Plane records for each epoch: Genesis
/// (C0) for epoch 0, the Key Epoch record (C6) for epoch 1.
fn recorded_commitments(suite: &Suite) -> BTreeMap<u64, Hash32> {
    let record = |case: &str| {
        ReceivedControlRecord::parse(&hex(case, &suite.case(case)["expected"]["cose_sign1"]))
            .unwrap()
    };
    let mut commitments = BTreeMap::new();
    match record("C0_genesis").body() {
        ControlBody::Genesis(genesis) => commitments.insert(0, genesis.dek_commitment),
        _ => panic!("C0_genesis: not Genesis"),
    };
    match record("C6_key_epoch_1").body() {
        ControlBody::KeyEpoch(epoch) => commitments.insert(epoch.epoch, epoch.dek_commitment),
        _ => panic!("C6_key_epoch_1: not a Key Epoch"),
    };
    commitments
}

fn fixture_dek(suite: &Suite, epoch: u64) -> Vec<u8> {
    hex(
        "fixtures",
        &suite.json["fixtures"]["resource"][format!("dek{epoch}")],
    )
}

#[test]
fn every_package_field_is_checked() {
    let suite = Suite::load();
    for case_id in PACKAGES {
        for name in suite.case(case_id)["expected"].as_object().unwrap().keys() {
            assert!(
                CHECKED.contains(&name.as_str()),
                "{case_id}: field {name} is not checked"
            );
        }
    }
}

#[test]
fn key_packages_reproduce_from_ikm_e_and_open() {
    let suite = Suite::load();
    let principals = suite.principals();
    let commitments = recorded_commitments(&suite);
    for case_id in PACKAGES {
        let case = suite.case(case_id);
        let expected = &case["expected"];
        let field = |name: &str| hex(case_id, &expected[name]);
        let ikm_e = hex(case_id, &case["inputs"]["hpke_ephemeral_ikm"]);

        let bytes = field("cose_sign1");
        let received = ReceivedKeyPackage::parse(&bytes)
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
        let header = received.header().clone();
        assert_eq!(
            header.hpke_info(),
            field("hpke_info_cbor"),
            "{case_id}: hpke_info_cbor"
        );
        assert_eq!(
            header.hpke_aad(),
            field("hpke_aad_cbor"),
            "{case_id}: hpke_aad_cbor"
        );
        let sender = principal_by_id(&principals, case_id, &header.sender);
        let recipient = principal_by_id(&principals, case_id, &header.recipient);
        assert_eq!(
            Some(sender.descriptor()),
            case["inputs"]["signer"]
                .as_str()
                .map(|name| principals[name].descriptor()),
            "{case_id}: inputs.signer is the sender"
        );

        // skE, pkE = DeriveKeyPair(ikmE); enc is pkE.
        let (sk_e, pk_e) = Kem::derive_keypair(&ikm_e);
        assert_eq!(
            sk_e.to_bytes().as_slice(),
            field("hpke_ephemeral_private"),
            "{case_id}: hpke_ephemeral_private"
        );
        assert_eq!(
            pk_e.to_bytes().as_slice(),
            field("hpke_enc"),
            "{case_id}: hpke_enc"
        );
        assert_eq!(
            X25519PrivateKey::from_bytes(hex32(case_id, &expected["hpke_ephemeral_private"]))
                .public_key()
                .as_slice(),
            field("hpke_enc"),
            "{case_id}: enc is the public key of skE"
        );

        // The KEM shared secret of Encap(pkR) with the same ephemeral key.
        let pk_r =
            <Kem as hpke::Kem>::PublicKey::from_bytes(recipient.descriptor().x25519_public())
                .unwrap();
        let (shared, encapped) =
            Kem::encap_with_rng(&pk_r, None, &mut FixedRng(ikm_e.clone())).unwrap();
        assert_eq!(
            shared.0.as_slice(),
            field("hpke_shared_secret"),
            "{case_id}: hpke_shared_secret"
        );
        assert_eq!(
            encapped.to_bytes().as_slice(),
            field("hpke_enc"),
            "{case_id}: encapsulated key"
        );

        // The key schedule's AEAD key and base nonce: the ciphertext opens
        // under exactly these values, and not if either changes.
        let dek = fixture_dek(&suite, header.data_epoch);
        let open_with = |key: &[u8], nonce: &[u8]| {
            let key = AeadKey::<Aead>(key.try_into().unwrap());
            let nonce = AeadNonce::<Aead>(nonce.try_into().unwrap());
            create_receiver_context::<Aead, Kdf, Kem>(&key, nonce, ExporterSecret::default())
                .open(&field("hpke_ciphertext"), &field("hpke_aad_cbor"))
                .ok()
        };
        let (key, nonce) = (field("hpke_key"), field("hpke_base_nonce"));
        assert_eq!(
            open_with(&key, &nonce),
            Some(dek.clone()),
            "{case_id}: hpke_key and hpke_base_nonce"
        );
        let flip = |mut bytes: Vec<u8>| {
            bytes[0] ^= 1;
            bytes
        };
        assert_eq!(
            open_with(&flip(key.clone()), &nonce),
            None,
            "{case_id}: other key"
        );
        assert_eq!(
            open_with(&key, &flip(nonce.clone())),
            None,
            "{case_id}: other nonce"
        );

        // The whole package re-seals byte for byte from ikmE.
        let resealed = KeyPackage::seal_with_rng(
            header.resource_id,
            header.data_epoch,
            header.control_head,
            &Dek::from_bytes(dek.clone().try_into().unwrap()),
            recipient.descriptor(),
            sender,
            &mut FixedRng(ikm_e),
        )
        .unwrap_or_else(|err| panic!("{case_id}: seal failed: {err}"));
        assert_eq!(
            resealed.enc(),
            field("hpke_enc"),
            "{case_id}: re-sealed enc"
        );
        assert_eq!(
            resealed.ciphertext(),
            field("hpke_ciphertext"),
            "{case_id}: hpke_ciphertext"
        );
        assert_eq!(
            resealed.signed_object().payload_bytes(),
            field("payload_cbor"),
            "{case_id}: payload_cbor"
        );
        assert_eq!(
            resealed.signed_object().bytes(),
            bytes,
            "{case_id}: cose_sign1"
        );
        assert_eq!(
            resealed.id().as_bytes().as_slice(),
            field("package_id"),
            "{case_id}: package_id"
        );
        assert_eq!(
            crypto::sha256(&bytes).as_bytes().as_slice(),
            field("package_id"),
            "{case_id}: package_id is SHA-256 of the exact bytes"
        );
        assert_eq!(
            cose::parse(&bytes).unwrap().payload_bytes(),
            field("payload_cbor"),
            "{case_id}: published payload"
        );

        // Verified as published, the package opens to the DEK of its epoch.
        let package = received
            .verify(sender.descriptor(), |_| Ok(()))
            .unwrap_or_else(|err| panic!("{case_id}: verify failed: {err}"));
        assert_eq!(package, resealed, "{case_id}: verified package");
        let opened = package
            .open(recipient, &commitments[&header.data_epoch])
            .unwrap_or_else(|err| panic!("{case_id}: open failed: {err}"));
        assert_eq!(
            opened.expose_secret().as_slice(),
            dek,
            "{case_id}: DEK of epoch {}",
            header.data_epoch
        );
    }
}

#[test]
fn enc_of_the_wrong_size_is_malformed() {
    // §25 (G-KP3): enc is bstr .size 32.
    let suite = Suite::load();
    let case_id = "kp_enc_wrong_size_KP0";
    let case = suite.case(case_id);
    let err = ReceivedKeyPackage::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
        .expect_err("kp_enc_wrong_size_KP0: parsed");
    assert_eq!(err, Error::KeyPackageMalformed, "{case_id}");
    assert_eq!(
        err.wire_code().map(|c| c.name()),
        case["expected"]["error"]["code"].as_str(),
        "{case_id}: code"
    );
    assert_eq!(case["expected"]["disposition"], "reject", "{case_id}");
}

#[test]
fn recipient_mismatch_is_client_local() {
    let suite = Suite::load();
    let principals = suite.principals();
    let case_id = "hpke_recipient_mismatch_KP0";
    let case = suite.case(case_id);
    let commitments = recorded_commitments(&suite);

    let received = ReceivedKeyPackage::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
        .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
    let header = received.header().clone();
    let carol: &PrincipalKeys = &principals["CAROL"];
    assert_eq!(
        &header.recipient,
        carol.descriptor().id(),
        "{case_id}: names CAROL"
    );
    // KP-1: the package names CAROL at C3, where she holds data/read and
    // OWNER may distribute, so every §25.2 check passes.
    let chain: Vec<Vec<u8>> = [
        "C0_genesis",
        "C1_grant_bob",
        "C2_invite_grant",
        "C3_invite_claim_carol",
    ]
    .iter()
    .map(|id| hex(id, &suite.case(id)["expected"]["cose_sign1"]))
    .collect();
    let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let (_, history) = validate_authorized(&refs, None).unwrap();
    assert_eq!(
        header.control_head.as_bytes(),
        history.last().unwrap().head.id.as_bytes(),
        "{case_id}: at C3"
    );
    let sender = principal_by_id(&principals, case_id, &header.sender);
    let package = received
        .verify(sender.descriptor(), key_package_policy(&history))
        .unwrap_or_else(|err| panic!("{case_id}: §25.2: {err}"));
    let commitment = &commitments[&header.data_epoch];

    // The context names CAROL's X25519 key as the one to try.
    assert_eq!(
        X25519PrivateKey::from_bytes(hex32(
            "principal_carol",
            &suite.case("principal_carol")["inputs"]["x25519_private"]
        ))
        .public_key(),
        *carol.descriptor().x25519_public(),
        "{case_id}: context recipient_x25519_private"
    );
    let err = package
        .open(carol, commitment)
        .expect_err("hpke_recipient_mismatch_KP0: opened for CAROL");
    assert_eq!(err, Error::HpkeOpenFailed, "{case_id}: CAROL");
    assert!(
        err.is_client_local() && err.wire_code().is_none(),
        "{case_id}: client-local"
    );

    // BOB holds the key it was sealed to, but the package is not his.
    let err = package
        .open(&principals["BOB"], commitment)
        .expect_err("hpke_recipient_mismatch_KP0: opened for BOB");
    assert_eq!(err, Error::KeyPackageRecipientMismatch, "{case_id}: BOB");
    assert!(err.is_client_local(), "{case_id}: client-local");

    let expected = &case["expected"];
    assert_eq!(expected["valid"], false, "{case_id}");
    assert_eq!(expected["disposition"], "reject", "{case_id}");
    assert!(expected["error"].is_null(), "{case_id}: no wire code");
}
