//! LFCP-TEST-VECTORS-01 cases for HPKE Key Packages: KP0, KPI, KPC and
//! hpke_recipient_mismatch_KP0.
//!
//! The `hpke` crate derives the ephemeral key from random input
//! (DeriveKeyPair), while the vectors publish the raw ephemeral private
//! key. Re-sealing, and the HPKE intermediates, therefore cannot be
//! reproduced through the crate's API. They are listed per field in
//! `NOT_CHECKABLE_PENDING_G_KP2` rather than dropped, and the guard test
//! requires every vector field to be either checked or listed there.
//! Every assertion names its case.

mod support;

use std::collections::BTreeMap;

use lfcp::base::{Error, Hash32};
use lfcp::cose;
use lfcp::crypto::{self, X25519PrivateKey};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::ReceivedControlRecord;
use lfcp::wire::key_package::ReceivedKeyPackage;
use support::vectors::{hex, hex32, principal_by_id, Suite};

const PACKAGES: [&str; 3] = ["KP0_bob_epoch0", "KPI_invite_epoch0", "KPC_carol_epoch1"];

/// Expected fields each package test compares byte for byte.
const CHECKED: &[&str] = &[
    "hpke_info_cbor",
    "hpke_aad_cbor",
    "hpke_enc",
    "hpke_ciphertext",
    "payload_cbor",
    "cose_sign1",
    "package_id",
];

/// Expected fields the crate API cannot reproduce from the raw ephemeral
/// private key: the HPKE intermediates. A ciphertext re-seal is equally
/// impossible; the published ciphertext is instead checked by opening it.
/// Pending spec gap G-KP2 (publish ikmE).
const NOT_CHECKABLE_PENDING_G_KP2: &[&str] = &["hpke_shared_secret", "hpke_key", "hpke_base_nonce"];

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
fn every_package_field_is_checked_or_pending_g_kp2() {
    let suite = Suite::load();
    for case_id in PACKAGES {
        for name in suite.case(case_id)["expected"].as_object().unwrap().keys() {
            let checked = CHECKED.contains(&name.as_str());
            let pending = NOT_CHECKABLE_PENDING_G_KP2.contains(&name.as_str());
            assert!(
                checked != pending,
                "{case_id}: field {name} is neither checked nor listed"
            );
        }
    }
}

#[test]
fn key_packages_match_and_open() {
    let suite = Suite::load();
    let principals = suite.principals();
    let commitments = recorded_commitments(&suite);
    for case_id in PACKAGES {
        let case = suite.case(case_id);
        let expected = &case["expected"];
        let field = |name: &str| hex(case_id, &expected[name]);

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

        // enc is the public key of the published ephemeral private key.
        let ephemeral =
            X25519PrivateKey::from_bytes(hex32(case_id, &case["inputs"]["hpke_ephemeral_private"]));
        assert_eq!(
            ephemeral.public_key().as_slice(),
            field("hpke_enc"),
            "{case_id}: hpke_enc"
        );

        // The payload and the signed object re-sign byte-exact.
        let object = cose::parse(&bytes).unwrap();
        assert_eq!(
            object.payload_bytes(),
            field("payload_cbor"),
            "{case_id}: payload_cbor"
        );
        let sender = principal_by_id(&principals, case_id, &header.sender);
        let resigned = cose::sign(&field("payload_cbor"), sender).unwrap();
        assert_eq!(resigned.bytes(), bytes, "{case_id}: cose_sign1");
        assert_eq!(
            crypto::sha256(&bytes).as_bytes().as_slice(),
            field("package_id"),
            "{case_id}: package_id"
        );

        let package = received
            .verify(sender.descriptor(), |_| Ok(()))
            .unwrap_or_else(|err| panic!("{case_id}: verify failed: {err}"));
        assert_eq!(
            package.id().as_bytes().as_slice(),
            field("package_id"),
            "{case_id}: id"
        );
        assert_eq!(package.enc(), field("hpke_enc"), "{case_id}: payload enc");
        assert_eq!(
            package.ciphertext(),
            field("hpke_ciphertext"),
            "{case_id}: hpke_ciphertext"
        );

        // Opening under the exact info and AAD authenticates them and the
        // ciphertext, and yields the DEK of the right epoch.
        let recipient = principal_by_id(&principals, case_id, &header.recipient);
        let commitment = &commitments[&header.data_epoch];
        let dek = package
            .open(recipient, commitment)
            .unwrap_or_else(|err| panic!("{case_id}: open failed: {err}"));
        assert_eq!(
            dek.expose_secret().as_slice(),
            fixture_dek(&suite, header.data_epoch),
            "{case_id}: DEK of epoch {}",
            header.data_epoch
        );
    }
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
    let sender = principal_by_id(&principals, case_id, &header.sender);
    let package = received
        .verify(sender.descriptor(), |_| Ok(()))
        .unwrap_or_else(|err| panic!("{case_id}: verify failed: {err}"));
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
