//! No secret reaches Debug, Display or error output.
//!
//! Every secret-bearing type and every error produced with secrets in
//! scope is formatted, and the output is searched for each secret, both as
//! hex and in the `[u8]` Debug form. HPKE ephemeral keys and shared
//! secrets never leave the `hpke` crate, so they cannot appear here.

use lfcp::base::{to_hex, DataUnitId, Error, Hash32, ResourceId};
use lfcp::crypto::{self, Ed25519SigningKey, X25519PrivateKey};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::frontier::Frontier;
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::{dek_commitment, ActorKey, Dek, SnapshotKey};
use lfcp::wire::snapshot::{Snapshot, SnapshotHeader};

const DEK: [u8; 32] = [0xd1; 32];
const ED25519_SEED: [u8; 32] = [0x5e; 32];
const X25519_PRIVATE: [u8; 32] = [0x7a; 32];
const RECIPIENT_ED25519_SEED: [u8; 32] = [0x6b; 32];
const RECIPIENT_X25519_PRIVATE: [u8; 32] = [0x8c; 32];

/// The forms in which a 32-byte secret could appear in formatted output.
fn forms(secret: &[u8; 32]) -> Vec<String> {
    let debug = format!("{secret:?}");
    vec![
        to_hex(secret),
        to_hex(secret).to_uppercase(),
        // The first eight elements of the array Debug form are enough to
        // spot a leak without matching unrelated output.
        debug[..debug.match_indices(',').nth(7).unwrap().0].to_owned(),
    ]
}

fn assert_clean(label: &str, output: &str, secrets: &[[u8; 32]]) {
    for secret in secrets {
        for form in forms(secret) {
            assert!(!output.contains(&form), "{label} leaks a secret: {output}");
        }
    }
}

#[test]
fn formatted_output_contains_no_secret() {
    let resource = ResourceId::from_bytes([1; 32]);
    let keys = PrincipalKeys::from_secrets(&ED25519_SEED, X25519_PRIVATE);
    let actor = *keys.descriptor().id();
    let dek = Dek::from_bytes(DEK);
    let actor_key = ActorKey::derive(&dek, &resource, 0, &actor);
    let snapshot_key = SnapshotKey::derive(&dek, &resource, 0, &actor);
    let recipient = PrincipalKeys::from_secrets(&RECIPIENT_ED25519_SEED, RECIPIENT_X25519_PRIVATE);
    let secrets = [
        DEK,
        ED25519_SEED,
        X25519_PRIVATE,
        RECIPIENT_ED25519_SEED,
        RECIPIENT_X25519_PRIVATE,
        *actor_key.expose_secret(),
        *snapshot_key.expose_secret(),
    ];

    let unit = DataUnit::seal(
        DataUnitHeader {
            resource_id: resource,
            data_epoch: 0,
            actor,
            sequence: 1,
            previous: None,
            control_head: Hash32::from_bytes([2; 32]),
        },
        b"plaintext",
        &dek,
        &keys,
    )
    .unwrap();
    let snapshot = Snapshot::seal(
        SnapshotHeader {
            resource_id: resource,
            data_epoch: 0,
            publisher: actor,
            sequence: 1,
            control_head: Hash32::from_bytes([2; 32]),
            frontier: Frontier::new(vec![]).unwrap(),
        },
        b"state",
        &dek,
        &keys,
    )
    .unwrap();
    let received = ReceivedDataUnit::parse(unit.signed_object().bytes()).unwrap();
    let head = Hash32::from_bytes([2; 32]);
    let commitment = dek_commitment(&resource, 0, &dek);
    let package = KeyPackage::seal(resource, 0, head, &dek, recipient.descriptor(), &keys).unwrap();
    let received_package = ReceivedKeyPackage::parse(package.signed_object().bytes()).unwrap();
    let opened = package.open(&recipient, &commitment).unwrap();

    let debug_outputs = [
        ("Dek", format!("{dek:?}")),
        ("ActorKey", format!("{actor_key:?}")),
        ("SnapshotKey", format!("{snapshot_key:?}")),
        (
            "Ed25519SigningKey",
            format!("{:?}", Ed25519SigningKey::from_seed(&ED25519_SEED)),
        ),
        (
            "X25519PrivateKey",
            format!("{:?}", X25519PrivateKey::from_bytes(X25519_PRIVATE)),
        ),
        ("PrincipalKeys", format!("{keys:?}")),
        ("recipient PrincipalKeys", format!("{recipient:?}")),
        ("KeyPackage", format!("{package:?}")),
        ("ReceivedKeyPackage", format!("{received_package:?}")),
        ("opened Dek", format!("{opened:?}")),
        ("DataUnit", format!("{unit:?}")),
        ("ReceivedDataUnit", format!("{received:?}")),
        ("Snapshot", format!("{snapshot:?}")),
    ];
    for (label, output) in &debug_outputs {
        assert_clean(label, output, &secrets);
    }
    assert_eq!(debug_outputs[0].1, "Dek(<redacted>)");

    // Errors produced while secrets are in use.
    let other = PrincipalKeys::from_secrets(&[3; 32], [4; 32]);
    let errors: Vec<Error> = vec![
        unit.open(&Dek::from_bytes([9; 32])).unwrap_err(),
        snapshot.open(&Dek::from_bytes([9; 32])).unwrap_err(),
        crypto::aead_open(actor_key.expose_secret(), &[0; 12], b"short", b"").unwrap_err(),
        DataUnit::seal(unit.header().clone(), b"x", &dek, &other).unwrap_err(),
        DataUnit::seal(
            DataUnitHeader {
                sequence: 0,
                previous: Some(DataUnitId::from_bytes([5; 32])),
                ..unit.header().clone()
            },
            b"x",
            &dek,
            &keys,
        )
        .unwrap_err(),
        received.clone().verify(other.descriptor()).unwrap_err(),
        package.open(&other, &commitment).unwrap_err(),
        package.open(&recipient, &head).unwrap_err(),
        crypto::hpke_open(
            recipient.agreement_key(),
            package.enc(),
            b"info",
            b"aad",
            package.ciphertext(),
        )
        .unwrap_err(),
        received_package
            .clone()
            .verify(other.descriptor(), |_| Ok(()))
            .unwrap_err(),
    ];
    for err in &errors {
        assert_clean("error Debug", &format!("{err:?}"), &secrets);
        assert_clean("error Display", &format!("{err}"), &secrets);
    }
}
