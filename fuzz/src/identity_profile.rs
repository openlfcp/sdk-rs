//! Identity variant of objects_admission: same framed record format, immutable
//! unit metadata retained through dependency waits, replay and Snapshot checks.
use crate::{plaintext, records};
use lfcp::{
    base::{PrincipalId, ResourceId},
    identity::{IdentityReplica, Received, UnitContext, WriterClass},
    shared_objects::framing,
};

pub fn check(data: &[u8]) {
    let first = run(data);
    let second = run(data);
    assert_eq!(first, second, "identity receive must be deterministic");
}
fn run(data: &[u8]) -> (Vec<Received>, Vec<String>, Vec<String>, Vec<String>) {
    let resource =
        ResourceId::from_bytes(*lfcp::crypto::sha256(b"LFCP-TV-IDENTITY-RESOURCE-I").as_bytes());
    let principals = ["OWNER", "DEV_B", "PAIR_J"].map(|label| {
        let ed = lfcp::crypto::sha256(format!("LFCP-TV-{label}-ED25519").as_bytes());
        let x = lfcp::crypto::sha256(format!("LFCP-TV-{label}-X25519").as_bytes());
        *lfcp::principal::PrincipalKeys::from_secrets(ed.as_bytes(), *x.as_bytes())
            .descriptor()
            .id()
    });
    let root = principals[0];
    let mut replica = IdentityReplica::new(resource, root);
    let mut verdicts = Vec::new();
    let mut witnesses = Vec::new();
    for (index, record) in records(data).into_iter().take(64).enumerate() {
        let signer = principals
            .get(usize::from(record.ctl & 3))
            .copied()
            .unwrap_or(PrincipalId::from_bytes([99; 32]));
        let class = if signer == root {
            WriterClass::Root
        } else if record.ctl & 16 != 0 {
            WriterClass::Personal
        } else {
            WriterClass::Pairing
        };
        let bytes = plaintext(&record);
        let unit = UnitContext {
            signer,
            class,
            actor_sequence: if record.ctl & 32 == 0 {
                framing::decode_change(&bytes).map_or(1, |c| c.seq())
            } else {
                (index + 2) as u64
            },
        };
        let before = replica.accepted();
        let result = replica.receive(unit, &bytes);
        if matches!(
            result,
            Received::Refused(_) | Received::Waiting | Received::Held | Received::Duplicate
        ) {
            assert_eq!(replica.accepted(), before);
        }
        let after = replica.accepted();
        let again = replica.receive(unit, &bytes);
        if result == Received::Applied {
            assert_eq!(again, Received::Duplicate);
        } else {
            assert_eq!(again, result);
        }
        assert_eq!(replica.accepted(), after);
        witnesses.push((unit, bytes));
        verdicts.push(result);
    }
    let accepted = replica.accepted();
    if !accepted.is_empty() && accepted.len() < 32 {
        let save = replica.save();
        let mut restored = IdentityReplica::new(resource, root);
        assert!(restored
            .receive_snapshot(&framing::encode_snapshot(&save), &witnesses)
            .unwrap());
        assert_eq!(restored.accepted(), accepted);
    }
    (
        verdicts,
        accepted.iter().map(ToString::to_string).collect(),
        replica.waiting().iter().map(ToString::to_string).collect(),
        replica.held().iter().map(ToString::to_string).collect(),
    )
}
