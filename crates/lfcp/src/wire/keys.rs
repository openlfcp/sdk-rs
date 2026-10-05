//! Data Epoch keys: the DEK, its commitment and the keys derived from it
//! (LFCP-WIRE-01 §11, §12, §29.1).
//!
//! | Value | Formula | § |
//! | --- | --- | --- |
//! | `dek_commitment` | `SHA-256("LFCP-DEK-v1" ‖ resource_id ‖ u64be(epoch) ‖ DEK)` | §11 |
//! | `actor_key` | `HKDF-SHA256(salt = resource_id ‖ u64be(epoch), IKM = DEK, info = "LFCP-DATA-KEY-v1" ‖ actor_id, L = 32)` | §12 |
//! | `snapshot_key` | `HKDF-SHA256(salt = resource_id ‖ u64be(epoch), IKM = DEK, info = "LFCP-SNAPSHOT-KEY-v1" ‖ publisher_id, L = 32)` | §29.1.1 |
//! | nonce | `0x00000000 ‖ u64be(sequence)` | §12, §29.1.2 |
//!
//! Key types redact themselves in `Debug`, wipe their bytes on drop and
//! are not `Clone`. Raw bytes leave them only through `expose_secret`.

use std::fmt;

use zeroize::Zeroizing;

use crate::base::{Hash32, PrincipalId, ResourceId};
use crate::crypto;

macro_rules! secret32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(Zeroizing<[u8; 32]>);

        impl $name {
            /// Wrap 32 secret bytes.
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// The raw secret bytes. Callers must not log or persist them
            /// in diagnostics.
            pub fn expose_secret(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret32! {
    /// A Resource Data Encryption Key for one Data Epoch (§11).
    Dek
}

secret32! {
    /// The per-actor Data Unit encryption key (§12).
    ActorKey
}

secret32! {
    /// The Snapshot encryption key of one publisher (§29.1.1).
    SnapshotKey
}

const DEK_DOMAIN: &[u8] = b"LFCP-DEK-v1";
const DATA_KEY_DOMAIN: &[u8] = b"LFCP-DATA-KEY-v1";
const SNAPSHOT_KEY_DOMAIN: &[u8] = b"LFCP-SNAPSHOT-KEY-v1";

/// The public commitment to the DEK of `epoch` (§11).
pub fn dek_commitment(resource_id: &ResourceId, epoch: u64, dek: &Dek) -> Hash32 {
    crypto::sha256_parts(&[
        DEK_DOMAIN,
        resource_id.as_bytes(),
        &epoch.to_be_bytes(),
        dek.expose_secret(),
    ])
}

/// HKDF salt shared by the actor and Snapshot keys: `resource_id ‖
/// u64be(epoch)`.
fn epoch_salt(resource_id: &ResourceId, epoch: u64) -> [u8; 40] {
    let mut salt = [0u8; 40];
    salt[..32].copy_from_slice(resource_id.as_bytes());
    salt[32..].copy_from_slice(&epoch.to_be_bytes());
    salt
}

fn derive(
    dek: &Dek,
    resource_id: &ResourceId,
    epoch: u64,
    domain: &[u8],
    principal: &PrincipalId,
) -> Zeroizing<[u8; 32]> {
    let info = [domain, principal.as_bytes()].concat();
    crypto::hkdf_sha256_32(&epoch_salt(resource_id, epoch), dek.expose_secret(), &info)
}

impl ActorKey {
    /// Derive the key `actor` encrypts its Data Units with in `epoch`
    /// (§12).
    pub fn derive(
        dek: &Dek,
        resource_id: &ResourceId,
        epoch: u64,
        actor: &PrincipalId,
    ) -> ActorKey {
        ActorKey(derive(dek, resource_id, epoch, DATA_KEY_DOMAIN, actor))
    }
}

impl SnapshotKey {
    /// Derive the key `publisher` encrypts its Snapshots with in `epoch`
    /// (§29.1.1).
    pub fn derive(
        dek: &Dek,
        resource_id: &ResourceId,
        epoch: u64,
        publisher: &PrincipalId,
    ) -> SnapshotKey {
        SnapshotKey(derive(
            dek,
            resource_id,
            epoch,
            SNAPSHOT_KEY_DOMAIN,
            publisher,
        ))
    }
}

/// The 12-byte ChaCha20-Poly1305 nonce for an actor sequence or a Snapshot
/// sequence: four zero bytes, then the sequence as u64 big-endian (§12,
/// §29.1.2).
pub fn sequence_nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_zero_prefixed_big_endian() {
        assert_eq!(sequence_nonce(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            sequence_nonce(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn keys_are_separated_by_domain_principal_and_epoch() {
        let dek = Dek::from_bytes([9; 32]);
        let resource = ResourceId::from_bytes([1; 32]);
        let a = PrincipalId::from_bytes([2; 32]);
        let b = PrincipalId::from_bytes([3; 32]);
        let actor = ActorKey::derive(&dek, &resource, 0, &a);
        assert_ne!(
            actor.expose_secret(),
            ActorKey::derive(&dek, &resource, 0, &b).expose_secret()
        );
        assert_ne!(
            actor.expose_secret(),
            ActorKey::derive(&dek, &resource, 1, &a).expose_secret()
        );
        assert_ne!(
            actor.expose_secret(),
            SnapshotKey::derive(&dek, &resource, 0, &a).expose_secret()
        );
        assert_ne!(
            dek_commitment(&resource, 0, &dek),
            dek_commitment(&resource, 1, &dek)
        );
    }
}
