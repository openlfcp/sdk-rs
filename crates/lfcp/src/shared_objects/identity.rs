//! Automerge actor IDs (SHARED-OBJECTS-PROFILE-01 §8) and Principal
//! references (§27).
//!
//! ```text
//! actor_id      = SHA-256("OPENLFCP-SHARED-OBJECTS-ACTOR-v1" || resource_id || principal_id)
//! principal-ref = "p:" base64url-no-padding(principal_id)
//! ```

use automerge::ActorId;

use crate::base::{self, PrincipalId, ResourceId};
use crate::crypto;
use crate::shared_objects::Diagnostic;

const ACTOR_DOMAIN: &[u8] = b"OPENLFCP-SHARED-OBJECTS-ACTOR-v1";

/// The 32-byte Automerge actor of `principal` in `resource` (§8). The same
/// Principal gets a different actor in every Resource.
pub fn actor_id_bytes(resource: &ResourceId, principal: &PrincipalId) -> [u8; 32] {
    *crypto::sha256_parts(&[ACTOR_DOMAIN, resource.as_bytes(), principal.as_bytes()]).as_bytes()
}

/// [`actor_id_bytes`] as an Automerge [`ActorId`].
pub fn actor_id(resource: &ResourceId, principal: &PrincipalId) -> ActorId {
    ActorId::from(actor_id_bytes(resource, principal))
}

/// The Principal reference `p:<base64url>` of `principal` (§27).
pub fn principal_ref(principal: &PrincipalId) -> String {
    format!("p:{}", base::to_b64url(principal.as_bytes()))
}

/// Parse a Principal reference: the prefix `p:` and the canonical unpadded
/// base64url of exactly 32 bytes (§27, §42). Anything else is
/// [`Diagnostic::InvalidPrincipalRef`].
pub fn parse_principal_ref(text: &str) -> Result<PrincipalId, Diagnostic> {
    text.strip_prefix("p:")
        .and_then(|encoded| base::from_b64url(encoded).ok())
        .and_then(|bytes| PrincipalId::from_slice(&bytes).ok())
        .ok_or(Diagnostic::InvalidPrincipalRef)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_refs_round_trip_and_reject_other_forms() {
        let id = PrincipalId::from_bytes([7; 32]);
        let text = principal_ref(&id);
        assert!(text.starts_with("p:") && !text.contains('='));
        assert_eq!(parse_principal_ref(&text), Ok(id));
        for bad in [
            "",
            "p:",
            "P:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
            "not-a-principal",
            "p:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw",
            "p:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        ] {
            assert_eq!(
                parse_principal_ref(bad),
                Err(Diagnostic::InvalidPrincipalRef),
                "{bad}"
            );
        }
    }

    #[test]
    fn actors_differ_per_resource() {
        let principal = PrincipalId::from_bytes([1; 32]);
        let a = actor_id_bytes(&ResourceId::from_bytes([2; 32]), &principal);
        let b = actor_id_bytes(&ResourceId::from_bytes([3; 32]), &principal);
        assert_ne!(a, b);
        assert_eq!(
            actor_id(&ResourceId::from_bytes([2; 32]), &principal).to_bytes(),
            a
        );
    }
}
