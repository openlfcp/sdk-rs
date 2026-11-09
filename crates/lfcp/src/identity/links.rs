//! Pairing URI codec and device fingerprints (IDENTITY-PROFILE-01 §5.2).
use crate::{
    base::{from_b64url, to_b64url, PrincipalId, ResourceId},
    principal::PrincipalKeys,
    wire::control::body::{is_loopback, scheme},
};
use std::fmt;
use zeroize::Zeroizing;

/// A rejected link. Its display never includes the URI or its secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkRejected;
impl fmt::Display for LinkRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PAIRING_LINK_REJECTED")
    }
}
impl std::error::Error for LinkRejected {}

/// Parsed pairing link; secret storage is zeroized on drop and redacted in Debug.
pub struct PairingLink {
    /// Identity Resource ID.
    pub identity: ResourceId,
    /// Route hints, in URI order.
    pub endpoints: Vec<String>,
    /// Pairing Principal, recomputed and matched against the URI.
    pub device: PrincipalId,
    secret: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for PairingLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingLink")
            .field("identity", &self.identity)
            .field("device", &self.device)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
impl PairingLink {
    /// Construct a link. Callers must first check the pairing device's active
    /// registration and the Genesis profile (§5.2–§5.3).
    pub fn new(
        identity: ResourceId,
        endpoints: Vec<String>,
        ed25519_seed: &[u8; 32],
        x25519_private: &[u8; 32],
    ) -> Result<Self, LinkRejected> {
        if endpoints.is_empty() || endpoints.iter().any(|e| !writable_endpoint(e)) {
            return Err(LinkRejected);
        }
        // The closed, deterministic invite-secret map has exactly this
        // encoding. Keep secret bytes in zeroizing storage throughout.
        let mut secret = Zeroizing::new(Vec::with_capacity(73));
        secret.extend_from_slice(&[0xa3, 0, 1, 1, 0x58, 0x20]);
        secret.extend_from_slice(ed25519_seed);
        secret.extend_from_slice(&[2, 0x58, 0x20]);
        secret.extend_from_slice(x25519_private);
        let keys = PrincipalKeys::from_secrets(ed25519_seed, *x25519_private);
        Ok(Self {
            identity,
            endpoints,
            device: *keys.descriptor().id(),
            secret,
        })
    }
    /// Parse only `lfcp://pair/`, the scheme and host in any case (§5.2,
    /// RFC 3986 §3.1, §3.2.2), including strict percent encoding and secret
    /// descriptor matching. No input text is included in failures.
    pub fn parse(uri: &str) -> Result<Self, LinkRejected> {
        const PREFIX: &str = "lfcp://pair/";
        let rest = uri
            .get(..PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(PREFIX))
            .map(|_| &uri[PREFIX.len()..])
            .ok_or(LinkRejected)?;
        let (public, fragment) = rest.split_once('#').ok_or(LinkRejected)?;
        let encoded = fragment.strip_prefix("secret=").ok_or(LinkRejected)?;
        let secret = Zeroizing::new(from_b64url(encoded).map_err(|_| LinkRejected)?);
        let keys = secret_keys(&secret)?;
        let (resource, query) = public.split_once('?').ok_or(LinkRejected)?;
        let identity = ResourceId::from_b64url(resource).map_err(|_| LinkRejected)?;
        let mut endpoints = Vec::new();
        let mut device = None;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = unescape(k)?;
            let v = unescape(v)?;
            match k.as_str() {
                "endpoint" => {
                    if !received_endpoint(&v) {
                        return Err(LinkRejected);
                    }
                    endpoints.push(v);
                }
                "device" => {
                    if device.is_some() {
                        return Err(LinkRejected);
                    }
                    device = Some(PrincipalId::from_b64url(&v).map_err(|_| LinkRejected)?);
                }
                _ => {}
            }
        }
        if endpoints.is_empty() || device.as_ref() != Some(keys.descriptor().id()) {
            return Err(LinkRejected);
        }
        Ok(Self {
            identity,
            endpoints,
            device: device.unwrap(),
            secret,
        })
    }
    /// Encode the canonical URI. The returned string contains a bearer secret;
    /// do not log, persist in history, or send it to a server.
    pub fn encode(&self) -> Zeroizing<String> {
        let hints = self
            .endpoints
            .iter()
            .map(|s| format!("endpoint={}", escape(s)))
            .collect::<Vec<_>>()
            .join("&");
        Zeroizing::new(format!(
            "lfcp://pair/{}?{}&device={}#secret={}",
            self.identity.to_b64url(),
            hints,
            self.device.to_b64url(),
            to_b64url(&self.secret)
        ))
    }
    /// Derive the pairing Principal's keys. Verify active kind-2 registration
    /// and the Genesis profile before using them for the pairing flow.
    pub fn keys(&self) -> Result<PrincipalKeys, LinkRejected> {
        secret_keys(&self.secret)
    }
}
fn secret_keys(bytes: &[u8]) -> Result<PrincipalKeys, LinkRejected> {
    if bytes.len() != 73
        || bytes[..6] != [0xa3, 0, 1, 1, 0x58, 0x20]
        || bytes[38..41] != [2, 0x58, 0x20]
    {
        return Err(LinkRejected);
    }
    let ed = Zeroizing::new(<[u8; 32]>::try_from(&bytes[6..38]).map_err(|_| LinkRejected)?);
    let x = Zeroizing::new(<[u8; 32]>::try_from(&bytes[41..73]).map_err(|_| LinkRejected)?);
    Ok(PrincipalKeys::from_secrets(&ed, *x))
}

/// An endpoint a receiver accepts in a link (§5.2, W §18.2, W §16): the
/// scheme `ws` or `wss`, compared case-insensitively and followed by `://`,
/// then a non-empty authority with no user information, fragment,
/// whitespace or control character.
fn received_endpoint(s: &str) -> bool {
    matches!(scheme(s).as_deref(), Some("ws" | "wss"))
        && s.split_once("://").is_some_and(|(_, s)| {
            !s.is_empty()
                && !s.starts_with(['/', '?'])
                && !s.contains(['#', '@'])
                && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        })
}
/// An endpoint a writer puts in a link (W §16): `wss`, or `ws` to a
/// loopback address.
fn writable_endpoint(s: &str) -> bool {
    received_endpoint(s)
        && match scheme(s).as_deref() {
            Some("wss") => true,
            Some("ws") => is_loopback(s),
            _ => false,
        }
}
fn escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            use fmt::Write;
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}
fn unescape(s: &str) -> Result<String, LinkRejected> {
    let mut out = Vec::new();
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let a = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or(LinkRejected)?;
            let b = bytes
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or(LinkRejected)?;
            out.push((a * 16 + b) as u8);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).map_err(|_| LinkRejected)
}
/// 80-bit, grouped lowercase RFC 4648 base32 device fingerprint (§5.2).
pub fn fingerprint(principal: &PrincipalId) -> String {
    let mut data = b"LFCP-DEVICE-FP-v1".to_vec();
    data.extend_from_slice(principal.as_bytes());
    let digest = crate::crypto::sha256(&data);
    let bytes = &digest.as_bytes()[..10];
    let mut out = String::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if !out.is_empty() && out.len() % 5 == 4 {
                out.push('-');
            }
            out.push(b"abcdefghijklmnopqrstuvwxyz234567"[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: [u8; 32] = [3; 32];
    const X: [u8; 32] = [4; 32];

    fn link(endpoint: &str) -> Result<PairingLink, LinkRejected> {
        PairingLink::new(
            ResourceId::from_bytes([7; 32]),
            vec![endpoint.into()],
            &ED,
            &X,
        )
    }

    /// A writer uses `wss`, or `ws` for a loopback address (W §16).
    #[test]
    fn new_accepts_wss_and_loopback_ws_only() {
        for ok in [
            "wss://sync.example",
            "WSS://sync.example/ws",
            "ws://127.0.0.1:8787",
            "ws://127.9.0.1",
            "ws://localhost:8787/ws",
            "WS://[::1]:8787",
        ] {
            assert!(link(ok).is_ok(), "{ok}");
        }
        for bad in [
            "ws://sync.example",
            "ws://10.0.0.1:8787",
            "https://sync.example",
            "wss:sync.example",
            "wss://",
            "wss:///path",
            "wss://user@sync.example",
            "sync.example",
        ] {
            assert_eq!(link(bad).err(), Some(LinkRejected), "{bad}");
        }
    }

    /// A receiver accepts `ws` or `wss` in any case, followed by `://` and
    /// an authority (§5.2, W §18.2, W §16); it does not apply the writer's
    /// loopback rule.
    #[test]
    fn parse_applies_the_receiver_check() {
        let canonical = link("wss://sync.example").unwrap().encode().to_string();
        let with = |endpoint: &str| {
            canonical.replace(
                "endpoint=wss%3A%2F%2Fsync.example",
                &format!("endpoint={}", escape(endpoint)),
            )
        };
        for ok in [
            "ws://127.0.0.1:8787",
            "WSS://sync.example",
            "Ws://sync.example",
            "ws://sync.example",
        ] {
            let parsed = PairingLink::parse(&with(ok)).unwrap();
            assert_eq!(parsed.endpoints, [ok]);
        }
        for bad in [
            "https://sync.example",
            "wss:sync.example",
            "wss://",
            "wss://?x",
        ] {
            assert!(PairingLink::parse(&with(bad)).is_err(), "{bad}");
        }
    }

    /// The scheme `lfcp` and the host `pair` are case-insensitive (§5.2);
    /// the path, query and fragment are not touched.
    #[test]
    fn parse_matches_the_prefix_in_any_case() {
        let canonical = link("wss://sync.example").unwrap().encode().to_string();
        let rest = canonical.strip_prefix("lfcp://pair/").unwrap();
        for prefix in ["LFCP://PAIR/", "Lfcp://Pair/", "lfcp://PAIR/"] {
            assert!(
                PairingLink::parse(&format!("{prefix}{rest}")).is_ok(),
                "{prefix}"
            );
        }
        for prefix in ["lfcp://join/", "lfcp:/pair/", "lfcp://pairs/", "lfcp://pai"] {
            assert!(
                PairingLink::parse(&format!("{prefix}{rest}")).is_err(),
                "{prefix}"
            );
        }
        assert!(PairingLink::parse("lfcp://pai").is_err());
        assert!(PairingLink::parse("ébcdefghijkl").is_err());
    }
}
