//! Thin wrappers over established cryptographic crates.
//!
//! This module exposes the primitives of the LFCP crypto profile v1
//! (LFCP-WIRE-01 §9): SHA-256, HKDF-SHA256, ChaCha20-Poly1305, Ed25519,
//! X25519 and HPKE (RFC 9180) Base mode with DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256 and ChaCha20-Poly1305. It never implements a primitive
//! itself.
//!
//! Private keys are wrapped in types whose `Debug` output is redacted and
//! which wipe their memory on drop, so they cannot leak through logs or
//! diagnostics.
//!
//! Ed25519 verification follows LFCP-WIRE-01 §10.5.1
//! ([`ed25519_verify_strict`]): `S < L`, canonical encodings of `A` and `R`,
//! neither of small order, and the cofactorless equation. Received public
//! keys are checked with [`ed25519_public_key_check`] (§7).

use std::fmt;

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::base::{Error, Hash32};

/// SHA-256 of `data`: `hash32(x)` in LFCP-WIRE-01 §5.3.
pub fn sha256(data: &[u8]) -> Hash32 {
    sha256_parts(&[data])
}

/// SHA-256 of the concatenation of `parts`, without building it.
pub fn sha256_parts(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Hash32::from_bytes(hasher.finalize().into())
}

/// HKDF-SHA256 (RFC 5869) with a 32-byte output: Extract with `salt` and
/// `ikm`, then Expand with `info`. The output is wiped when dropped.
pub fn hkdf_sha256_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// ChaCha20-Poly1305 (RFC 8439) encryption. Returns the ciphertext followed
/// by the 16-byte tag.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("LFCP plaintexts are far below the ChaCha20-Poly1305 limit")
}

/// ChaCha20-Poly1305 (RFC 8439) decryption of ciphertext followed by its
/// tag. Any failure is [`Error::AeadFailure`].
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailure)
}

/// An Ed25519 signing key, made from its 32-byte RFC 8032 seed.
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    /// The key for a 32-byte seed (RFC 8032 §5.1.5).
    pub fn from_seed(seed: &[u8; 32]) -> Ed25519SigningKey {
        Ed25519SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// The 64-byte signature of `message`. Ed25519 is deterministic: the
    /// same key and message always give the same signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SigningKey(<redacted>)")
    }
}

/// Check an Ed25519 public key as §10.5.1 requires of `A`: a canonical
/// point encoding (it decodes, and re-encoding the point gives the same
/// bytes, which excludes `y >= p` and `x = 0` with the sign bit set) of a
/// point that is not of small order. Any failure is
/// [`Error::SignatureInvalid`].
pub fn ed25519_public_key_check(public_key: &[u8; 32]) -> Result<(), Error> {
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| Error::SignatureInvalid)?;
    if key.to_edwards().compress().to_bytes() != *public_key || key.is_weak() {
        return Err(Error::SignatureInvalid);
    }
    Ok(())
}

/// Verify an Ed25519 signature by the §10.5.1 rules.
///
/// Rules 1, 3 (for `R`) and 4 are `verify_strict`'s: it rejects `S >= L`
/// and small-order `A` and `R`, and accepts only when the cofactorless
/// recomputation of `R` encodes to exactly the signature's `R` bytes, which
/// also rejects a non-canonical `R`. [`ed25519_public_key_check`] adds
/// rule 2 for `A`. Every failure is [`Error::SignatureInvalid`].
pub fn ed25519_verify_strict(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    ed25519_public_key_check(public_key)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| Error::SignatureInvalid)?;
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    key.verify_strict(message, &signature)
        .map_err(|_| Error::SignatureInvalid)
}

/// Lenient RFC 8032 verification, for tests that show why strict
/// verification is used. Not used by the protocol code.
#[cfg(test)]
fn ed25519_verify_lenient(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map(|key| {
            use ed25519_dalek::Verifier as _;
            key.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok()
        })
        .unwrap_or(false)
}

type HpkeKem = hpke::kem::X25519HkdfSha256;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// HPKE Base-mode single-shot seal (RFC 9180 §6.1) to an X25519 public key,
/// with a fresh ephemeral key from the operating system's RNG. Returns the
/// 32-byte `enc` and the ciphertext with its tag.
pub fn hpke_seal(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; 32], Vec<u8>), Error> {
    use hpke::Deserializable as _;
    let recipient = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| Error::HpkeSealFailed)?;
    let (enc, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(
        &hpke::OpModeS::Base,
        &recipient,
        info,
        plaintext,
        aad,
    )
    .map_err(|_| Error::HpkeSealFailed)?;
    Ok((enc_bytes(&enc), ciphertext))
}

/// [`hpke_seal`] with a caller-supplied RNG, for the RFC 9180 self-test
/// only. Not part of the API: a predictable ephemeral key breaks HPKE.
#[cfg(test)]
fn hpke_seal_with_rng(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl hpke::rand_core::CryptoRng,
) -> ([u8; 32], Vec<u8>) {
    use hpke::Deserializable as _;
    let recipient = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient).unwrap();
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(
        &hpke::OpModeS::Base,
        &recipient,
        info,
        plaintext,
        aad,
        rng,
    )
    .unwrap();
    (enc_bytes(&enc), ciphertext)
}

fn enc_bytes(enc: &<HpkeKem as hpke::Kem>::EncappedKey) -> [u8; 32] {
    use hpke::Serializable as _;
    enc.to_bytes().into()
}

/// HPKE Base-mode single-shot open (RFC 9180 §6.1) with an X25519 private
/// key. Any failure, including an `enc` that is not a 32-byte X25519 key,
/// is [`Error::HpkeOpenFailed`]. The plaintext is wiped when dropped.
pub fn hpke_open(
    recipient: &X25519PrivateKey,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    use hpke::Deserializable as _;
    let secret = Zeroizing::new(recipient.0.to_bytes());
    let recipient = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(secret.as_slice())
        .map_err(|_| Error::HpkeOpenFailed)?;
    let enc =
        <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error::HpkeOpenFailed)?;
    hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
        &hpke::OpModeR::Base,
        &recipient,
        &enc,
        info,
        ciphertext,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::HpkeOpenFailed)
}

/// An X25519 private key (RFC 7748).
pub struct X25519PrivateKey(x25519_dalek::StaticSecret);

impl X25519PrivateKey {
    /// The key for 32 private-key bytes. Clamping happens inside the
    /// X25519 function, as RFC 7748 §5 specifies.
    pub fn from_bytes(bytes: [u8; 32]) -> X25519PrivateKey {
        X25519PrivateKey(x25519_dalek::StaticSecret::from(bytes))
    }

    /// The 32-byte public key: X25519 of the private key and the base point.
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }
}

impl fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519PrivateKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{fixed, from_hex};

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        fixed(&from_hex(text).unwrap()).unwrap()
    }

    #[test]
    fn sha256_matches_fips_180_example() {
        assert_eq!(
            sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_parts(&[b"a", b"", b"bc"]), sha256(b"abc"));
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        let okm = hkdf_sha256_32(
            &hex::<13>("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &hex::<10>("f0f1f2f3f4f5f6f7f8f9"),
        );
        // The first 32 of the 42 output bytes; HKDF output is a prefix of
        // the longer output.
        assert_eq!(
            *okm,
            hex::<32>("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    #[test]
    fn aead_matches_rfc8439_section_2_8_2() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex("070000004041424344454647");
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = aead_seal(&key, &nonce, plaintext, &aad);
        let expected = from_hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b6116",
            "1ae10b594f09e26a7e902ecbd0600691"
        ))
        .unwrap();
        assert_eq!(sealed, expected);
        assert_eq!(aead_open(&key, &nonce, &sealed, &aad).unwrap(), plaintext);

        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        let err = aead_open(&key, &nonce, &tampered, &aad).unwrap_err();
        assert_eq!(err, Error::AeadFailure);
        assert_eq!(err.wire_code(), None);
        assert!(err.is_client_local());
        assert_eq!(
            aead_open(&key, &nonce, &sealed, b"other aad"),
            Err(Error::AeadFailure)
        );
    }

    /// Returns fixed bytes: the RFC 9180 test vector's `ikmE`.
    struct FixedRng(Vec<u8>);

    impl hpke::rand_core::TryRng for FixedRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unimplemented!("the HPKE self-test only fills bytes")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!("the HPKE self-test only fills bytes")
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let bytes: Vec<u8> = self.0.drain(..dst.len()).collect();
            dst.copy_from_slice(&bytes);
            Ok(())
        }
    }

    impl hpke::rand_core::TryCryptoRng for FixedRng {}

    #[test]
    fn hpke_matches_rfc9180_a_2_1() {
        // RFC 9180 Appendix A.2.1: Base mode, DHKEM(X25519, HKDF-SHA256),
        // HKDF-SHA256, ChaCha20-Poly1305; the first encryption.
        let info = from_hex("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let ikm_e =
            from_hex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b").unwrap();
        let sk_r: [u8; 32] =
            hex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let pk_r: [u8; 32] =
            hex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let enc: [u8; 32] = hex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let aad = from_hex("436f756e742d30").unwrap();
        let pt = from_hex("4265617574792069732074727574682c20747275746820626561757479").unwrap();
        let ct = from_hex(concat!(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db",
            "21993c62ce81883d2dd1b51a28"
        ))
        .unwrap();

        let recipient = X25519PrivateKey::from_bytes(sk_r);
        assert_eq!(recipient.public_key(), pk_r);
        assert_eq!(
            hpke_seal_with_rng(&pk_r, &info, &aad, &pt, &mut FixedRng(ikm_e)),
            (enc, ct.clone())
        );
        assert_eq!(*hpke_open(&recipient, &enc, &info, &aad, &ct).unwrap(), pt);

        // Fresh randomness: a different enc each time, still opening.
        let (enc1, ct1) = hpke_seal(&pk_r, &info, &aad, &pt).unwrap();
        let (enc2, _) = hpke_seal(&pk_r, &info, &aad, &pt).unwrap();
        assert_ne!(enc1, enc2);
        assert_eq!(
            *hpke_open(&recipient, &enc1, &info, &aad, &ct1).unwrap(),
            pt
        );

        for (label, result) in [
            ("other info", hpke_open(&recipient, &enc, b"x", &aad, &ct)),
            ("other aad", hpke_open(&recipient, &enc, &info, b"x", &ct)),
            (
                "short enc",
                hpke_open(&recipient, &enc[..31], &info, &aad, &ct),
            ),
            (
                "other key",
                hpke_open(
                    &X25519PrivateKey::from_bytes([1; 32]),
                    &enc,
                    &info,
                    &aad,
                    &ct,
                ),
            ),
        ] {
            let err = result.unwrap_err();
            assert_eq!(err, Error::HpkeOpenFailed, "{label}");
            assert!(err.is_client_local(), "{label}");
        }
    }

    #[test]
    fn ed25519_matches_rfc8032_test_1() {
        let key = Ed25519SigningKey::from_seed(&hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let (public, signature) = rfc8032_test_1();
        assert_eq!(key.public_key(), public);
        assert_eq!(key.sign(b""), signature);
        assert_eq!(ed25519_verify_strict(&public, b"", &signature), Ok(()));
        assert_eq!(
            ed25519_verify_strict(&public, b"x", &signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn strict_verification_rejects_a_small_order_key() {
        // The identity point as public key and R, with S = 0, satisfies the
        // lenient equation for every message.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&identity);
        assert!(ed25519_verify_lenient(
            &identity,
            b"any message",
            &signature
        ));
        assert_eq!(
            ed25519_verify_strict(&identity, b"any message", &signature),
            Err(Error::SignatureInvalid)
        );
    }

    /// RFC 8032 test 1: secret key, public key and the signature of "".
    fn rfc8032_test_1() -> ([u8; 32], [u8; 64]) {
        let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555",
            "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        (public, signature)
    }

    #[test]
    fn strict_verification_rejects_s_not_below_l() {
        // §10.5.1 rule 1: S + L is the same scalar mod L but not < L.
        let (public, mut signature) = rfc8032_test_1();
        let l: [u8; 32] = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for (s, l) in signature[32..].iter_mut().zip(l) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(
            ed25519_verify_strict(&public, b"", &signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn public_keys_must_be_canonical_and_not_of_small_order() {
        let (public, _) = rfc8032_test_1();
        assert_eq!(ed25519_public_key_check(&public), Ok(()));

        // §10.5.1 rule 2: y + p for a small y encodes the same y modulo p.
        // At least one such encoding decodes to a point that is not of
        // small order; the decoder accepts it, the check does not.
        let mut found = 0;
        for y in 0u8..19 {
            // p = 2^255 - 19, so y + p = 2^255 - 19 + y < 2^255.
            let mut bytes = [0xffu8; 32];
            bytes[31] = 0x7f;
            bytes[0] = 0xed + y;
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&bytes) else {
                continue;
            };
            if key.is_weak() {
                continue;
            }
            assert_eq!(
                ed25519_public_key_check(&bytes),
                Err(Error::SignatureInvalid),
                "y = p + {y}"
            );
            found += 1;
        }
        assert!(
            found > 0,
            "no non-canonical encoding of a large-order point"
        );

        // Rule 3: the neutral element and an order-4 point.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            ed25519_public_key_check(&identity),
            Err(Error::SignatureInvalid)
        );
        assert_eq!(
            ed25519_public_key_check(&[0; 32]),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn x25519_matches_rfc7748_section_6_1() {
        let alice = X25519PrivateKey::from_bytes(hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        assert_eq!(
            alice.public_key(),
            hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    #[test]
    fn private_keys_do_not_print() {
        let key = Ed25519SigningKey::from_seed(&[7; 32]);
        assert_eq!(format!("{key:?}"), "Ed25519SigningKey(<redacted>)");
        let key = X25519PrivateKey::from_bytes([7; 32]);
        assert_eq!(format!("{key:?}"), "X25519PrivateKey(<redacted>)");
    }
}
