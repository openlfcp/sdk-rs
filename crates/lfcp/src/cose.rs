//! Canonical COSE_Sign1 signed objects (LFCP-WIRE-01 §10).
//!
//! Every persistent LFCP signed object has exactly this shape, with no
//! enclosing CBOR tag:
//!
//! ```text
//! [ h'<deterministic {1: -8, 4: kid}>', {}, h'<deterministic payload>', h'<64-byte signature>' ]
//! ```
//!
//! The signature is Ed25519 over the deterministic `Sig_structure`
//! `["Signature1", protected, h'', payload]` (§10.4, §10.5). The object ID is
//! SHA-256 of the exact object bytes (§10.6).
//!
//! [`parse`] keeps the exact received bytes. Hashing and verification use
//! those bytes and the exact protected-header and payload byte strings;
//! nothing is re-encoded for them. Re-encoding happens only inside the
//! determinism checks (§5.2, N7), which compare and never substitute.

use crate::base::{Error, Hash32, PrincipalId};
use crate::cbor::{self, Value};
use crate::crypto;
use crate::principal::{PrincipalDescriptor, PrincipalKeys};

/// COSE algorithm identifier for EdDSA (RFC 9053), encoded as -8.
const ALG_EDDSA: i64 = -8;
/// Protected header label `alg`.
const LABEL_ALG: u64 = 1;
/// Protected header label `kid`.
const LABEL_KID: u64 = 4;

/// A canonical signed object, with the parts and ID taken from its exact
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedObject {
    bytes: Vec<u8>,
    protected: Vec<u8>,
    payload: Vec<u8>,
    payload_value: Value,
    signature: [u8; 64],
    kid: PrincipalId,
    id: Hash32,
}

impl SignedObject {
    /// The exact COSE_Sign1 bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The exact protected-header byte string contents.
    pub fn protected_bytes(&self) -> &[u8] {
        &self.protected
    }

    /// The exact payload byte string contents.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// The decoded payload. Its encoding is exactly
    /// [`payload_bytes`](Self::payload_bytes).
    pub fn payload(&self) -> &Value {
        &self.payload_value
    }

    /// The 64-byte Ed25519 signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The `kid`: the Principal ID of the signer the object names.
    pub fn kid(&self) -> &PrincipalId {
        &self.kid
    }

    /// The object ID: SHA-256 of the exact bytes (§10.6).
    pub fn id(&self) -> &Hash32 {
        &self.id
    }

    /// The deterministic `Sig_structure` bytes this object's signature
    /// covers.
    pub fn sig_structure(&self) -> Vec<u8> {
        sig_structure(&self.protected, &self.payload)
    }
}

/// The deterministic encoding of the protected header for `kid` (§10.1).
pub fn protected_header(kid: &PrincipalId) -> Vec<u8> {
    let header = Value::Map(vec![
        (Value::Unsigned(LABEL_ALG), Value::int(ALG_EDDSA)),
        (
            Value::Unsigned(LABEL_KID),
            Value::bytes(kid.as_bytes().to_vec()),
        ),
    ]);
    cbor::encode(&header).expect("the protected header is always encodable")
}

/// The deterministic `Sig_structure` over exact protected-header and
/// payload bytes, with empty external AAD (§10.4, §10.5).
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = Value::Array(vec![
        Value::text("Signature1"),
        Value::bytes(protected.to_vec()),
        Value::bytes(Vec::new()),
        Value::bytes(payload.to_vec()),
    ]);
    cbor::encode(&structure).expect("a Sig_structure is always encodable")
}

/// Sign `payload` as `signer` and build the canonical object.
///
/// The payload must already be deterministic CBOR (§10.3); other bytes are
/// refused rather than re-encoded, so the caller's bytes are the signed
/// bytes. The signer's keys and descriptor come together in
/// [`PrincipalKeys`], so the `kid` always matches the signing key.
pub fn sign(payload: &[u8], signer: &PrincipalKeys) -> Result<SignedObject, Error> {
    let payload_value = cbor::check_deterministic(payload)?;
    let kid = *signer.descriptor().id();
    let protected = protected_header(&kid);
    let signature = signer
        .signing_key()
        .sign(&sig_structure(&protected, payload));
    let object = Value::Array(vec![
        Value::bytes(protected.clone()),
        Value::Map(Vec::new()),
        Value::bytes(payload.to_vec()),
        Value::bytes(signature.to_vec()),
    ]);
    let bytes = cbor::encode(&object)?;
    Ok(SignedObject {
        id: crypto::sha256(&bytes),
        bytes,
        protected,
        payload: payload.to_vec(),
        payload_value,
        signature,
        kid,
    })
}

/// Parse received bytes as a canonical signed object.
///
/// Checks the structure only; call [`verify`] for the signature. Rejects a
/// tagged object, anything other than the §10 four-element shape, a
/// protected header other than `{1: -8, 4: kid}`, a non-empty unprotected
/// header, an absent payload, a signature that is not 64 bytes, and object,
/// protected-header or payload bytes that are not deterministic CBOR.
pub fn parse(bytes: &[u8]) -> Result<SignedObject, Error> {
    // Major type 6 is a tag; tag 18 is the COSE_Sign1 tag that LFCP forbids.
    if bytes.first().is_some_and(|initial| initial >> 5 == 6) {
        return Err(Error::CoseTagged);
    }
    let object = cbor::decode_strict(bytes)?;
    let [protected, unprotected, payload, signature] = object
        .as_array()
        .and_then(|items| <&[Value; 4]>::try_from(items).ok())
        .ok_or(Error::CoseMalformed)?;

    let protected = protected.as_bytes().ok_or(Error::CoseMalformed)?;
    match unprotected.as_map() {
        Some([]) => {}
        Some(_) => return Err(Error::CoseUnprotectedNotEmpty),
        None => return Err(Error::CoseMalformed),
    }
    let payload = match payload {
        Value::Bytes(bytes) => bytes,
        Value::Null => return Err(Error::CosePayloadAbsent),
        _ => return Err(Error::CoseMalformed),
    };
    let signature: [u8; 64] = signature
        .as_bytes()
        .ok_or(Error::CoseMalformed)?
        .try_into()
        .map_err(|_| Error::CoseSignatureLength)?;

    let kid = parse_protected_header(protected)?;
    let payload_value = cbor::check_deterministic(payload)?;

    Ok(SignedObject {
        id: crypto::sha256(bytes),
        bytes: bytes.to_vec(),
        protected: protected.to_vec(),
        payload: payload.clone(),
        payload_value,
        signature,
        kid,
    })
}

/// Check the protected header bytes (§5.2 N7, §10.1) and return the `kid`.
fn parse_protected_header(protected: &[u8]) -> Result<PrincipalId, Error> {
    let header = cbor::check_deterministic(protected)?;
    let entries = header.as_map().ok_or(Error::CoseProtectedHeader)?;
    let alg = header.get_uint(LABEL_ALG);
    let kid = header.get_uint(LABEL_KID).and_then(Value::as_bytes);
    match (entries.len(), alg, kid) {
        (2, Some(alg), Some(kid)) if *alg == Value::int(ALG_EDDSA) => {
            PrincipalId::from_slice(kid).map_err(|_| Error::CoseProtectedHeader)
        }
        _ => Err(Error::CoseProtectedHeader),
    }
}

/// Verify `object` as signed by `signer`, the Principal the object requires
/// as signer (for example, the actor of a Data Unit).
///
/// Fails with [`Error::CoseKidMismatch`] when the `kid` names another
/// Principal, and with [`Error::SignatureInvalid`] when the signature does
/// not verify under the signer's key. Both are `INVALID_SIGNATURE` on the
/// wire (§10.5).
pub fn verify(object: &SignedObject, signer: &PrincipalDescriptor) -> Result<(), Error> {
    if object.kid != *signer.id() {
        return Err(Error::CoseKidMismatch);
    }
    crypto::ed25519_verify_strict(
        signer.ed25519_public(),
        &object.sig_structure(),
        &object.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[n; 32], [n.wrapping_add(100); 32])
    }

    fn payload() -> Vec<u8> {
        cbor::encode(&Value::Map(vec![(Value::Unsigned(0), Value::text("hi"))])).unwrap()
    }

    /// Re-encode a signed object with one of its four parts replaced.
    fn with_part(object: &SignedObject, index: usize, part: Value) -> Vec<u8> {
        let mut parts = cbor::decode_strict(object.bytes())
            .unwrap()
            .as_array()
            .unwrap()
            .to_vec();
        parts[index] = part;
        cbor::encode(&Value::Array(parts)).unwrap()
    }

    #[test]
    fn sign_parse_verify_round_trip() {
        let signer = keys(1);
        let signed = sign(&payload(), &signer).unwrap();
        let parsed = parse(signed.bytes()).unwrap();
        assert_eq!(parsed, signed);
        assert_eq!(parsed.id(), &crypto::sha256(signed.bytes()));
        assert_eq!(parsed.kid(), signer.descriptor().id());
        assert_eq!(verify(&parsed, signer.descriptor()), Ok(()));
        assert_eq!(
            verify(&parsed, keys(2).descriptor()),
            Err(Error::CoseKidMismatch)
        );
    }

    #[test]
    fn sign_refuses_non_deterministic_payload() {
        assert_eq!(
            sign(&[0x18, 0x01], &keys(1)).unwrap_err(),
            Error::CborNotDeterministic
        );
    }

    #[test]
    fn verify_rejects_a_changed_signature() {
        let signer = keys(1);
        let mut object = sign(&payload(), &signer).unwrap();
        object.signature[0] ^= 1;
        assert_eq!(
            verify(&object, signer.descriptor()),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn parse_rejects_non_canonical_shapes() {
        let signer = keys(1);
        let object = sign(&payload(), &signer).unwrap();
        let kid = Value::bytes(signer.descriptor().id().as_bytes().to_vec());
        let header = |entries: Vec<(Value, Value)>| {
            Value::bytes(cbor::encode(&Value::Map(entries)).unwrap())
        };
        let alg = (Value::Unsigned(1), Value::int(-8));
        let kid_entry = (Value::Unsigned(4), kid.clone());

        let mut tagged = vec![0xd2];
        tagged.extend_from_slice(object.bytes());
        let mut three = cbor::decode_strict(object.bytes())
            .unwrap()
            .as_array()
            .unwrap()
            .to_vec();
        three.pop();

        let cases: Vec<(&str, Vec<u8>, Error)> = vec![
            ("tag 18", tagged, Error::CoseTagged),
            (
                "three elements",
                cbor::encode(&Value::Array(three)).unwrap(),
                Error::CoseMalformed,
            ),
            (
                "unprotected not empty",
                with_part(
                    &object,
                    1,
                    Value::Map(vec![(Value::Unsigned(4), kid.clone())]),
                ),
                Error::CoseUnprotectedNotEmpty,
            ),
            (
                "detached payload",
                with_part(&object, 2, Value::Null),
                Error::CosePayloadAbsent,
            ),
            (
                "short signature",
                with_part(&object, 3, Value::bytes(vec![0; 63])),
                Error::CoseSignatureLength,
            ),
            (
                "protected not a bstr",
                with_part(&object, 0, Value::Map(vec![alg.clone()])),
                Error::CoseMalformed,
            ),
            (
                "alg -7",
                with_part(
                    &object,
                    0,
                    header(vec![
                        (Value::Unsigned(1), Value::int(-7)),
                        kid_entry.clone(),
                    ]),
                ),
                Error::CoseProtectedHeader,
            ),
            (
                "no kid",
                with_part(&object, 0, header(vec![alg.clone()])),
                Error::CoseProtectedHeader,
            ),
            (
                "extra protected parameter",
                with_part(
                    &object,
                    0,
                    header(vec![
                        alg.clone(),
                        kid_entry.clone(),
                        (Value::Unsigned(3), Value::Unsigned(0)),
                    ]),
                ),
                Error::CoseProtectedHeader,
            ),
            (
                "31-byte kid",
                with_part(
                    &object,
                    0,
                    header(vec![
                        alg.clone(),
                        (Value::Unsigned(4), Value::bytes(vec![0; 31])),
                    ]),
                ),
                Error::CoseProtectedHeader,
            ),
            (
                "non-deterministic protected header",
                with_part(
                    &object,
                    0,
                    Value::bytes(
                        [
                            &[0xa2, 0x18, 0x01][..],
                            &[0x27, 0x04, 0x58, 0x20],
                            signer.descriptor().id().as_bytes(),
                        ]
                        .concat(),
                    ),
                ),
                Error::CborNotDeterministic,
            ),
            (
                "non-deterministic payload",
                with_part(&object, 2, Value::bytes(vec![0x18, 0x05])),
                Error::CborNotDeterministic,
            ),
            (
                "payload not CBOR",
                with_part(&object, 2, Value::bytes(vec![0xff])),
                Error::CborReserved,
            ),
            (
                "trailing bytes",
                [object.bytes(), &[0]].concat(),
                Error::CborTrailingBytes,
            ),
        ];
        for (name, bytes, expected) in cases {
            assert_eq!(parse(&bytes), Err(expected), "{name}");
        }
    }
}
