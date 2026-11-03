//! Allocation-free schema bounds before the ordinary CBOR/COSE decoder.
//! All helpers borrow slices; no advertised length is used to allocate.

use super::{
    CERTIFICATE_DOMAIN, DEVICE_MANAGE, MAX_CHAIN_DEPTH, MAX_MANAGING_DEPTH, MAX_MASK_ENTRIES,
    MAX_SCOPE_ENTRIES, OWNER_ACT,
};
use crate::base::Error;
use crate::cbor::scan::Reader;

const MALFORMED: Error = Error::DeviceCertificateMalformed;

fn fixed_bytes(reader: &mut Reader<'_>, len: usize) -> Result<(), Error> {
    if reader.bytes(2)?.len() == len {
        Ok(())
    } else {
        Err(MALFORMED)
    }
}

fn count(reader: &mut Reader<'_>, major: u8, min: usize, max: usize) -> Result<usize, Error> {
    let (kind, n) = reader.head()?;
    if kind != major || n < min as u64 || n > max as u64 {
        return Err(MALFORMED);
    }
    Ok(n as usize)
}

fn signed_payload(bytes: &[u8]) -> Result<&[u8], Error> {
    let mut object = Reader::new(bytes);
    object.expect(4, 4)?;
    let mut protected = Reader::new(object.bytes(2)?);
    protected.expect(5, 2)?;
    protected.expect(0, 1)?;
    protected.expect(1, 7)?;
    protected.expect(0, 4)?;
    fixed_bytes(&mut protected, 32)?;
    protected.finish()?;
    object.expect(5, 0)?;
    let payload = object.bytes(2)?;
    fixed_bytes(&mut object, 64)?;
    object.finish()?;
    Ok(payload)
}

pub(super) fn certificate(bytes: &[u8]) -> Result<(), Error> {
    certificate_manages(bytes).map(|_| ())
}

pub(super) fn certificate_manages(bytes: &[u8]) -> Result<bool, Error> {
    let mut payload = Reader::new(signed_payload(bytes)?);
    payload.expect(4, 7)?;
    if payload.bytes(3)? != CERTIFICATE_DOMAIN.as_bytes() {
        return Err(MALFORMED);
    }
    fixed_bytes(&mut payload, 32)?;
    payload.expect(5, 3)?;
    for key in 0..3 {
        payload.expect(0, key)?;
        fixed_bytes(&mut payload, 32)?;
    }
    let kind = count(&mut payload, 0, 0, 2)?;
    let mask_len = count(&mut payload, 4, 1, MAX_MASK_ENTRIES)?;
    let (mut read, mut write, mut manages, mut owner, mut only_read_write) =
        (false, false, false, false, true);
    for _ in 0..mask_len {
        let (major, code) = payload.head()?;
        if major != 0 {
            return Err(MALFORMED);
        }
        read |= code == 1;
        write |= code == 2;
        manages |= code == DEVICE_MANAGE;
        owner |= code == OWNER_ACT;
        only_read_write &= matches!(code, 1 | 2);
    }
    let (min_scope, max_scope) = match kind {
        0 => (0, 0),
        1 => (1, MAX_SCOPE_ENTRIES),
        _ => (1, 1),
    };
    let scope_len = count(&mut payload, 4, min_scope, max_scope)?;
    for _ in 0..scope_len {
        fixed_bytes(&mut payload, 32)?;
    }
    fixed_bytes(&mut payload, 16)?;
    payload.finish()?;
    if (manages && !(read && write))
        || (kind == 1 && (manages || owner))
        || (kind == 2 && !only_read_write)
    {
        return Err(MALFORMED);
    }
    Ok(manages)
}

pub(super) fn chain(bytes: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(bytes);
    let len = count(&mut reader, 4, 1, MAX_CHAIN_DEPTH)?;
    for index in 0..len {
        let manages = certificate_manages(reader.bytes(2)?)?;
        if index == 0 && manages && len > MAX_MANAGING_DEPTH {
            return Err(MALFORMED);
        }
    }
    reader.finish()
}

/// Locate a map field without allocating. Normal decoding subsequently
/// checks closed-map rules, key types, duplicates and ordering.
fn field(bytes: &[u8], key: u64) -> Result<Option<&[u8]>, Error> {
    let mut reader = Reader::new(bytes);
    let (major, len) = reader.head()?;
    if major != 5 {
        return Err(Error::ControlRecordMalformed);
    }
    let mut found = None;
    for _ in 0..len {
        let key_bytes = reader.value_bytes()?;
        let value = reader.value_bytes()?;
        if Reader::new(key_bytes).head()? == (0, key) {
            if found.is_some() {
                return Err(Error::CborDuplicateKey);
            }
            found = Some(value);
        }
    }
    reader.finish()?;
    Ok(found)
}

pub(crate) fn control_record(bytes: &[u8]) -> Result<(), Error> {
    // Preserve the existing COSE parser's diagnostics for malformed outer
    // envelopes. Its payload decoder is reached only for a valid envelope.
    let Ok(payload) = signed_payload(bytes) else {
        return Ok(());
    };
    let Some(control_type) = field(payload, 3)? else {
        return Ok(());
    };
    let (major, control_type) = Reader::new(control_type).head()?;
    if major != 0 {
        return Ok(());
    }
    let chain_key = match control_type {
        0 => 5,
        6 => 2,
        9 => 1,
        _ => return Ok(()),
    };
    if let Some(body) = field(payload, 5)? {
        if let Some(bytes) = field(body, chain_key)? {
            chain(bytes)?;
        }
    }
    Ok(())
}
