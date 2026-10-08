//! Shared helpers of the admission fuzz targets: the corpus identities,
//! the record format the stateful targets read, chunk re-framing and the
//! panic policy.
//!
//! Record format (`objects_admission`, `sections_receive`): a sequence of
//! records, each `[ctl: u8][len: u16 LE][len bytes]`, delivered in order to
//! one replica. A truncated last record is dropped. `ctl`:
//!
//! - bits 0-1: the signer, an index into the target's corpus Principals
//!   (3 is a Principal of no corpus);
//! - bit 2: the bytes are `[chunk type][chunk body]`, and the harness
//!   writes the chunk header (magic, checksum, length) around them, so a
//!   mutated body still reaches the checks behind the checksum;
//! - bit 3: the bytes are the chunk alone, and the harness frames it as
//!   `[1, bstr]` (§11); otherwise they are the whole plaintext;
//! - bit 4 (`objects_admission` only): apply through
//!   `SharedObjects::apply_change` (origin established) instead of
//!   `apply_unit_change`.

use std::panic;
use std::sync::Once;

use lfcp::base::{PrincipalId, ResourceId};
use sha2::{Digest, Sha256};

/// SHARED-OBJECTS-TEST-VECTORS-01 `fixtures`: `resource_a_hex` and the
/// Principals andrey, pavel and masha (spec at the `spec.lock` pin).
pub const OBJECTS_RESOURCE: &str =
    "1081b3b99d4f5d39d86d07bef0849a9ba40f00d0ca9a295a51f0fa65500f9f84";
pub const OBJECTS_PRINCIPALS: [&str; 3] = [
    "bd07952a86218f6f57a360520c0403acd3c72f275907e8cb38a3d6362ab4c9f4",
    "eba658a7f4d1ccadd2d2e46658c853a0b19fe587f355e8845f170d248ac2bbea",
    "1b1c18c7dde569d5415f7263ea1ad444d6add0f04f4044bea67894a8161d71e6",
];

/// SHARED-SECTIONS-TEST-VECTORS-01 `identities`: the Resource and the
/// Principals A, B and C.
pub const SECTIONS_RESOURCE: &str =
    "2d6075739e9fd23b2cb6aad58c26f790a9a263d2bfef08a0f8eb46c0ee8421fa";
pub const SECTIONS_PRINCIPALS: [&str; 3] = [
    "3ae3393c151002986f841515ad299c1ba197e9c7800ccc670c61574040b13b05",
    "e8481983fae0acc7bc2388601090f328f1d3db80b8ace898a2d6cb1a8d2ccec1",
    "c67ab66de9eb58dea7e786446b71d326ed98f091106734e120a31290bf8cf011",
];

/// A Principal of no corpus.
const STRANGER: [u8; 32] = [0x5a; 32];

/// At most this many records are read from one input.
pub const MAX_RECORDS: usize = 48;

pub const CTL_REFRAME: u8 = 1 << 2;
pub const CTL_FRAME: u8 = 1 << 3;
pub const CTL_ORIGIN_ESTABLISHED: u8 = 1 << 4;

fn id32(hex: &str) -> [u8; 32] {
    lfcp::base::fixed(&lfcp::base::from_hex(hex).expect("hex")).expect("32 bytes")
}

pub fn resource(hex: &str) -> ResourceId {
    ResourceId::from_bytes(id32(hex))
}

/// The signer named by `ctl`'s low two bits.
pub fn signer(principals: &[&str; 3], ctl: u8) -> PrincipalId {
    match ctl & 3 {
        3 => PrincipalId::from_bytes(STRANGER),
        i => PrincipalId::from_bytes(id32(principals[usize::from(i)])),
    }
}

/// One record of the input.
pub struct Record<'a> {
    pub ctl: u8,
    pub bytes: &'a [u8],
}

/// The records of `data`.
pub fn records(mut data: &[u8]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    while data.len() >= 3 && out.len() < MAX_RECORDS {
        let ctl = data[0];
        let len = usize::from(u16::from_le_bytes([data[1], data[2]]));
        let Some(bytes) = data.get(3..3 + len) else {
            break;
        };
        out.push(Record { ctl, bytes });
        data = &data[3 + len..];
    }
    out
}

/// The record encoding of `(ctl, bytes)`, for seeds and reproducers.
pub fn encode_record(ctl: u8, bytes: &[u8]) -> Vec<u8> {
    let len = u16::try_from(bytes.len()).expect("a record holds at most 64 KiB");
    let mut out = vec![ctl];
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn uleb(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// An Automerge chunk of type `chunk_type` around `body`, with the right
/// length and checksum (the first four bytes of the SHA-256 of type,
/// length and body).
pub fn chunk(chunk_type: u8, body: &[u8]) -> Vec<u8> {
    let mut hashed = vec![chunk_type];
    uleb(body.len() as u64, &mut hashed);
    hashed.extend_from_slice(body);
    let checksum = Sha256::digest(&hashed);
    let mut out = vec![0x85, 0x6f, 0x4a, 0x83];
    out.extend_from_slice(&checksum[..4]);
    out.extend_from_slice(&hashed);
    out
}

/// `[1, bstr]` around `payload` (§11, §13).
pub fn frame(payload: &[u8]) -> Vec<u8> {
    lfcp::shared_objects::framing::encode_change(payload)
}

/// The plaintext a record stands for.
pub fn plaintext(record: &Record<'_>) -> Vec<u8> {
    let bytes = if record.ctl & CTL_REFRAME != 0 {
        match record.bytes.split_first() {
            Some((&t, body)) => chunk(t, body),
            None => Vec::new(),
        }
    } else {
        record.bytes.to_vec()
    };
    if record.ctl & (CTL_FRAME | CTL_REFRAME) != 0 {
        frame(&bytes)
    } else {
        bytes
    }
}

static PANIC_POLICY: Once = Once::new();

/// libfuzzer-sys aborts on every panic, also one the library catches as
/// defense in depth (`load_guarded`, `engine_apply`). By default the
/// targets restore a hook that only prints, so a contained engine panic
/// is not a crash: an uncaught panic still reaches libfuzzer-sys's
/// `catch_unwind` and aborts. `LFCP_FUZZ_STRICT=1` keeps abort-on-any-panic
/// to find the contained ones.
pub fn panic_policy() {
    PANIC_POLICY.call_once(|| {
        if std::env::var_os("LFCP_FUZZ_STRICT").is_none() {
            let _ = panic::take_hook();
            panic::set_hook(Box::new(|info| {
                if std::env::var_os("LFCP_FUZZ_QUIET").is_none() {
                    eprintln!("panic (contained unless an abort follows): {info}");
                }
            }));
        }
    });
}

/// Finding F2: `framing::decode_change` panics inside
/// `automerge::Change::from_bytes` on a change whose object or operation
/// counter does not fit in 32 bits (automerge 0.12 `OpId::new` unwraps),
/// a panic nothing catches. Every target decodes first, so the targets
/// skip such a plaintext until the fix lands; `LFCP_FUZZ_F2=1` delivers it.
pub fn known_f2(plaintext: &[u8]) -> bool {
    if std::env::var_os("LFCP_FUZZ_F2").is_some() {
        return false;
    }
    panic::catch_unwind(|| lfcp::shared_objects::framing::decode_change(plaintext)).is_err()
}

/// Finding F3: admission accepts a change Automerge applies but cannot
/// reproduce from the document, and the document's save then fails to load
/// ("mismatching heads", "missing ops") or makes the load panic: a
/// non-canonical change (a column with more rows than operations), an
/// operation whose predecessor is an operation on another key or list
/// element, a delete without a predecessor, or a change without operations
/// whose start op is not its actor's next. The admission
/// target skips that failure until the fix lands; `LFCP_FUZZ_F3=1` reports
/// it.
pub fn known_f3(save: &[u8]) -> bool {
    if std::env::var_os("LFCP_FUZZ_F3").is_some() {
        return false;
    }
    !matches!(
        panic::catch_unwind(|| automerge::AutoCommit::load(save).is_ok()),
        Ok(true)
    )
}

/// Finding F4: on a document holding such a change (F3, a predecessor on
/// another key), `SharedObjects::changes` (`AutoCommit::get_changes`)
/// panics in Automerge's change collector, a panic nothing catches. The
/// admission target stops a run there until the fix lands;
/// `LFCP_FUZZ_F4=1` lets the panic through.
pub fn known_f4<T>(read: impl FnOnce() -> T) -> Option<T> {
    if std::env::var_os("LFCP_FUZZ_F4").is_some() {
        return Some(read());
    }
    panic::catch_unwind(panic::AssertUnwindSafe(read)).ok()
}

/// F4 on a Shared Sections replica: once it holds a change of F3, a later
/// `SectionsReplica::receive` can panic in Automerge (`get_change_by_hash`,
/// "MissingOps"). Runs `read` on `state`; a panic is known, and `None`,
/// only when the document `doc` reads from `state` then no longer saves to
/// a loadable image (the replica is poisoned). Any other panic goes on.
/// `LFCP_FUZZ_F4=1` lets every panic through.
pub fn guarded<S, T>(
    state: &mut S,
    read: impl FnOnce(&mut S) -> T,
    doc: impl FnOnce(&S) -> automerge::AutoCommit,
) -> Option<T> {
    if std::env::var_os("LFCP_FUZZ_F4").is_some() {
        return Some(read(state));
    }
    match panic::catch_unwind(panic::AssertUnwindSafe(|| read(&mut *state))) {
        Ok(value) => Some(value),
        Err(payload) => {
            let save = doc(state).save();
            if known_f3(&save) {
                None
            } else {
                panic::resume_unwind(payload)
            }
        }
    }
}
