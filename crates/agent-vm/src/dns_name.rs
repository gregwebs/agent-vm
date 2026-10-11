//! Shared ASCII DNS label shape; permission semantics belong to callers.
use vstd::prelude::*;

verus! {
pub(crate) const MAX_HOST_BYTES: usize = 253;
pub(crate) const MAX_LABEL_BYTES: usize = 63;

/// An accepted DNS label byte: lowercase letter, digit or `-`.
///
/// Written out flat so the executable scanner can restate the expression exactly.
pub(crate) open spec fn ldh_byte_allowed(byte: u8) -> bool {
    (b'a' <= byte && byte <= b'z') || (b'0' <= byte && byte <= b'9') || byte == b'-'
}

/// Whether `bytes[i..]` continues a valid LDH host given the scanner state:
/// `label_len` bytes into the current label, and `prev_dash` whether the byte
/// just consumed was `-`. At the end of the input the final label must be
/// complete (non-empty, <= [`MAX_LABEL_BYTES`]) and must not end in `-`.
///
/// This is the byte-exact kernel of [`ldh_host_bytes`]; the
/// canonicalization and permission-specific policy checks stay with the callers.
pub(crate) open spec fn host_prefix_ok(
    bytes: Seq<u8>,
    i: int,
    label_len: int,
    prev_dash: bool,
) -> bool
    decreases bytes.len() - i,
{
    if i >= bytes.len() {
        label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
    } else if bytes[i] == b'.' {
        label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
            && host_prefix_ok(bytes, i + 1, 0, false)
    } else {
        ldh_byte_allowed(bytes[i])
            && !(label_len == 0 && bytes[i] == b'-')
            && label_len < MAX_LABEL_BYTES
            && host_prefix_ok(bytes, i + 1, label_len + 1, bytes[i] == b'-')
    }
}

/// The LDH *byte shape* of a canonical DNS name: non-empty, <= 253 bytes,
/// only `[a-z0-9.-]`, no trailing dot, and non-empty labels of <= 63 bytes that
/// neither start nor end with `-`.
pub(crate) open spec fn ldh_host_spec(bytes: Seq<u8>) -> bool {
    1 <= bytes.len() && bytes.len() <= MAX_HOST_BYTES && host_prefix_ok(bytes, 0, 0, false)
}

// The recursive body mirrors `host_prefix_ok` clause for clause, so the
// postcondition is definitional; the value is that the accepted language is
// *specified* and the executable form cannot drift from it silently.
#[allow(clippy::manual_range_contains)]
fn host_prefix_ok_exec(
    bytes: &[u8],
    i: usize,
    label_len: usize,
    prev_dash: bool,
) -> (ok: bool)
    ensures ok == host_prefix_ok(bytes@, i as int, label_len as int, prev_dash),
    decreases bytes.len() - i,
{
    if i >= bytes.len() {
        label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
    } else {
        let byte = bytes[i];
        if byte == b'.' {
            label_len >= 1 && label_len <= MAX_LABEL_BYTES && !prev_dash
                && host_prefix_ok_exec(bytes, i + 1, 0, false)
        } else {
            let allowed = (b'a' <= byte && byte <= b'z')
                || (b'0' <= byte && byte <= b'9')
                || byte == b'-';
            assert(allowed == ldh_byte_allowed(byte));
            allowed
                && !(label_len == 0 && byte == b'-')
                && label_len < MAX_LABEL_BYTES
                && host_prefix_ok_exec(bytes, i + 1, label_len + 1, byte == b'-')
        }
    }
}

#[allow(clippy::len_zero)]
pub(crate) fn ldh_host_bytes(bytes: &[u8]) -> (ok: bool)
    ensures ok == ldh_host_spec(bytes@),
{
    1 <= bytes.len() && bytes.len() <= MAX_HOST_BYTES && host_prefix_ok_exec(bytes, 0, 0, false)
}

}
