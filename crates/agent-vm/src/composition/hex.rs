//! Lowercase hex encoding without a new dependency: `sha2` already gives us
//! `GenericArray` output, and the hex alphabet is trivial to hand-roll. Kept
//! as one shared helper rather than a private copy per caller — the v1 chain
//! encoder, the context enumeration and (from the next commit) the v2
//! identity encoders all need exactly these bytes.

pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
