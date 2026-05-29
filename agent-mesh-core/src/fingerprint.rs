//! BLAKE3-based fingerprint for keys and content-addressed payloads.
//!
//! A `Fingerprint` is just the 32-byte BLAKE3 hash of some canonical
//! byte representation (typically a 32-byte ed25519 public key, but
//! also used for envelope payloads). It's small, equality-comparable,
//! and prints as a short hex prefix suitable for log lines.

use crate::MeshError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte BLAKE3 hash, used as the canonical ID for keys and
/// content-addressed blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    /// Hash an arbitrary byte slice with BLAKE3, returning the
    /// resulting fingerprint.
    #[must_use]
    pub fn of_bytes(data: &[u8]) -> Self {
        let h = blake3::hash(data);
        Self(*h.as_bytes())
    }

    /// 12-character hex prefix, suitable for human display in log
    /// lines and CLI output. Six bytes is enough collision resistance
    /// to disambiguate hundreds of agents on a single user.
    #[must_use]
    pub fn short(&self) -> String {
        hex::encode(&self.0[..6])
    }

    /// Full 64-character hex encoding.
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl std::str::FromStr for Fingerprint {
    type Err = MeshError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| MeshError::Encoding(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(MeshError::Encoding(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn short_truncates_to_12_hex_chars() {
        let fp = Fingerprint::of_bytes(b"hello world");
        let s = fp.short();
        assert_eq!(s.len(), 12, "short should be 12 hex chars (6 bytes)");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn roundtrip_hex() {
        let fp = Fingerprint::of_bytes(b"some bytes");
        let h = fp.hex();
        assert_eq!(h.len(), 64);
        let parsed = Fingerprint::from_str(&h).expect("parse roundtrip");
        assert_eq!(fp, parsed);
    }

    #[test]
    fn equality() {
        let a = Fingerprint::of_bytes(b"x");
        let b = Fingerprint::of_bytes(b"x");
        let c = Fingerprint::of_bytes(b"y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn from_str_rejects_wrong_length() {
        let err = Fingerprint::from_str("deadbeef").expect_err("too short");
        match err {
            MeshError::Encoding(_) => {}
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[test]
    fn from_str_rejects_non_hex() {
        let err = Fingerprint::from_str("zz").expect_err("not hex");
        match err {
            MeshError::Encoding(_) => {}
            other => panic!("expected Encoding, got {other:?}"),
        }
    }

    #[test]
    fn display_matches_short() {
        let fp = Fingerprint::of_bytes(b"display test");
        assert_eq!(format!("{fp}"), fp.short());
    }

    #[test]
    fn debug_does_not_panic() {
        let fp = Fingerprint::of_bytes(b"debug");
        let _ = format!("{fp:?}");
    }

    #[test]
    fn hash_in_collection() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Fingerprint::of_bytes(b"a"));
        set.insert(Fingerprint::of_bytes(b"a"));
        set.insert(Fingerprint::of_bytes(b"b"));
        assert_eq!(set.len(), 2);
    }
}
