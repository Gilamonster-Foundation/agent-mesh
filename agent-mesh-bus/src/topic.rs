//! [`Topic`] — a user-scoped pub/sub name.
//!
//! Topics are namespaced under the issuing user's pubkey fingerprint
//! so two unrelated users running buses on the same LAN can never
//! collide on a topic name. The wire form is
//! `"<user_fp_hex>:<name>"`; the user-fingerprint prefix is the
//! same auto-team root the transport handshake enforces, so a "topic
//! foo" from a peer outside our user can never address a topic foo
//! we've subscribed to.

use agent_mesh_core::Fingerprint;
use std::fmt;
use std::str::FromStr;

/// A user-scoped topic name.
///
/// Wire form: `"<user_fp_hex>:<name>"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic {
    /// Fingerprint of the user pubkey this topic belongs to. Two
    /// different users' "echo" topics are distinct.
    pub user_fp: Fingerprint,
    /// Application-chosen name. May contain colons; only the FIRST
    /// colon is the separator from the user prefix.
    pub name: String,
}

impl Topic {
    /// Construct a topic from a user fingerprint + name.
    #[must_use]
    pub fn new(user_fp: Fingerprint, name: impl Into<String>) -> Self {
        Self {
            user_fp,
            name: name.into(),
        }
    }

    /// Wire-form representation: `"<user_fp_hex>:<name>"`.
    #[must_use]
    pub fn wire(&self) -> String {
        format!("{}:{}", self.user_fp.hex(), self.name)
    }

    /// Inverse of [`Self::wire`].
    ///
    /// Returns `None` if `s` is missing the `:` separator, or if the
    /// prefix isn't a valid fingerprint. The name half is everything
    /// after the FIRST `:`, so topic names may themselves contain
    /// colons.
    #[must_use]
    pub fn parse_wire(s: &str) -> Option<Self> {
        let (fp_str, name) = s.split_once(':')?;
        let user_fp = Fingerprint::from_str(fp_str).ok()?;
        Some(Self {
            user_fp,
            name: name.to_string(),
        })
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.wire())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp_of(seed: u8) -> Fingerprint {
        Fingerprint([seed; 32])
    }

    #[test]
    fn wire_format_roundtrip() {
        let t = Topic::new(fp_of(1), "echo");
        let s = t.wire();
        let back = Topic::parse_wire(&s).expect("parse roundtrip");
        assert_eq!(back, t);
    }

    #[test]
    fn different_users_different_wire() {
        let a = Topic::new(fp_of(1), "echo");
        let b = Topic::new(fp_of(2), "echo");
        assert_ne!(a.wire(), b.wire());
        // The name half is identical; only the user prefix differs.
        assert!(a.wire().ends_with(":echo"));
        assert!(b.wire().ends_with(":echo"));
    }

    #[test]
    fn parse_rejects_malformed() {
        // No colon → no separator.
        assert!(Topic::parse_wire("notopic").is_none());
        // Empty user prefix → invalid fingerprint.
        assert!(Topic::parse_wire(":echo").is_none());
        // Non-hex prefix → invalid fingerprint.
        assert!(Topic::parse_wire("zz:echo").is_none());
    }

    #[test]
    fn display_matches_wire() {
        let t = Topic::new(fp_of(7), "drake/work");
        assert_eq!(format!("{t}"), t.wire());
    }

    #[test]
    fn name_may_contain_colons() {
        // Only the FIRST colon is structural. A name like
        // "namespace:sub" should survive the wire roundtrip.
        let t = Topic::new(fp_of(3), "namespace:sub");
        let back = Topic::parse_wire(&t.wire()).expect("parse");
        assert_eq!(back.name, "namespace:sub");
    }

    #[test]
    fn empty_name_is_allowed() {
        let t = Topic::new(fp_of(4), "");
        let back = Topic::parse_wire(&t.wire()).expect("parse");
        assert_eq!(back.name, "");
    }

    #[test]
    fn topic_hashes_with_user_and_name() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Topic::new(fp_of(1), "echo"));
        set.insert(Topic::new(fp_of(1), "echo"));
        set.insert(Topic::new(fp_of(2), "echo"));
        set.insert(Topic::new(fp_of(1), "other"));
        assert_eq!(set.len(), 3);
    }
}
