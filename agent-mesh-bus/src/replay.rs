//! Replay defense — nonce cache and per-peer sequence tracker.
//!
//! Two complementary checks every incoming envelope passes through:
//!
//! 1. **Nonce cache** ([`NonceCache`]): reject any envelope whose
//!    24-byte nonce we've already seen, regardless of sender. Bounded
//!    by an LRU-style FIFO so the cache cannot grow unbounded under a
//!    flood. The check is in-process state — there's no cross-bus
//!    coordination; a fresh bus starts with an empty cache.
//! 2. **Sequence tracker** ([`SequenceTracker`]): for each sender
//!    fingerprint, remember the highest sequence number we've
//!    accepted. New envelopes must be strictly greater. This catches
//!    replays of (peer, seq) tuples even if they survive the nonce
//!    check (e.g. by coming from a different bus that hadn't seen
//!    them yet).
//!
//! Neither check uses wall-clock time. Both are per-process and
//! best-effort — they raise the bar but don't claim perfection.

use agent_mesh_core::Fingerprint;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

/// Bounded LRU-style nonce cache. Rejects duplicates.
///
/// The capacity is a hard ceiling: when a fresh nonce arrives and the
/// cache is full, the oldest one is evicted. A reasonable default is
/// 4096 — large enough to span any realistic burst, small enough that
/// the memory cost is trivial.
pub struct NonceCache {
    inner: Mutex<NonceInner>,
    capacity: usize,
}

struct NonceInner {
    seen: HashSet<[u8; 24]>,
    order: VecDeque<[u8; 24]>,
}

impl NonceCache {
    /// Build a fresh cache with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(NonceInner {
                seen: HashSet::new(),
                order: VecDeque::new(),
            }),
            capacity,
        }
    }

    /// Check + insert in one atomic step.
    ///
    /// Returns `true` if the nonce is new (and was inserted). Returns
    /// `false` if it was already in the cache (i.e. duplicate; the
    /// caller should reject the envelope).
    pub fn check_and_insert(&self, nonce: [u8; 24]) -> bool {
        let mut inner = self.inner.lock().expect("nonce cache poisoned");
        if inner.seen.contains(&nonce) {
            return false;
        }
        inner.seen.insert(nonce);
        inner.order.push_back(nonce);
        while inner.order.len() > self.capacity {
            if let Some(old) = inner.order.pop_front() {
                inner.seen.remove(&old);
            }
        }
        true
    }

    /// Current number of nonces in the cache. For tests + diagnostics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("nonce cache poisoned").seen.len()
    }

    /// `true` if the cache holds no nonces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Tracks the highest sequence number accepted per peer.
///
/// New envelopes from a peer must have `sequence > last_seen` —
/// strictly monotonic, no gaps required. This catches replays
/// (`seq == last`) and out-of-order rewinds (`seq < last`) without
/// requiring a per-peer connection state machine.
#[derive(Default)]
pub struct SequenceTracker {
    inner: Mutex<HashMap<Fingerprint, u64>>,
}

impl SequenceTracker {
    /// Build a fresh tracker with no peers known.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept and advance iff `seq > last_seen` for this peer.
    ///
    /// On accept, returns `Ok(())` and remembers `seq` as the new
    /// high-water mark. On reject, returns
    /// `Err((expected, actual))`: `expected` is `last_seen + 1`
    /// (the lowest sequence we'd next accept), `actual` is the
    /// sequence that arrived. The mutation only happens on accept.
    pub fn check_and_advance(
        &self,
        peer: Fingerprint,
        seq: u64,
    ) -> std::result::Result<(), (u64, u64)> {
        let mut inner = self.inner.lock().expect("seq tracker poisoned");
        let last = inner.get(&peer).copied().unwrap_or(0);
        if seq > last {
            inner.insert(peer, seq);
            Ok(())
        } else {
            Err((last + 1, seq))
        }
    }

    /// Last-seen sequence for this peer, or `None` if we've never
    /// seen one. For tests + diagnostics.
    #[must_use]
    pub fn last_seen(&self, peer: &Fingerprint) -> Option<u64> {
        self.inner
            .lock()
            .expect("seq tracker poisoned")
            .get(peer)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp_of(seed: u8) -> Fingerprint {
        Fingerprint([seed; 32])
    }

    fn nonce_of(seed: u8) -> [u8; 24] {
        [seed; 24]
    }

    #[test]
    fn nonce_cache_accepts_new_nonces() {
        let c = NonceCache::new(8);
        assert!(c.check_and_insert(nonce_of(1)));
        assert!(c.check_and_insert(nonce_of(2)));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn nonce_cache_rejects_duplicate() {
        let c = NonceCache::new(8);
        assert!(c.check_and_insert(nonce_of(1)));
        assert!(
            !c.check_and_insert(nonce_of(1)),
            "second insert must report duplicate"
        );
        assert_eq!(c.len(), 1, "duplicate must not grow cache");
    }

    #[test]
    fn nonce_cache_evicts_oldest_at_capacity() {
        let c = NonceCache::new(3);
        c.check_and_insert(nonce_of(1));
        c.check_and_insert(nonce_of(2));
        c.check_and_insert(nonce_of(3));
        c.check_and_insert(nonce_of(4));
        // After inserting a 4th into a cap-3 cache, the oldest (1)
        // should be evicted — i.e. accepted again as "new".
        assert_eq!(c.len(), 3);
        assert!(
            c.check_and_insert(nonce_of(1)),
            "evicted nonce is new again"
        );
    }

    #[test]
    fn nonce_cache_is_empty_starts_true() {
        let c = NonceCache::new(8);
        assert!(c.is_empty());
        c.check_and_insert(nonce_of(1));
        assert!(!c.is_empty());
    }

    #[test]
    fn seq_tracker_accepts_monotonic() {
        let t = SequenceTracker::new();
        let p = fp_of(1);
        assert!(t.check_and_advance(p, 1).is_ok());
        assert!(t.check_and_advance(p, 2).is_ok());
        assert!(t.check_and_advance(p, 100).is_ok());
        assert_eq!(t.last_seen(&p), Some(100));
    }

    #[test]
    fn seq_tracker_rejects_repeat() {
        let t = SequenceTracker::new();
        let p = fp_of(1);
        t.check_and_advance(p, 5).unwrap();
        let err = t.check_and_advance(p, 5).unwrap_err();
        // expected = last_seen + 1 = 6; actual = 5
        assert_eq!(err, (6, 5));
    }

    #[test]
    fn seq_tracker_rejects_out_of_order() {
        let t = SequenceTracker::new();
        let p = fp_of(1);
        t.check_and_advance(p, 10).unwrap();
        let err = t.check_and_advance(p, 9).unwrap_err();
        assert_eq!(err, (11, 9));
    }

    #[test]
    fn seq_tracker_independent_per_peer() {
        let t = SequenceTracker::new();
        let a = fp_of(1);
        let b = fp_of(2);
        t.check_and_advance(a, 100).unwrap();
        // Peer B starts fresh — seq 1 is fine even though A is at 100.
        assert!(t.check_and_advance(b, 1).is_ok());
        assert_eq!(t.last_seen(&a), Some(100));
        assert_eq!(t.last_seen(&b), Some(1));
    }

    #[test]
    fn seq_tracker_unknown_peer_has_no_last_seen() {
        let t = SequenceTracker::new();
        assert!(t.last_seen(&fp_of(99)).is_none());
    }

    #[test]
    fn seq_tracker_rejects_zero_when_starting() {
        // Implicit initial last_seen is 0, so seq=0 must NOT be
        // accepted — every legitimate first send must use seq >= 1.
        let t = SequenceTracker::new();
        let err = t.check_and_advance(fp_of(1), 0).unwrap_err();
        assert_eq!(err, (1, 0));
    }
}
