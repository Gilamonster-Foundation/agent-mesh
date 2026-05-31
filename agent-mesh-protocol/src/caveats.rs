//! `Caveats` — the authority lattice for attenuated agent capabilities.
//!
//! A [`Caveats`] value is an element of a bounded **meet-semilattice**
//! `(L, ⊑, ⊓, ⊤)`:
//!
//! - **`⊤` (top)** — [`Caveats::top`] — the user's full, *unrestricted*
//!   authority. The absence of any caveat is `⊤`.
//! - **`⊑` (attenuates / "is at most")** — [`Caveats::leq`] — `a ⊑ b` means
//!   `a` grants no more than `b`. It is a partial order (reflexive,
//!   antisymmetric, transitive).
//! - **`⊓` (meet)** — [`Caveats::meet`] — the greatest lower bound: the most
//!   permissive authority that is still `⊑` both operands. `meet` is the only
//!   way capabilities compose along a delegation chain, and it can **never
//!   amplify** — for all `a, b`: `a ⊓ b ⊑ a` and `a ⊓ b ⊑ b`.
//!
//! Delegation is **attenuation-only**: a child must satisfy `child ⊑ parent`,
//! and because the algebra has no reachable join/amplify operation, a confused
//! or compromised agent *cannot* escalate beyond the down-set of the caveats
//! it was minted with. Safety becomes structural rather than a property of the
//! model behaving.
//!
//! This crate ships the lattice type and its laws (property-tested). Wiring it
//! into [`crate::AgentMetadata`] and enforcing `child ⊑ parent` at issue time
//! is the next step; OS-level enforcement (Landlock, uid-mapped namespaces) is
//! the step after that. See
//! `docs/decisions/agentic_object_capability_security.md` in the `newt-agent`
//! repo for the full design.
//!
//! ## Scope semantics
//!
//! Each axis is a [`Scope`] (a set of allowed items, or `All`). Membership is
//! **exact** at this layer: `fs_read` carries the literal paths/prefixes the
//! authority names, and `⊑`/`⊓` are set inclusion / intersection. Treating a
//! path as a *prefix* that also authorizes its descendants is an
//! *enforcement* concern (it belongs with the Landlock layer), not a property
//! of the lattice algebra — so it is deliberately out of scope here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// A set-valued authority axis: either unrestricted (`All`, the top of this
/// axis) or exactly the listed items.
///
/// Ordered so that `Only(s) ⊑ All` for every `s`, and
/// `Only(a) ⊑ Only(b) ⟺ a ⊆ b`. The meet is intersection, with `All` acting
/// as the identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope<T: Ord + Clone> {
    /// Unrestricted — authorizes every item. The `⊤` of this axis.
    All,
    /// Authorizes exactly the items in the set (canonical: a `BTreeSet`).
    Only(BTreeSet<T>),
}

impl<T: Ord + Clone> Scope<T> {
    /// The top of this axis (`All`, unrestricted).
    #[must_use]
    pub fn top() -> Self {
        Self::All
    }

    /// The empty authority on this axis — authorizes nothing.
    #[must_use]
    pub fn none() -> Self {
        Self::Only(BTreeSet::new())
    }

    /// Build a bounded scope from an iterator of items.
    pub fn only<I: IntoIterator<Item = T>>(items: I) -> Self {
        Self::Only(items.into_iter().collect())
    }

    /// `self ⊑ other` — does `self` authorize no more than `other`?
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        match (self, other) {
            // Everything is ⊑ unrestricted.
            (_, Self::All) => true,
            // Unrestricted is not ⊑ a bounded set.
            (Self::All, Self::Only(_)) => false,
            // Bounded ⊑ bounded iff subset.
            (Self::Only(a), Self::Only(b)) => a.is_subset(b),
        }
    }

    /// `self ⊓ other` — the greatest lower bound (most permissive scope still
    /// `⊑` both). `All` is the identity; otherwise intersection.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::All, x) | (x, Self::All) => x.clone(),
            (Self::Only(a), Self::Only(b)) => Self::Only(a.intersection(b).cloned().collect()),
        }
    }
}

/// A numeric upper bound axis (e.g. "at most N tool calls").
///
/// `Unlimited` is the top; `AtMost(n) ⊑ AtMost(m) ⟺ n ≤ m`. The meet is the
/// tighter (smaller) bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CountBound {
    /// No bound — the `⊤` of this axis.
    Unlimited,
    /// At most this many.
    AtMost(u64),
}

impl CountBound {
    /// The top of this axis (`Unlimited`).
    #[must_use]
    pub fn top() -> Self {
        Self::Unlimited
    }

    /// `self ⊑ other` — is `self` at least as tight a bound as `other`?
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        match (self, other) {
            (_, Self::Unlimited) => true,
            (Self::Unlimited, Self::AtMost(_)) => false,
            (Self::AtMost(a), Self::AtMost(b)) => a <= b,
        }
    }

    /// `self ⊓ other` — the tighter bound.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unlimited, x) | (x, Self::Unlimited) => *x,
            (Self::AtMost(a), Self::AtMost(b)) => Self::AtMost((*a).min(*b)),
        }
    }
}

/// The capability set an agent holds — one element of the authority
/// meet-semilattice. See the [module docs](crate::caveats).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveats {
    /// Filesystem paths the agent may read.
    pub fs_read: Scope<String>,
    /// Filesystem paths the agent may write.
    pub fs_write: Scope<String>,
    /// Commands the agent may execute.
    pub exec: Scope<String>,
    /// Network hosts the agent may reach.
    pub net: Scope<String>,
    /// Upper bound on tool calls this authority permits.
    pub max_calls: CountBound,
    /// Generation counters this authority is valid for (causal, not
    /// wall-clock — a caveat keys on "flight N", never on time).
    pub valid_for_generation: Scope<u64>,
}

impl Caveats {
    /// `⊤` — unrestricted authority on every axis. Equivalent to "no caveats",
    /// i.e. the user's full authority.
    #[must_use]
    pub fn top() -> Self {
        Self {
            fs_read: Scope::top(),
            fs_write: Scope::top(),
            exec: Scope::top(),
            net: Scope::top(),
            max_calls: CountBound::top(),
            valid_for_generation: Scope::top(),
        }
    }

    /// `self ⊑ other` — does `self` grant no more authority than `other` on
    /// *every* axis? This is the attenuation check: a delegated child's
    /// caveats must be `⊑` its parent's.
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        self.fs_read.leq(&other.fs_read)
            && self.fs_write.leq(&other.fs_write)
            && self.exec.leq(&other.exec)
            && self.net.leq(&other.net)
            && self.max_calls.leq(&other.max_calls)
            && self.valid_for_generation.leq(&other.valid_for_generation)
    }

    /// `self ⊓ other` — the greatest lower bound, axis by axis. This is how
    /// authority composes along a delegation chain; it can never amplify.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            fs_read: self.fs_read.meet(&other.fs_read),
            fs_write: self.fs_write.meet(&other.fs_write),
            exec: self.exec.meet(&other.exec),
            net: self.net.meet(&other.net),
            max_calls: self.max_calls.meet(&other.max_calls),
            valid_for_generation: self.valid_for_generation.meet(&other.valid_for_generation),
        }
    }
}

impl Default for Caveats {
    /// Absence of caveats is `⊤` (unrestricted) — the back-compatible default
    /// so an `AgentMetadata` with no declared caveats keeps today's behavior.
    fn default() -> Self {
        Self::top()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Hand-written examples (read like a spec) ────────────────────────────

    #[test]
    fn scope_all_is_top() {
        let bounded = Scope::only(["/a".to_string()]);
        assert!(bounded.leq(&Scope::All));
        assert!(!Scope::<String>::All.leq(&bounded));
        assert_eq!(Scope::<String>::All.meet(&bounded), bounded);
    }

    #[test]
    fn scope_subset_order() {
        let small = Scope::only(["/a".to_string()]);
        let big = Scope::only(["/a".to_string(), "/b".to_string()]);
        assert!(small.leq(&big));
        assert!(!big.leq(&small));
        assert_eq!(big.meet(&small), small);
    }

    #[test]
    fn scope_disjoint_meet_is_empty() {
        let a = Scope::only(["/a".to_string()]);
        let b = Scope::only(["/b".to_string()]);
        assert_eq!(a.meet(&b), Scope::none());
        assert!(Scope::<String>::none().leq(&a));
    }

    #[test]
    fn count_bound_order_and_meet() {
        assert!(CountBound::AtMost(3).leq(&CountBound::AtMost(5)));
        assert!(!CountBound::AtMost(5).leq(&CountBound::AtMost(3)));
        assert!(CountBound::AtMost(99).leq(&CountBound::Unlimited));
        assert!(!CountBound::Unlimited.leq(&CountBound::AtMost(1)));
        assert_eq!(
            CountBound::AtMost(5).meet(&CountBound::AtMost(3)),
            CountBound::AtMost(3)
        );
        assert_eq!(
            CountBound::Unlimited.meet(&CountBound::AtMost(7)),
            CountBound::AtMost(7)
        );
    }

    #[test]
    fn caveats_top_is_above_everything() {
        let restricted = Caveats {
            fs_read: Scope::only(["/repo".to_string()]),
            fs_write: Scope::none(),
            exec: Scope::only(["git".to_string()]),
            net: Scope::none(),
            max_calls: CountBound::AtMost(10),
            valid_for_generation: Scope::only([7u64]),
        };
        assert!(restricted.leq(&Caveats::top()));
        assert!(!Caveats::top().leq(&restricted));
    }

    #[test]
    fn caveats_meet_attenuates_each_axis() {
        let a = Caveats {
            fs_read: Scope::only(["/repo".to_string(), "/tmp".to_string()]),
            max_calls: CountBound::AtMost(10),
            ..Caveats::top()
        };
        let b = Caveats {
            fs_read: Scope::only(["/repo".to_string()]),
            max_calls: CountBound::AtMost(4),
            ..Caveats::top()
        };
        let m = a.meet(&b);
        assert_eq!(m.fs_read, Scope::only(["/repo".to_string()]));
        assert_eq!(m.max_calls, CountBound::AtMost(4));
        assert!(m.leq(&a) && m.leq(&b));
    }

    #[test]
    fn caveats_serde_roundtrip() {
        let c = Caveats {
            exec: Scope::only(["git".to_string(), "cargo".to_string()]),
            max_calls: CountBound::AtMost(3),
            valid_for_generation: Scope::only([42u64]),
            ..Caveats::top()
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Caveats = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // ── Property tests: the lattice laws + attenuation-only ──────────────────

    fn scope_str() -> impl Strategy<Value = Scope<String>> {
        prop_oneof![
            Just(Scope::All),
            prop::collection::btree_set("[a-d]", 0..4).prop_map(Scope::Only),
        ]
    }

    fn count_bound() -> impl Strategy<Value = CountBound> {
        prop_oneof![
            Just(CountBound::Unlimited),
            (0u64..6).prop_map(CountBound::AtMost)
        ]
    }

    fn gen_scope() -> impl Strategy<Value = Scope<u64>> {
        prop_oneof![
            Just(Scope::All),
            prop::collection::btree_set(0u64..4, 0..4).prop_map(Scope::Only),
        ]
    }

    prop_compose! {
        fn caveats()(
            fs_read in scope_str(),
            fs_write in scope_str(),
            exec in scope_str(),
            net in scope_str(),
            max_calls in count_bound(),
            valid_for_generation in gen_scope(),
        ) -> Caveats {
            Caveats { fs_read, fs_write, exec, net, max_calls, valid_for_generation }
        }
    }

    proptest! {
        // Partial order: reflexive, antisymmetric, transitive.
        #[test]
        fn leq_reflexive(a in caveats()) {
            prop_assert!(a.leq(&a));
        }

        #[test]
        fn leq_antisymmetric(a in caveats(), b in caveats()) {
            if a.leq(&b) && b.leq(&a) {
                prop_assert_eq!(a, b);
            }
        }

        #[test]
        fn leq_transitive(a in caveats(), b in caveats(), c in caveats()) {
            if a.leq(&b) && b.leq(&c) {
                prop_assert!(a.leq(&c));
            }
        }

        // Meet is the greatest lower bound.
        #[test]
        fn meet_is_lower_bound(a in caveats(), b in caveats()) {
            let m = a.meet(&b);
            prop_assert!(m.leq(&a), "meet must be ⊑ left");
            prop_assert!(m.leq(&b), "meet must be ⊑ right");
        }

        #[test]
        fn meet_is_greatest_lower_bound(a in caveats(), b in caveats(), c in caveats()) {
            // Any common lower bound c is ⊑ the meet.
            if c.leq(&a) && c.leq(&b) {
                prop_assert!(c.leq(&a.meet(&b)));
            }
        }

        // Meet is a commutative, associative, idempotent monoid with ⊤ identity.
        #[test]
        fn meet_commutative(a in caveats(), b in caveats()) {
            prop_assert_eq!(a.meet(&b), b.meet(&a));
        }

        #[test]
        fn meet_associative(a in caveats(), b in caveats(), c in caveats()) {
            prop_assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
        }

        #[test]
        fn meet_idempotent(a in caveats()) {
            prop_assert_eq!(a.meet(&a), a.clone());
        }

        #[test]
        fn top_is_meet_identity(a in caveats()) {
            prop_assert_eq!(a.meet(&Caveats::top()), a.clone());
            prop_assert!(a.leq(&Caveats::top()));
        }

        // The headline safety property: meet can NEVER amplify. Composing two
        // authorities only ever yields something ⊑ each input — no reachable
        // operation produces authority above an operand.
        #[test]
        fn meet_never_amplifies(a in caveats(), b in caveats()) {
            let m = a.meet(&b);
            prop_assert!(m.leq(&a) && m.leq(&b));
            // And m is strictly not above a unless m == a (no amplification):
            if a.leq(&m) {
                prop_assert_eq!(&m, &a);
            }
        }
    }
}
