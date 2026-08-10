//! Content-addressed **authority provenance** — the portable semantic layer.
//!
//! This is the mesh half of the Content-Addressed Authority Provenance design
//! (PLAN step 1 / task #134). Software supply-chain security protects the
//! provenance of artifacts that *execute*; this applies the same techniques to
//! the provenance of the **authority under which execution is permitted**.
//!
//! Four distinct proofs, never collapsed:
//!
//! | Proof | Mechanism | Answers |
//! |-------|-----------|---------|
//! | Identity | [`AuthorityId`]/[`GrantId`] (CID) | *is this the exact object?* |
//! | Assertion | signature (deferred) | *who vouched for it?* |
//! | Authorization | attenuation algebra ([`check_derivation`]) | *is this legal?* |
//! | Enforcement | platform witness (agent-bridle) | *what did the OS enforce?* |
//!
//! **Scope of this module (deliberately portable):** it owns [`Authority`] /
//! [`Grant`] and their typed CIDs, the resolved-authority lattice
//! ([`ResolvedScope`] / [`ResolvedAuthority`]), the [`ScopeRelation`], the pure
//! **admission** decision ([`admit`], the L3 BOUND law), and the **verifier
//! contract** ([`AttestationVerifier`]). It never learns a native fence format
//! (SBPL / Landlock / AppContainer) — agent-bridle *projects* its native fence
//! into a [`ResolvedAuthority`] and calls [`admit`] here.
//!
//! The seven governing laws (each carries a proof obligation, discharged
//! separately by the formal specs — task #137):
//! L1 IDENTITY, L2 NON-EQUIVOCATION, L3 BOUND, L4 FLOOR, L5 PROVENANCE,
//! L6 AUTHORIZATION, L7 FAIL-CLOSED. This module implements the executable form
//! of L3/L6/L7 and the L1 typed-identity discipline.

use std::collections::BTreeSet;

use content_addressable::canonical::to_canonical_dagcbor;
use content_addressable::{ContentAddressable, ContentError, ContentId};
use serde::{Deserialize, Serialize};

use crate::caveats::{Caveats, Scope};

// ── Domain tags (L1: typed domains cannot be confused) ───────────────────────
//
// Each provenance body carries its domain tag in the hashed bytes, so two
// objects with coincidentally-equal payloads still get distinct CIDs.
const AUTHORITY_KIND: &str = "agent-mesh/provenance/authority/v1";
const GRANT_KIND: &str = "agent-mesh/provenance/grant/v1";

/// A domain-tagged body: `{ kind, body }`. dag-cbor sorts map keys, so field
/// order is irrelevant to the canonical form; the tag's presence is what
/// separates domains. Serialize-only (never round-tripped as a value).
#[derive(Serialize)]
struct Tagged<'a, B: Serialize> {
    kind: &'a str,
    body: &'a B,
}

fn typed_canonical_form<B: Serialize>(kind: &str, body: &B) -> Result<Vec<u8>, ContentError> {
    to_canonical_dagcbor(&Tagged { kind, body })
}

// ── Typed content IDs (L1) ───────────────────────────────────────────────────

/// The content identity of an [`Authority`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorityId(pub ContentId);

/// The content identity of a [`Grant`] (its authority-ref + derivation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantId(pub ContentId);

/// The content identity of an operator Attestation (signing is deferred — the id
/// is stable now so an Elevation edge can name it before the verifier lands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationId(pub ContentId);

// ── Authority = the authority VALUE (a tagged `Caveats`) ──────────────────────

/// A portable authority value: exactly the mesh [`Caveats`] lattice, given a
/// stable content identity for the first time. **Introducing an identity, not a
/// new authority model** — Newt has no `Grant` type today; authority is a bare
/// `Caveats`, so [`AuthorityId`] is the first stable name a delegated authority
/// ever gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    caveats: Caveats,
}

impl Authority {
    /// Wrap a `Caveats` as a content-addressable authority value.
    #[must_use]
    pub fn new(caveats: Caveats) -> Self {
        Self { caveats }
    }

    /// The authority lattice value.
    #[must_use]
    pub fn caveats(&self) -> &Caveats {
        &self.caveats
    }

    /// This authority's typed content id (L1).
    ///
    /// # Errors
    /// Propagates a dag-cbor encoding error (e.g. a non-finite float — impossible
    /// for `Caveats`, which has no floats).
    pub fn id(&self) -> Result<AuthorityId, ContentError> {
        Ok(AuthorityId(self.content_id()?))
    }
}

impl ContentAddressable for Authority {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        typed_canonical_form(AUTHORITY_KIND, &self.caveats)
    }
}

// ── Grant = authority-ref + derivation (the id-split fix) ─────────────────────

/// How a [`Grant`] came to hold its authority (the authorization proof — L6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Derivation {
    /// A root grant — the session baseline, derived from nothing.
    Root,
    /// Attenuated from `parent`: the algebra requires `child ⊑ parent`
    /// ([`check_derivation`] enforces it). An attenuation can NEVER widen.
    Attenuation { parent: GrantId },
    /// Elevated from `parent`: widens by definition, so the algebra cannot bless
    /// it — it is legal *only* through a valid operator `attestation`
    /// (signature). Signatures are deferred (contract §8); until a verifier
    /// lands, [`check_derivation`] fail-closes every elevation.
    Elevation {
        parent: GrantId,
        attestation: AttestationId,
    },
}

/// A grant: a reference to an [`Authority`] value plus the [`Derivation`] that
/// justifies holding it.
///
/// **The id-split fix:** the grant references its authority by [`AuthorityId`]
/// rather than inlining the `Caveats`, so the *authority value* and the *grant*
/// are two distinct objects with two distinct CIDs. The same authority reached
/// by two different derivations is two different grants (correct), and a grant's
/// identity is not silently a re-hash of the raw caveats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    authority: AuthorityId,
    derivation: Derivation,
}

impl Grant {
    /// A grant over `authority` justified by `derivation`.
    #[must_use]
    pub fn new(authority: AuthorityId, derivation: Derivation) -> Self {
        Self {
            authority,
            derivation,
        }
    }

    /// The authority this grant confers, by content id.
    #[must_use]
    pub fn authority(&self) -> AuthorityId {
        self.authority
    }

    /// How this grant was derived.
    #[must_use]
    pub fn derivation(&self) -> &Derivation {
        &self.derivation
    }

    /// This grant's typed content id (L1).
    ///
    /// # Errors
    /// Propagates a dag-cbor encoding error.
    pub fn id(&self) -> Result<GrantId, ContentError> {
        Ok(GrantId(self.content_id()?))
    }
}

impl ContentAddressable for Grant {
    fn canonical_form(&self) -> Result<Vec<u8>, ContentError> {
        // The grant body: `{ authority, derivation }`. Domain-tagged so a grant
        // CID can never collide with the authority CID it references.
        #[derive(Serialize)]
        struct Body<'a> {
            authority: &'a AuthorityId,
            derivation: &'a Derivation,
        }
        typed_canonical_form(
            GRANT_KIND,
            &Body {
                authority: &self.authority,
                derivation: &self.derivation,
            },
        )
    }
}

// ── L6 AUTHORIZATION: attenuation algebra / elevation signature ──────────────

/// The verifier contract for operator Elevation attestations (L6). Real
/// signature verification is provided downstream (agent-bridle / newt operator
/// key); Phase A ships only the contract plus a fail-closed default.
pub trait AttestationVerifier {
    /// Does `attestation` authorize elevating from `parent` to `child`? A CID
    /// **identifies**, it never authorizes — an elevation is legal only if this
    /// returns `true`.
    fn verify_elevation(&self, parent: GrantId, child: &Grant, attestation: AttestationId) -> bool;
}

/// The fail-closed default verifier: **rejects every elevation** (L7). Signing
/// is deferred (contract §8), so until a real operator-key verifier lands, no
/// elevation edge is admissible — only attenuation (algebra) is.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllElevations;

impl AttestationVerifier for DenyAllElevations {
    fn verify_elevation(
        &self,
        _parent: GrantId,
        _child: &Grant,
        _attestation: AttestationId,
    ) -> bool {
        false
    }
}

/// Why a derivation edge is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationReject {
    /// An attenuation edge whose child authority is NOT `⊑` the parent (it
    /// widens) — algebra forbids it (I5).
    AttenuationWidens,
    /// The declared parent grant id does not match the parent supplied.
    ParentMismatch,
    /// An elevation whose attestation the verifier rejected (or the deferred
    /// default, which rejects all).
    ElevationUnauthorized,
    /// The parent authority value was needed to check the edge but not supplied.
    MissingParentAuthority,
}

/// Result of checking one derivation edge (L6 + L7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationDecision {
    /// The edge is valid.
    Valid,
    /// The edge is rejected, fail-closed.
    Reject(DerivationReject),
}

/// Check a single derivation edge for `child`, given the resolved parent
/// (authority value + its id), against `verifier` (L6).
///
/// * `Root` is always valid (no parent).
/// * `Attenuation` requires the parent id to match AND `child ⊑ parent`
///   (algebra, [`Caveats::leq`]); a widening is rejected.
/// * `Elevation` requires the parent id to match AND `verifier.verify_elevation`
///   to accept — the algebra deliberately cannot bless a widening.
#[must_use]
pub fn check_derivation(
    child: &Grant,
    child_authority: &Authority,
    parent: Option<(&GrantId, &Authority)>,
    verifier: &dyn AttestationVerifier,
) -> DerivationDecision {
    use DerivationReject as R;
    match child.derivation() {
        Derivation::Root => DerivationDecision::Valid,
        Derivation::Attenuation {
            parent: declared_parent,
        } => {
            let Some((parent_id, parent_authority)) = parent else {
                return DerivationDecision::Reject(R::MissingParentAuthority);
            };
            if parent_id != declared_parent {
                return DerivationDecision::Reject(R::ParentMismatch);
            }
            if child_authority.caveats().leq(parent_authority.caveats()) {
                DerivationDecision::Valid
            } else {
                DerivationDecision::Reject(R::AttenuationWidens)
            }
        }
        Derivation::Elevation {
            parent: declared_parent,
            attestation,
        } => {
            let Some((parent_id, _parent_authority)) = parent else {
                return DerivationDecision::Reject(R::MissingParentAuthority);
            };
            if parent_id != declared_parent {
                return DerivationDecision::Reject(R::ParentMismatch);
            }
            if verifier.verify_elevation(*parent_id, child, *attestation) {
                DerivationDecision::Valid
            } else {
                DerivationDecision::Reject(R::ElevationUnauthorized)
            }
        }
    }
}

// ── L3 BOUND: the resolved-authority lattice + pure admission ────────────────

/// What a native fence actually permits on ONE axis, expressed portably (the
/// projection agent-bridle produces from its native profile). The lattice the
/// L3 BOUND law is *computed* over — fidelity is never asserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedScope {
    /// The mechanism permits exactly this set (e.g. canonicalized paths / hosts).
    ConcreteScope(BTreeSet<String>),
    /// The mechanism permits a named capability class it cannot enumerate as a
    /// concrete set (e.g. a whole loopback interface). Comparable to another
    /// scope only when the other names the identical class.
    CapabilityClass(String),
    /// The mechanism imposes no restriction on this axis (`⊤`).
    Unbounded,
    /// The mechanism's authority on this axis could not be resolved. **Any**
    /// comparison involving `Unknown` is `Unknown` → fail-closed (L7).
    Unknown,
}

impl ResolvedScope {
    /// Lift a delegated [`Scope<String>`] into the resolved lattice: `All ⇒
    /// Unbounded`, `Only(set) ⇒ ConcreteScope(set)`.
    #[must_use]
    pub fn from_scope(scope: &Scope<String>) -> Self {
        match scope {
            Scope::All => Self::Unbounded,
            Scope::Only(set) => Self::ConcreteScope(set.clone()),
        }
    }

    /// The union `self ∪ other` — the bounding authority when combining the
    /// delegated grant with the authorized closure. Conservative / fail-closed:
    /// any `Unknown` ⇒ `Unknown`; any `Unbounded` ⇒ `Unbounded`; two concrete
    /// sets ⇒ their union; equal classes ⇒ that class; a class mixed with a
    /// concrete set (not portably combinable) ⇒ `Unknown`.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Unbounded, _) | (_, Self::Unbounded) => Self::Unbounded,
            (Self::ConcreteScope(a), Self::ConcreteScope(b)) => {
                Self::ConcreteScope(a.union(b).cloned().collect())
            }
            (Self::CapabilityClass(a), Self::CapabilityClass(b)) if a == b => {
                Self::CapabilityClass(a.clone())
            }
            _ => Self::Unknown,
        }
    }
}

/// How a resolved scope stands relative to a bounding scope (does the fence stay
/// within what was authorized?).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRelation {
    /// The resolved scope equals the bound.
    Equal,
    /// The resolved scope is a strict subset of the bound (more confined — fine).
    Subset,
    /// The resolved scope is a strict superset of the bound — it **widens**
    /// authority beyond what was granted (the OCAP bug this whole layer exists to
    /// catch).
    Superset,
    /// Neither contains the other.
    Incomparable,
    /// Not decidable in the portable lattice (a class vs a concrete set, or an
    /// `Unknown` operand) → treated as fail-closed by [`admit`].
    Unknown,
}

/// Relate a resolved fence scope to the bound it must stay within: does
/// `resolved ⊆ bound`? Returns the precise relation so a widening
/// ([`ScopeRelation::Superset`]) is a distinct, reportable fact from an
/// undecidable comparison ([`ScopeRelation::Unknown`]).
#[must_use]
pub fn relate(resolved: &ResolvedScope, bound: &ResolvedScope) -> ScopeRelation {
    use ResolvedScope as S;
    match (resolved, bound) {
        (S::Unknown, _) | (_, S::Unknown) => ScopeRelation::Unknown,
        (S::Unbounded, S::Unbounded) => ScopeRelation::Equal,
        // The fence permits everything but the bound does not — a widening.
        (S::Unbounded, _) => ScopeRelation::Superset,
        // The bound permits everything, the fence is narrower (or equal-if-also-⊤,
        // handled above) — within bounds.
        (_, S::Unbounded) => ScopeRelation::Subset,
        (S::ConcreteScope(a), S::ConcreteScope(b)) => {
            if a == b {
                ScopeRelation::Equal
            } else if a.is_subset(b) {
                ScopeRelation::Subset
            } else if a.is_superset(b) {
                ScopeRelation::Superset
            } else {
                ScopeRelation::Incomparable
            }
        }
        (S::CapabilityClass(a), S::CapabilityClass(b)) if a == b => ScopeRelation::Equal,
        // A class vs a concrete set (or differing classes) cannot be decided
        // portably — fail-closed.
        _ => ScopeRelation::Unknown,
    }
}

/// Per-axis resolved authority for the four OS-confinement axes (the axes a
/// native fence governs; `max_calls`/`valid_for_generation` are gate budget, not
/// fence scope, and are out of this projection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedAuthority {
    pub fs_read: ResolvedScope,
    pub fs_write: ResolvedScope,
    pub exec: ResolvedScope,
    pub net: ResolvedScope,
}

impl ResolvedAuthority {
    /// The four axes in fixed order (for uniform per-axis checks).
    fn axes(&self) -> [(ConfinedAxis, &ResolvedScope); 4] {
        [
            (ConfinedAxis::FsRead, &self.fs_read),
            (ConfinedAxis::FsWrite, &self.fs_write),
            (ConfinedAxis::Exec, &self.exec),
            (ConfinedAxis::Net, &self.net),
        ]
    }

    /// Project a delegated [`Caveats`] into the resolved lattice — the bound the
    /// grant alone authorizes (before adding any [`RuntimeClosure`], which lives
    /// in agent-bridle).
    #[must_use]
    pub fn from_delegated(caveats: &Caveats) -> Self {
        Self {
            fs_read: ResolvedScope::from_scope(&caveats.fs_read),
            fs_write: ResolvedScope::from_scope(&caveats.fs_write),
            exec: ResolvedScope::from_scope(&caveats.exec),
            net: ResolvedScope::from_scope(&caveats.net),
        }
    }

    fn axis(&self, axis: ConfinedAxis) -> &ResolvedScope {
        match axis {
            ConfinedAxis::FsRead => &self.fs_read,
            ConfinedAxis::FsWrite => &self.fs_write,
            ConfinedAxis::Exec => &self.exec,
            ConfinedAxis::Net => &self.net,
        }
    }
}

/// The four OS-confinement axes (names an [`AdmissionReject`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinedAxis {
    FsRead,
    FsWrite,
    Exec,
    Net,
}

/// The reason an admission is refused (L3 + L7): the axis whose resolved fence
/// exceeded its bound, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionReject {
    pub axis: ConfinedAxis,
    pub relation: ScopeRelation,
}

/// The admission decision (L3 BOUND). `Admit` iff, on **every** axis, the fence's
/// resolved scope stays within the bound `delegated ∪ closure`; any widening,
/// incomparability, or undecidable comparison refuses fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    Admit,
    Reject(AdmissionReject),
}

/// **The pure L3 admission decision.** For every axis, the actually-permitted
/// authority (`resolved`, projected from the native fence by agent-bridle) must
/// be `⊆` the bound `delegated ∪ closure`:
///
/// * `delegated` — the least-authority grant the model holds.
/// * `closure` — the explicit, minimal, harness-disjoint [`RuntimeClosure`] the
///   harness legitimately adds (loader paths, etc.); it is agent-bridle's
///   object, projected here as a [`ResolvedAuthority`].
///
/// Admit iff `resolved ⊆ (delegated ∪ closure)` on every axis. A fence that
/// permits MORE than that bound (`Superset`), an undecidable comparison
/// (`Unknown`), or an `Incomparable` set refuses — a widening is a refusal, not a
/// silently-admitted run. Pure: no IO, no platform knowledge.
#[must_use]
pub fn admit(
    resolved: &ResolvedAuthority,
    delegated: &Caveats,
    closure: &ResolvedAuthority,
) -> AdmissionDecision {
    let delegated = ResolvedAuthority::from_delegated(delegated);
    for (axis, fence_scope) in resolved.axes() {
        let bound = delegated.axis(axis).union(closure.axis(axis));
        match relate(fence_scope, &bound) {
            ScopeRelation::Equal | ScopeRelation::Subset => {}
            relation => {
                return AdmissionDecision::Reject(AdmissionReject { axis, relation });
            }
        }
    }
    AdmissionDecision::Admit
}

/// A no-authority closure (all axes deny/empty) — the common case where the
/// harness adds nothing beyond the delegated grant.
#[must_use]
pub fn empty_closure() -> ResolvedAuthority {
    ResolvedAuthority {
        fs_read: ResolvedScope::ConcreteScope(BTreeSet::new()),
        fs_write: ResolvedScope::ConcreteScope(BTreeSet::new()),
        exec: ResolvedScope::ConcreteScope(BTreeSet::new()),
        net: ResolvedScope::ConcreteScope(BTreeSet::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveats::CountBound;

    fn concrete(items: &[&str]) -> ResolvedScope {
        ResolvedScope::ConcreteScope(items.iter().map(|s| s.to_string()).collect())
    }

    fn caveats(fs_read: Scope<String>, exec: Scope<String>, net: Scope<String>) -> Caveats {
        Caveats {
            fs_read,
            fs_write: Scope::none(),
            exec,
            net,
            max_calls: CountBound::top(),
            valid_for_generation: Scope::top(),
        }
    }

    /// A parent grant `(GrantId, Authority)` over `auth`, as a Root — the shape
    /// `check_derivation` consumes (derivations reference the parent GRANT).
    fn parent_grant(auth: &Authority) -> (GrantId, Authority) {
        let grant = Grant::new(auth.id().unwrap(), Derivation::Root);
        (grant.id().unwrap(), auth.clone())
    }

    // ── L1 identity: determinism + typed-domain separation ───────────────────

    #[test]
    fn authority_id_is_deterministic() {
        let a = Authority::new(Caveats::top());
        assert_eq!(a.id().unwrap(), a.clone().id().unwrap());
    }

    #[test]
    fn typed_domains_cannot_collide() {
        // An Authority and a Grant can never share a CID, even constructed to be
        // "the same shape", because each hashes a distinct domain tag.
        let auth = Authority::new(Caveats::top());
        let auth_id = auth.id().unwrap();
        let grant = Grant::new(auth_id, Derivation::Root);
        // Different typed ids (distinct kinds in the hashed body).
        assert_ne!(auth_id.0, grant.id().unwrap().0);
    }

    #[test]
    fn identity_is_transport_agnostic() {
        // The CID comes from the canonical dag-cbor form, not the transport wire,
        // so a serde_json round-trip preserves the id (L1 — one validated
        // canonical representation).
        let auth_id = Authority::new(caveats(
            Scope::only(["/repo".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        ))
        .id()
        .unwrap();
        let g = Grant::new(auth_id, Derivation::Root);
        let back: Grant = serde_json::from_slice(&serde_json::to_vec(&g).unwrap()).unwrap();
        assert_eq!(g, back);
        assert_eq!(g.id().unwrap(), back.id().unwrap());
    }

    #[test]
    fn grant_id_splits_authority_from_derivation() {
        // Same authority, two derivations → two distinct grants (the id-split).
        let auth_id = Authority::new(Caveats::top()).id().unwrap();
        let other = Authority::new(caveats(Scope::none(), Scope::none(), Scope::none()))
            .id()
            .unwrap();
        let root = Grant::new(auth_id, Derivation::Root);
        let attenuated = Grant::new(
            auth_id,
            Derivation::Attenuation {
                parent: GrantId(other.0),
            },
        );
        assert_ne!(root.id().unwrap(), attenuated.id().unwrap());
    }

    // ── L6 authorization: attenuation algebra / elevation signature ──────────

    #[test]
    fn attenuation_admits_only_when_child_leq_parent() {
        let parent_auth = Authority::new(caveats(
            Scope::only(["/repo".into(), "/tmp".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        ));
        let (parent_id, parent) = parent_grant(&parent_auth);
        // Child ⊑ parent (narrower fs_read) — valid.
        let child = Authority::new(caveats(
            Scope::only(["/repo".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        ));
        let g = Grant::new(
            child.id().unwrap(),
            Derivation::Attenuation { parent: parent_id },
        );
        assert_eq!(
            check_derivation(&g, &child, Some((&parent_id, &parent)), &DenyAllElevations),
            DerivationDecision::Valid
        );
        // Child ⋠ parent (adds /etc) — a widening masquerading as attenuation.
        let widening = Authority::new(caveats(
            Scope::only(["/repo".into(), "/etc".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        ));
        let bad = Grant::new(
            widening.id().unwrap(),
            Derivation::Attenuation { parent: parent_id },
        );
        assert_eq!(
            check_derivation(
                &bad,
                &widening,
                Some((&parent_id, &parent)),
                &DenyAllElevations
            ),
            DerivationDecision::Reject(DerivationReject::AttenuationWidens)
        );
    }

    #[test]
    fn elevation_is_fail_closed_without_a_verifier() {
        let (parent_id, parent) = parent_grant(&Authority::new(Caveats::top()));
        let child = Authority::new(Caveats::top());
        let g = Grant::new(
            child.id().unwrap(),
            Derivation::Elevation {
                parent: parent_id,
                attestation: AttestationId(parent_id.0),
            },
        );
        // The deferred default rejects every elevation (L7).
        assert_eq!(
            check_derivation(&g, &child, Some((&parent_id, &parent)), &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::ElevationUnauthorized)
        );
    }

    #[test]
    fn attenuation_rejects_a_parent_id_mismatch() {
        let (parent_id, parent) = parent_grant(&Authority::new(Caveats::top()));
        let (wrong, _) = parent_grant(&Authority::new(caveats(
            Scope::none(),
            Scope::none(),
            Scope::none(),
        )));
        let child = Authority::new(Caveats::top());
        let g = Grant::new(
            child.id().unwrap(),
            Derivation::Attenuation { parent: wrong },
        );
        assert_eq!(
            check_derivation(&g, &child, Some((&parent_id, &parent)), &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::ParentMismatch)
        );
    }

    // ── L3 bound: the resolved lattice + admission ───────────────────────────

    #[test]
    fn relate_classifies_subset_superset_equal() {
        assert_eq!(
            relate(&concrete(&["a"]), &concrete(&["a", "b"])),
            ScopeRelation::Subset
        );
        assert_eq!(
            relate(&concrete(&["a", "b"]), &concrete(&["a"])),
            ScopeRelation::Superset
        );
        assert_eq!(
            relate(&concrete(&["a"]), &concrete(&["a"])),
            ScopeRelation::Equal
        );
        assert_eq!(
            relate(&concrete(&["a"]), &concrete(&["b"])),
            ScopeRelation::Incomparable
        );
        // Unbounded fence over a bounded bound is a widening.
        assert_eq!(
            relate(&ResolvedScope::Unbounded, &concrete(&["a"])),
            ScopeRelation::Superset
        );
        // Any Unknown → Unknown (fail-closed).
        assert_eq!(
            relate(&ResolvedScope::Unknown, &concrete(&["a"])),
            ScopeRelation::Unknown
        );
        assert_eq!(
            relate(
                &ResolvedScope::CapabilityClass("loopback".into()),
                &concrete(&["127.0.0.1"])
            ),
            ScopeRelation::Unknown
        );
    }

    #[test]
    fn admit_when_fence_matches_the_delegated_grant() {
        let delegated = caveats(
            Scope::only(["/repo".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        );
        // Fence resolves to exactly the delegated scopes (fs_write empty = delegated none).
        let fence = ResolvedAuthority {
            fs_read: concrete(&["/repo"]),
            fs_write: concrete(&[]),
            exec: concrete(&["git"]),
            net: concrete(&[]),
        };
        assert_eq!(
            admit(&fence, &delegated, &empty_closure()),
            AdmissionDecision::Admit
        );
    }

    #[test]
    fn admit_refuses_a_fence_that_widens_beyond_delegated_plus_closure() {
        let delegated = caveats(
            Scope::only(["/repo".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        );
        // The fence permits /etc on fs_read — beyond the grant, and no closure adds it.
        let fence = ResolvedAuthority {
            fs_read: concrete(&["/repo", "/etc"]),
            fs_write: concrete(&[]),
            exec: concrete(&["git"]),
            net: concrete(&[]),
        };
        assert_eq!(
            admit(&fence, &delegated, &empty_closure()),
            AdmissionDecision::Reject(AdmissionReject {
                axis: ConfinedAxis::FsRead,
                relation: ScopeRelation::Superset,
            })
        );
    }

    #[test]
    fn admit_accepts_a_widening_that_the_explicit_closure_authorizes() {
        // The classic legitimate case: the harness closure explicitly adds the
        // loader path, so the fence permitting it is within delegated ∪ closure.
        let delegated = caveats(Scope::only(["/repo".into()]), Scope::none(), Scope::none());
        let closure = ResolvedAuthority {
            fs_read: concrete(&["/usr/lib"]),
            fs_write: concrete(&[]),
            exec: concrete(&[]),
            net: concrete(&[]),
        };
        let fence = ResolvedAuthority {
            fs_read: concrete(&["/repo", "/usr/lib"]),
            fs_write: concrete(&[]),
            exec: concrete(&[]),
            net: concrete(&[]),
        };
        assert_eq!(
            admit(&fence, &delegated, &closure),
            AdmissionDecision::Admit
        );
        // …but a path in NEITHER the grant nor the closure still refuses.
        let sneaky = ResolvedAuthority {
            fs_read: concrete(&["/repo", "/usr/lib", "/root/.ssh"]),
            ..fence
        };
        assert_eq!(
            admit(&sneaky, &delegated, &closure),
            AdmissionDecision::Reject(AdmissionReject {
                axis: ConfinedAxis::FsRead,
                relation: ScopeRelation::Superset,
            })
        );
    }

    #[test]
    fn admit_fail_closes_on_an_unknown_resolution() {
        // A fence axis the projector could not resolve refuses (L7), never admits.
        let delegated = caveats(Scope::top(), Scope::top(), Scope::top());
        let fence = ResolvedAuthority {
            fs_read: ResolvedScope::Unknown,
            fs_write: ResolvedScope::Unbounded,
            exec: ResolvedScope::Unbounded,
            net: ResolvedScope::Unbounded,
        };
        assert_eq!(
            admit(&fence, &delegated, &empty_closure()),
            AdmissionDecision::Reject(AdmissionReject {
                axis: ConfinedAxis::FsRead,
                relation: ScopeRelation::Unknown,
            })
        );
    }
}
