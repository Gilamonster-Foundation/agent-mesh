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
//
// The inner `ContentId` is PRIVATE: domain-separated hashing is the cryptographic
// protection, but the Rust type system reinforces it too. Without a public inner
// field, an accidental rebrand like `GrantId(authority_id.0)` won't compile — a
// typed id is obtained from its object's `.id()` (or deserialized), never
// re-tagged from another domain's id. Read the underlying CID via `content_id()`.

/// The content identity of an [`Authority`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorityId(ContentId);

/// The content identity of a [`Grant`] (its authority-ref + derivation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantId(ContentId);

/// The content identity of an operator Attestation (signing is deferred — the id
/// is stable now so an Elevation edge can name it before the verifier lands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttestationId(ContentId);

impl AuthorityId {
    /// The underlying content id (read-only; construction is via [`Authority::id`]).
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        self.0
    }
}

impl GrantId {
    /// The underlying content id (read-only; construction is via [`Grant::id`]).
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        self.0
    }
}

impl AttestationId {
    /// The underlying content id (read-only). Construction is deliberately narrow
    /// while attestations are deferred: an `AttestationId` will be produced by a
    /// future `Attestation::id()`; deserialization is the only external path today.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        self.0
    }
}

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

// ── Grant ⇄ Authority content binding (the CID is load-bearing) ──────────────

/// The two authority ids in an [`BindError::AuthorityCidMismatch`] (boxed so the
/// error variant stays small).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityMismatch {
    /// The [`AuthorityId`] the grant commits to.
    pub named_by_grant: AuthorityId,
    /// The CID of the body the caller tried to bind.
    pub of_body: AuthorityId,
}

/// Why an [`Authority`] body could not be bound to a [`Grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// Computing the authority's CID failed (dag-cbor encoding).
    Encoding(String),
    /// The supplied body's CID is **not** the [`AuthorityId`] the grant names —
    /// it is a different authority than the one the grant content-binds. A
    /// resolver handing over a "convenient" body is rejected here, fail-closed.
    AuthorityCidMismatch(Box<AuthorityMismatch>),
}

/// A [`Grant`] paired with the exact [`Authority`] body it names — and the
/// pairing is **only constructible when the body's CID equals the grant's
/// `authority` field**. This is the whole point of content addressing: the
/// caveats an edge is judged against are provably the caveats the grant commits
/// to, not a body a buggy or hostile resolver substituted. Every function that
/// reasons about a grant's *authority value* takes a `ResolvedGrant`, so the
/// mismatch case is unrepresentable rather than merely checked-somewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGrant {
    grant: Grant,
    authority: Authority,
}

impl ResolvedGrant {
    /// Bind `authority` to `grant`, **verifying** `authority.id() ==
    /// grant.authority()`. Fails closed on any mismatch or encoding error — the
    /// only way to obtain a `ResolvedGrant`, so a mismatched body can never reach
    /// the derivation/admission logic.
    pub fn bind(grant: Grant, authority: Authority) -> Result<Self, BindError> {
        let of_body = authority
            .id()
            .map_err(|e| BindError::Encoding(e.to_string()))?;
        if of_body != grant.authority() {
            return Err(BindError::AuthorityCidMismatch(Box::new(
                AuthorityMismatch {
                    named_by_grant: grant.authority(),
                    of_body,
                },
            )));
        }
        Ok(Self { grant, authority })
    }

    /// The grant.
    #[must_use]
    pub fn grant(&self) -> &Grant {
        &self.grant
    }

    /// The authority body — provably the one `grant` names.
    #[must_use]
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The grant's content id.
    ///
    /// # Errors
    /// Propagates a dag-cbor encoding error.
    pub fn id(&self) -> Result<GrantId, ContentError> {
        self.grant.id()
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
    /// The parent grant supplied does not have the [`GrantId`] the child's
    /// derivation names (computed from the parent grant, not trusted from a
    /// caller-passed id).
    ParentMismatch,
    /// An elevation whose attestation the verifier rejected (or the deferred
    /// default, which rejects all).
    ElevationUnauthorized,
    /// A non-root edge needs its parent grant, but none was supplied.
    MissingParent,
    /// A CID needed to check the edge could not be computed (fail-closed).
    CidUnavailable,
}

/// Result of checking one derivation edge (L6 + L7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivationDecision {
    /// The edge is valid.
    Valid,
    /// The edge is rejected, fail-closed.
    Reject(DerivationReject),
}

/// Check a single derivation edge for `child` against its `parent` (L6).
///
/// Both are [`ResolvedGrant`]s, so each carries an authority body that is
/// **CID-bound to its grant** — the caveats compared are provably the ones the
/// grants name, closing the substitution attack where a resolver validates an
/// edge against a convenient body the grant does not commit to. The parent's
/// [`GrantId`] is recomputed from the parent grant here and matched against the
/// id the child's derivation names; it is never trusted from the caller.
///
/// * `Root` is always valid (no parent).
/// * `Attenuation` requires the parent id to match AND `child ⊑ parent`
///   (algebra, [`Caveats::leq`]); a widening is rejected.
/// * `Elevation` requires the parent id to match AND `verifier.verify_elevation`
///   to accept — the algebra deliberately cannot bless a widening.
#[must_use]
pub fn check_derivation(
    child: &ResolvedGrant,
    parent: Option<&ResolvedGrant>,
    verifier: &dyn AttestationVerifier,
) -> DerivationDecision {
    use DerivationReject as R;
    // The parent's identity is COMPUTED from the parent grant and matched against
    // the id the child's derivation names — never trusted from a caller. Combined
    // with `ResolvedGrant` (each authority body is CID-bound to its grant at
    // construction), every caveat compared below is provably the caveats the
    // grants commit to. That is what makes the algebra sound; an unchecked CID
    // would be decorative.
    let matched_parent = |declared: &GrantId| -> Result<&ResolvedGrant, DerivationDecision> {
        let parent = parent.ok_or(DerivationDecision::Reject(R::MissingParent))?;
        let parent_id = parent
            .id()
            .map_err(|_| DerivationDecision::Reject(R::CidUnavailable))?;
        if &parent_id != declared {
            return Err(DerivationDecision::Reject(R::ParentMismatch));
        }
        Ok(parent)
    };

    match child.grant().derivation() {
        Derivation::Root => DerivationDecision::Valid,
        Derivation::Attenuation {
            parent: declared_parent,
        } => {
            let parent = match matched_parent(declared_parent) {
                Ok(p) => p,
                Err(reject) => return reject,
            };
            // Both authorities are CID-bound to their grants (ResolvedGrant), so
            // this `⊑` is over the exact caveats the grants name.
            if child
                .authority()
                .caveats()
                .leq(parent.authority().caveats())
            {
                DerivationDecision::Valid
            } else {
                DerivationDecision::Reject(R::AttenuationWidens)
            }
        }
        Derivation::Elevation {
            parent: declared_parent,
            attestation,
        } => {
            let parent = match matched_parent(declared_parent) {
                Ok(p) => p,
                Err(reject) => return reject,
            };
            let parent_id = match parent.id() {
                Ok(id) => id,
                Err(_) => return DerivationDecision::Reject(R::CidUnavailable),
            };
            if verifier.verify_elevation(parent_id, child.grant(), *attestation) {
                DerivationDecision::Valid
            } else {
                DerivationDecision::Reject(R::ElevationUnauthorized)
            }
        }
    }
}

// ── L5 PROVENANCE: chain termination at an externally-trusted root ───────────

/// Why a derivation chain is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReject {
    /// An empty chain proves nothing (fail-closed).
    Empty,
    /// Edge `index` (child `chain[index]` → parent `chain[index + 1]`) failed
    /// [`check_derivation`] for the carried reason.
    Edge {
        index: usize,
        reason: DerivationReject,
    },
    /// `chain[index]` is a [`Derivation::Root`] but is not the terminus — a root
    /// may only appear at the end of a chain (it derives from nothing).
    RootNotTerminal { index: usize },
    /// The terminus is not a [`Derivation::Root`]: the chain does not bottom out
    /// at a self-standing root, so there is nothing to anchor trust to.
    NonRootTerminus,
    /// The chain is structurally valid **and** terminates at a root, but that
    /// root is not the externally-configured trusted anchor. Structural validity
    /// is not trust: a CID identifies, it does not authorize. This is the reject
    /// that stops an attacker's self-authored, internally-consistent chain.
    UntrustedRoot { found: GrantId, expected: GrantId },
    /// A CID needed to anchor the chain could not be computed (fail-closed).
    CidUnavailable,
}

/// Whether a derivation chain is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDecision {
    /// Every edge is a valid derivation AND the chain terminates at the exact
    /// externally-trusted root.
    Trusted,
    /// The chain is rejected, fail-closed.
    Reject(ChainReject),
}

/// **Verify a full derivation chain against an externally-trusted root (L5).**
///
/// `chain` is ordered leaf → root: `chain[0]` is the grant whose trust is in
/// question, `chain[i + 1]` is the parent of `chain[i]`, and the last element is
/// the claimed root. Every element is a [`ResolvedGrant`], so each authority body
/// is CID-bound to its grant.
///
/// A chain is [`ChainDecision::Trusted`] iff **both** hold:
///
/// 1. **Every edge is a valid derivation.** For each non-terminal `chain[i]`,
///    [`check_derivation`] against `chain[i + 1]` succeeds — which recomputes the
///    parent id and rejects any link whose declared parent is not the actual next
///    grant. The terminus must be a [`Derivation::Root`]; a root may not appear
///    anywhere else.
/// 2. **The root is the configured trust anchor.** The terminal root's [`GrantId`]
///    must equal `trusted_root`. **This is the load-bearing step of L5.** A
///    structurally perfect, internally-consistent chain an attacker authored
///    themselves is *rejected here* — a CID identifies the root, it does not make
///    the root trusted. Trust enters the system only by an operator configuring
///    which root [`GrantId`] is the anchor; it is never inferred from structure.
#[must_use]
pub fn verify_chain(
    chain: &[ResolvedGrant],
    trusted_root: GrantId,
    verifier: &dyn AttestationVerifier,
) -> ChainDecision {
    let Some(terminus) = chain.last() else {
        return ChainDecision::Reject(ChainReject::Empty);
    };
    // Walk every edge leaf → root. `chain[i]` (i < last) must derive validly from
    // `chain[i + 1]`, and must not itself be a Root (a root derives from nothing,
    // so it can only be the terminus).
    for (index, child) in chain.iter().enumerate() {
        if index == chain.len() - 1 {
            break;
        }
        if matches!(child.grant().derivation(), Derivation::Root) {
            return ChainDecision::Reject(ChainReject::RootNotTerminal { index });
        }
        let parent = &chain[index + 1];
        match check_derivation(child, Some(parent), verifier) {
            DerivationDecision::Valid => {}
            DerivationDecision::Reject(reason) => {
                return ChainDecision::Reject(ChainReject::Edge { index, reason });
            }
        }
    }

    // The terminus must be a root...
    if !matches!(terminus.grant().derivation(), Derivation::Root) {
        return ChainDecision::Reject(ChainReject::NonRootTerminus);
    }
    // ...and it must be THE trusted root. Structural validity ≠ trust.
    let root_id = match terminus.id() {
        Ok(id) => id,
        Err(_) => return ChainDecision::Reject(ChainReject::CidUnavailable),
    };
    if root_id != trusted_root {
        return ChainDecision::Reject(ChainReject::UntrustedRoot {
            found: root_id,
            expected: trusted_root,
        });
    }
    ChainDecision::Trusted
}

// ── L3 BOUND: the resolved-authority lattice + pure admission ────────────────

/// What a native fence actually permits on ONE axis, expressed portably (the
/// projection agent-bridle produces from its native profile). The lattice the
/// L3 BOUND law is *computed* over — fidelity is never asserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedScope {
    /// Bounded authority: the union of `concrete` items the mechanism permits
    /// (e.g. canonicalized paths / hosts) **and** named capability `classes` it
    /// permits but cannot enumerate as a concrete set (e.g. a whole loopback
    /// interface). The two are independent dimensions, so a fence can permit both.
    /// The empty scope (`{}`, `{}`) is the **bottom / identity** element for
    /// [`union`](Self::union): `∅ ∪ X = X`.
    Bounded {
        concrete: BTreeSet<String>,
        classes: BTreeSet<String>,
    },
    /// The mechanism imposes no restriction on this axis (`⊤`, the top element).
    Unbounded,
    /// The mechanism's authority on this axis could not be resolved. **Any**
    /// comparison involving `Unknown` is `Unknown` → fail-closed (L7).
    Unknown,
}

impl ResolvedScope {
    /// The bottom element: permits nothing. The identity for [`union`](Self::union).
    #[must_use]
    pub fn empty() -> Self {
        Self::Bounded {
            concrete: BTreeSet::new(),
            classes: BTreeSet::new(),
        }
    }

    /// A bounded scope of concrete items only.
    #[must_use]
    pub fn concrete<I: IntoIterator<Item = String>>(items: I) -> Self {
        Self::Bounded {
            concrete: items.into_iter().collect(),
            classes: BTreeSet::new(),
        }
    }

    /// A bounded scope of a single named capability class only.
    #[must_use]
    pub fn class(name: impl Into<String>) -> Self {
        Self::Bounded {
            concrete: BTreeSet::new(),
            classes: BTreeSet::from([name.into()]),
        }
    }

    /// Lift a delegated [`Scope<String>`] into the resolved lattice: `All ⇒
    /// Unbounded`, `Only(set) ⇒ Bounded{concrete: set}`.
    #[must_use]
    pub fn from_scope(scope: &Scope<String>) -> Self {
        match scope {
            Scope::All => Self::Unbounded,
            Scope::Only(set) => Self::Bounded {
                concrete: set.clone(),
                classes: BTreeSet::new(),
            },
        }
    }

    /// The union `self ∪ other` — the bounding authority when combining the
    /// delegated grant with the authorized closure. `Unknown` propagates
    /// (fail-closed); `Unbounded` absorbs; two bounded scopes union their concrete
    /// and class dimensions independently. The empty scope is the identity, so
    /// `∅ ∪ X = X` for every `X` (the composability law).
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Unbounded, _) | (_, Self::Unbounded) => Self::Unbounded,
            (
                Self::Bounded {
                    concrete: ca,
                    classes: la,
                },
                Self::Bounded {
                    concrete: cb,
                    classes: lb,
                },
            ) => Self::Bounded {
                concrete: ca.union(cb).cloned().collect(),
                classes: la.union(lb).cloned().collect(),
            },
        }
    }
}

/// How a resolved scope stands relative to a bounding scope (does the fence stay
/// within what was authorized?).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRelation {
    /// The resolved scope equals the bound.
    Equal,
    /// The resolved scope is a subset of the bound (more confined — fine).
    Subset,
    /// The resolved scope is a superset of the bound — it **widens** authority
    /// beyond what was granted (the OCAP bug this whole layer exists to catch).
    Superset,
    /// Neither contains the other.
    Incomparable,
    /// Not decidable in the portable lattice (an `Unknown` operand) → treated as
    /// fail-closed by [`admit`].
    Unknown,
}

/// Relate a resolved fence scope to the bound it must stay within: does
/// `resolved ⊆ bound`? Returns the precise relation so a widening
/// ([`ScopeRelation::Superset`]) is a distinct, reportable fact from an
/// undecidable comparison ([`ScopeRelation::Unknown`]). Containment is per
/// dimension: `Bounded ⊆ Bounded` iff both `concrete ⊆ concrete` and
/// `classes ⊆ classes`.
#[must_use]
pub fn relate(resolved: &ResolvedScope, bound: &ResolvedScope) -> ScopeRelation {
    use ResolvedScope as S;
    match (resolved, bound) {
        (S::Unknown, _) | (_, S::Unknown) => ScopeRelation::Unknown,
        (S::Unbounded, S::Unbounded) => ScopeRelation::Equal,
        // The fence permits everything but the bound does not — a widening.
        (S::Unbounded, _) => ScopeRelation::Superset,
        // The bound permits everything, the fence is narrower — within bounds.
        (_, S::Unbounded) => ScopeRelation::Subset,
        (
            S::Bounded {
                concrete: ca,
                classes: la,
            },
            S::Bounded {
                concrete: cb,
                classes: lb,
            },
        ) => {
            if ca == cb && la == lb {
                ScopeRelation::Equal
            } else if ca.is_subset(cb) && la.is_subset(lb) {
                ScopeRelation::Subset
            } else if ca.is_superset(cb) && la.is_superset(lb) {
                ScopeRelation::Superset
            } else {
                ScopeRelation::Incomparable
            }
        }
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
        fs_read: ResolvedScope::empty(),
        fs_write: ResolvedScope::empty(),
        exec: ResolvedScope::empty(),
        net: ResolvedScope::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveats::CountBound;

    fn concrete(items: &[&str]) -> ResolvedScope {
        ResolvedScope::concrete(items.iter().map(|s| s.to_string()))
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
    /// A ROOT [`ResolvedGrant`] over `c` — a grant paired with its CID-bound
    /// authority (the only way `check_derivation` accepts an authority body).
    fn root_grant(c: Caveats) -> ResolvedGrant {
        let auth = Authority::new(c);
        let grant = Grant::new(auth.id().unwrap(), Derivation::Root);
        ResolvedGrant::bind(grant, auth).unwrap()
    }

    /// A derived [`ResolvedGrant`] over `c` with derivation `d`, honestly bound to
    /// its own authority body.
    fn derived_grant(c: Caveats, d: Derivation) -> ResolvedGrant {
        let auth = Authority::new(c);
        let grant = Grant::new(auth.id().unwrap(), d);
        ResolvedGrant::bind(grant, auth).unwrap()
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
        let parent = root_grant(caveats(
            Scope::only(["/repo".into(), "/tmp".into()]),
            Scope::only(["git".into()]),
            Scope::none(),
        ));
        let parent_id = parent.id().unwrap();
        // Child ⊑ parent (narrower fs_read) — valid.
        let child = derived_grant(
            caveats(
                Scope::only(["/repo".into()]),
                Scope::only(["git".into()]),
                Scope::none(),
            ),
            Derivation::Attenuation { parent: parent_id },
        );
        assert_eq!(
            check_derivation(&child, Some(&parent), &DenyAllElevations),
            DerivationDecision::Valid
        );
        // Child ⋠ parent (adds /etc) — a widening masquerading as attenuation.
        let widening = derived_grant(
            caveats(
                Scope::only(["/repo".into(), "/etc".into()]),
                Scope::only(["git".into()]),
                Scope::none(),
            ),
            Derivation::Attenuation { parent: parent_id },
        );
        assert_eq!(
            check_derivation(&widening, Some(&parent), &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::AttenuationWidens)
        );
    }

    #[test]
    fn elevation_is_fail_closed_without_a_verifier() {
        let parent = root_grant(Caveats::top());
        let parent_id = parent.id().unwrap();
        let child = derived_grant(
            Caveats::top(),
            Derivation::Elevation {
                parent: parent_id,
                attestation: AttestationId(parent_id.0),
            },
        );
        // The deferred default rejects every elevation (L7).
        assert_eq!(
            check_derivation(&child, Some(&parent), &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::ElevationUnauthorized)
        );
    }

    #[test]
    fn derivation_rejects_a_parent_that_is_not_the_named_grant() {
        let parent = root_grant(Caveats::top());
        let parent_id = parent.id().unwrap();
        // A DIFFERENT resolved grant, whose computed id ≠ the declared parent id.
        let impostor = root_grant(caveats(Scope::none(), Scope::none(), Scope::none()));
        assert_ne!(impostor.id().unwrap(), parent_id);
        let child = derived_grant(
            Caveats::top(),
            Derivation::Attenuation { parent: parent_id },
        );
        // Supplying the impostor as the parent is rejected — the parent id is
        // recomputed from the grant, not trusted.
        assert_eq!(
            check_derivation(&child, Some(&impostor), &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::ParentMismatch)
        );
    }

    // ── Content binding: the CID is load-bearing (the #72 review) ────────────

    #[test]
    fn bind_rejects_a_body_the_grant_does_not_name() {
        // A grant that commits to a WIDE authority (/repo + /etc)…
        let named = Authority::new(caveats(
            Scope::only(["/repo".into(), "/etc".into()]),
            Scope::none(),
            Scope::none(),
        ));
        let grant = Grant::new(named.id().unwrap(), Derivation::Root);
        // …cannot be paired with a convenient, narrower body — bind fails closed.
        let convenient = Authority::new(caveats(
            Scope::only(["/repo".into()]),
            Scope::none(),
            Scope::none(),
        ));
        match ResolvedGrant::bind(grant, convenient) {
            Err(BindError::AuthorityCidMismatch(_)) => {}
            other => panic!("a mismatched body must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn attenuation_cannot_be_validated_against_a_substituted_body() {
        // The reviewer's attack, end to end: a child grant NAMES a widening
        // authority (/repo + /etc, which ⋠ the parent), but the attacker wants it
        // judged against a convenient narrow body (/repo, which ⊑ parent).
        let parent = root_grant(caveats(
            Scope::only(["/repo".into()]),
            Scope::none(),
            Scope::none(),
        ));
        let parent_id = parent.id().unwrap();
        let widening = Authority::new(caveats(
            Scope::only(["/repo".into(), "/etc".into()]),
            Scope::none(),
            Scope::none(),
        ));
        let child_grant = Grant::new(
            widening.id().unwrap(),
            Derivation::Attenuation { parent: parent_id },
        );
        // The substitution is impossible: binding the convenient body to the grant
        // fails (its CID ≠ the grant's authority field).
        let convenient = Authority::new(caveats(
            Scope::only(["/repo".into()]),
            Scope::none(),
            Scope::none(),
        ));
        assert!(ResolvedGrant::bind(child_grant.clone(), convenient).is_err());
        // The only admissible pairing uses the grant's REAL (widening) body, which
        // check_derivation then rejects — the widening cannot hide.
        let honest = ResolvedGrant::bind(child_grant, widening).unwrap();
        assert_eq!(
            check_derivation(&honest, Some(&parent), &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::AttenuationWidens)
        );
    }

    #[test]
    fn derivation_without_a_parent_fails_closed() {
        let parent_id = root_grant(Caveats::top()).id().unwrap();
        let child = derived_grant(
            Caveats::top(),
            Derivation::Attenuation { parent: parent_id },
        );
        assert_eq!(
            check_derivation(&child, None, &DenyAllElevations),
            DerivationDecision::Reject(DerivationReject::MissingParent)
        );
    }

    // ── L5 provenance: chain termination at a trusted root ───────────────────

    /// Build a valid leaf → root chain: a root over `parent_c`, and an
    /// attenuation child over `child_c` whose declared parent is that root.
    fn root_and_child(parent_c: Caveats, child_c: Caveats) -> (ResolvedGrant, ResolvedGrant) {
        let root = root_grant(parent_c);
        let child = derived_grant(
            child_c,
            Derivation::Attenuation {
                parent: root.id().unwrap(),
            },
        );
        (root, child)
    }

    #[test]
    fn chain_is_trusted_only_when_it_terminates_at_the_configured_root() {
        // A legitimate root the operator has anchored, with an honest attenuation
        // beneath it, is trusted.
        let (root, child) = root_and_child(
            caveats(
                Scope::only(["/repo".into(), "/tmp".into()]),
                Scope::only(["git".into()]),
                Scope::none(),
            ),
            caveats(
                Scope::only(["/repo".into()]),
                Scope::only(["git".into()]),
                Scope::none(),
            ),
        );
        let trusted = root.id().unwrap();
        let chain = [child, root];
        assert_eq!(
            verify_chain(&chain, trusted, &DenyAllElevations),
            ChainDecision::Trusted
        );
    }

    #[test]
    fn a_self_authored_root_is_rejected_unless_it_is_the_configured_anchor() {
        // The attacker builds a *structurally perfect* chain: a well-formed root
        // and a genuine attenuation beneath it. Every edge validates. But the root
        // is one they minted themselves, not the operator's anchor — so it is NOT
        // trusted. A CID identifies the root; it does not authorize it.
        let (attacker_root, child) = root_and_child(
            Caveats::top(),
            caveats(Scope::only(["/repo".into()]), Scope::none(), Scope::none()),
        );
        // The edge itself is perfectly valid...
        assert_eq!(
            check_derivation(&child, Some(&attacker_root), &DenyAllElevations),
            DerivationDecision::Valid
        );
        // ...but a DIFFERENT root is the configured trust anchor.
        let real_anchor = root_grant(caveats(
            Scope::only(["/srv".into()]),
            Scope::none(),
            Scope::none(),
        ))
        .id()
        .unwrap();
        let attacker_root_id = attacker_root.id().unwrap();
        let chain = [child, attacker_root];
        assert_eq!(
            verify_chain(&chain, real_anchor, &DenyAllElevations),
            ChainDecision::Reject(ChainReject::UntrustedRoot {
                found: attacker_root_id,
                expected: real_anchor,
            })
        );
    }

    #[test]
    fn a_chain_that_does_not_bottom_out_at_a_root_is_rejected() {
        // A single-element chain whose only element is an attenuation (no root
        // beneath it) has nothing to anchor — fail-closed.
        let orphan = derived_grant(
            Caveats::top(),
            Derivation::Attenuation {
                parent: root_grant(Caveats::top()).id().unwrap(),
            },
        );
        let anchor = root_grant(Caveats::top()).id().unwrap();
        assert_eq!(
            verify_chain(&[orphan], anchor, &DenyAllElevations),
            ChainDecision::Reject(ChainReject::NonRootTerminus)
        );
    }

    #[test]
    fn a_broken_link_in_the_chain_is_rejected() {
        // The child names a parent that is not the grant actually sitting above it
        // in the chain — check_derivation recomputes the parent id and rejects.
        let real_root = root_grant(Caveats::top());
        let other_parent_id = root_grant(caveats(
            Scope::only(["/elsewhere".into()]),
            Scope::none(),
            Scope::none(),
        ))
        .id()
        .unwrap();
        // Child claims descent from `other_parent_id`, but the chain places
        // `real_root` above it.
        let child = derived_grant(
            Caveats::top(),
            Derivation::Attenuation {
                parent: other_parent_id,
            },
        );
        let trusted = real_root.id().unwrap();
        let chain = [child, real_root];
        assert_eq!(
            verify_chain(&chain, trusted, &DenyAllElevations),
            ChainDecision::Reject(ChainReject::Edge {
                index: 0,
                reason: DerivationReject::ParentMismatch,
            })
        );
    }

    #[test]
    fn an_empty_chain_proves_nothing() {
        let anchor = root_grant(Caveats::top()).id().unwrap();
        assert_eq!(
            verify_chain(&[], anchor, &DenyAllElevations),
            ChainDecision::Reject(ChainReject::Empty)
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
        // A capability class and a concrete set live on independent dimensions:
        // neither contains the other, so the relation is Incomparable — which
        // `admit` refuses just as firmly as Unknown (fail-closed), but it is an
        // honest structural fact, not an undecidable one.
        assert_eq!(
            relate(&ResolvedScope::class("loopback"), &concrete(&["127.0.0.1"])),
            ScopeRelation::Incomparable
        );
        // A class within the same class dimension relates cleanly.
        assert_eq!(
            relate(
                &ResolvedScope::class("loopback"),
                &ResolvedScope::class("loopback")
            ),
            ScopeRelation::Equal
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

    // ── L3 lattice laws: the resolved-authority algebra needs the same
    //    property-test rigor as the caveat lattice, because a broken union or
    //    a non-monotone bound would let a widening slip past `admit`. ──────────
    mod lattice_laws {
        use super::*;
        use proptest::prelude::*;

        /// A generator over the whole `ResolvedScope` domain: the empty bottom,
        /// arbitrary bounded concrete/class mixes, `Unbounded`, and `Unknown`.
        fn scope() -> impl Strategy<Value = ResolvedScope> {
            prop_oneof![
                Just(ResolvedScope::Unbounded),
                Just(ResolvedScope::Unknown),
                (
                    prop::collection::btree_set("[a-d]", 0..4),
                    prop::collection::btree_set("class-[x-z]", 0..3),
                )
                    .prop_map(|(concrete, classes)| ResolvedScope::Bounded { concrete, classes }),
            ]
        }

        proptest! {
            /// The empty scope is the identity for union: `∅ ∪ X = X` and
            /// `X ∪ ∅ = X`. This is the exact law the old `ConcreteScope /
            /// CapabilityClass` split violated (`∅ ∪ class(X)` collapsed to
            /// `Unknown`), which is why a legitimate closure-authorized widening
            /// could be mis-classified.
            #[test]
            fn empty_is_the_union_identity(x in scope()) {
                prop_assert_eq!(ResolvedScope::empty().union(&x), x.clone());
                prop_assert_eq!(x.union(&ResolvedScope::empty()), x);
            }

            /// Union is commutative: `a ∪ b = b ∪ a`.
            #[test]
            fn union_is_commutative(a in scope(), b in scope()) {
                prop_assert_eq!(a.union(&b), b.union(&a));
            }

            /// Union is associative: `(a ∪ b) ∪ c = a ∪ (b ∪ c)`.
            #[test]
            fn union_is_associative(a in scope(), b in scope(), c in scope()) {
                prop_assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
            }

            /// Union is idempotent: `a ∪ a = a`.
            #[test]
            fn union_is_idempotent(a in scope()) {
                prop_assert_eq!(a.union(&a), a.clone());
            }

            /// `Unknown` is absorbing under union — fail-closed propagation: an
            /// unresolved axis can never be cleaned up by combining it with
            /// anything.
            #[test]
            fn unknown_propagates_through_union(a in scope()) {
                prop_assert_eq!(a.union(&ResolvedScope::Unknown), ResolvedScope::Unknown);
                prop_assert_eq!(ResolvedScope::Unknown.union(&a), ResolvedScope::Unknown);
            }

            /// `Unbounded` absorbs every *resolved* scope (bottom..Unbounded).
            /// Only `Unknown` overrides it (checked above): `⊤ ∪ bounded = ⊤`.
            #[test]
            fn unbounded_absorbs_bounded(
                concrete in prop::collection::btree_set("[a-d]", 0..4),
                classes in prop::collection::btree_set("class-[x-z]", 0..3),
            ) {
                let b = ResolvedScope::Bounded { concrete, classes };
                prop_assert_eq!(ResolvedScope::Unbounded.union(&b), ResolvedScope::Unbounded);
                prop_assert_eq!(b.union(&ResolvedScope::Unbounded), ResolvedScope::Unbounded);
            }

            /// No-widening / monotonicity: the union is an *upper bound*, so a
            /// resolved scope is always `⊆` its union with anything. If this fails,
            /// `admit`'s `resolved ⊆ delegated ∪ closure` test would be judging
            /// against a bound that is not actually a bound.
            #[test]
            fn union_is_an_upper_bound(a in scope(), b in scope()) {
                let bound = a.union(&b);
                // `a` relative to `a ∪ b` is never a Superset (never a widening).
                prop_assert_ne!(relate(&a, &bound), ScopeRelation::Superset);
                prop_assert_ne!(relate(&b, &bound), ScopeRelation::Superset);
            }

            /// `relate` is reflexive: every scope equals itself (including
            /// `Unbounded`; `Unknown` is the sole exception — it is never
            /// decidably equal, by fail-closed design).
            #[test]
            fn relate_is_reflexive(a in scope()) {
                match a {
                    ResolvedScope::Unknown => {
                        prop_assert_eq!(relate(&a, &a), ScopeRelation::Unknown);
                    }
                    _ => prop_assert_eq!(relate(&a, &a), ScopeRelation::Equal),
                }
            }

            /// `relate` is antisymmetric in direction: if `a ⊆ b` is `Subset`
            /// then `b ⊆ a` is `Superset`, and vice-versa (mirrored view).
            #[test]
            fn relate_direction_is_mirrored(a in scope(), b in scope()) {
                match relate(&a, &b) {
                    ScopeRelation::Subset => {
                        prop_assert_eq!(relate(&b, &a), ScopeRelation::Superset);
                    }
                    ScopeRelation::Superset => {
                        prop_assert_eq!(relate(&b, &a), ScopeRelation::Subset);
                    }
                    ScopeRelation::Equal => {
                        prop_assert_eq!(relate(&b, &a), ScopeRelation::Equal);
                    }
                    ScopeRelation::Incomparable => {
                        prop_assert_eq!(relate(&b, &a), ScopeRelation::Incomparable);
                    }
                    // Any Unknown operand keeps both directions Unknown.
                    ScopeRelation::Unknown => {
                        prop_assert_eq!(relate(&b, &a), ScopeRelation::Unknown);
                    }
                }
            }
        }
    }
}
