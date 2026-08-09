# Decision: agent-mesh owns the portable semantic layer of content-addressed authority provenance

**Status:** accepted (2026-08-09) — operator-approved plan; implementation stacked
**Date:** 2026-08-09
**Owner:** Claude (steward); operator (Shawn) approved
**Refs:** agent-bridle `docs/adr/0025`, newt-agent `docs/decisions/`, the audit + plan on the
knowledge board (`2026-08-09_ab317-bounded-authority-audit-EVIDENCE.md`,
`2026-08-09_content-addressed-authority-provenance-PLAN.md`), agent-bridle#317.

## Context

An adversarial audit of agent-bridle #317 proved its enforcement admission checks only
*strength* (`≥ floor`) and never *scope* (`effective ⊆ authorized`) — 19 confirmed cases where a
kernel-enforced **wider** scope is admitted on strength alone. The fix requires content-addressing
authority end-to-end (REAPI discipline: the fence *is* an addressed closure, so a widening is a
different CID). The question this decision settles: **which layer owns what**, so agent-mesh does
not become a place that understands OS sandbox mechanics.

## Decision

Under a 7-law spine (L1 IDENTITY, L2 NON-EQUIVOCATION, L3 BOUND, L4 FLOOR, L5 PROVENANCE,
L6 AUTHORIZATION, L7 FAIL-CLOSED — full statements in agent-bridle ADR 0025), **agent-mesh
(`agent-mesh-protocol`) owns the portable semantic layer**, next to the existing `Caveats`
lattice it already exports:

- `Authority { kind, caveats }` + `AuthorityId = CID(Authority)`.
- `Grant { kind, authority: AuthorityId, derivation }` + `GrantId = CID(Grant)` — the id bug in the
  v0 contract (a `derivation` field outside the hashed id) is fixed here. Same Caveats ⇒ same
  `AuthorityId`; same authority via a different derivation ⇒ different `GrantId`.
- The **resolved-authority lattice** — `ConcreteScope | CapabilityClass | Unbounded | Unknown` —
  rich enough for Windows AppContainer capability classes and coarse macOS surfaces without
  fabricating a concrete set.
- `ScopeRelation` (`Exact | Subset | Widened | Unknown`) and the **pure admission decision
  function**: given an *authorized* authority and a *resolved-authority projection* (produced by a
  native backend), compute `relation` per restricted axis; `Widened | Unknown ⇒ refuse` (L3, L7).
- The portable **verifier contract** — attenuation (`⊑`) and operator-signature elevation (L6): a
  CID identifies an elevation record, it never authorizes it.
- All objects `impl content-addressable::ContentAddressable` via canonical dag-cbor (`content-addressable
  0.1.0`; do not fork). Canonical rule: decode → validate → normalize → re-encode → CID.

**agent-mesh never learns Seatbelt SBPL / Landlock / AppContainer.** Native compilation, the
`RuntimeClosure`, the native `ResolvedFence`, its application, and `EnforcementEvidence` live in
**agent-bridle**, which *projects* a native fence into the portable resolved-authority the mesh
function checks. This keeps a coordinator able to verify portable proof projections without
reimplementing each OS sandbox compiler.

## Consequences

- `agent-mesh-protocol` gains the authority-provenance vocabulary on its own release cadence;
  agent-bridle consumes it (candidate-SHA/path-override during the integration train — no forced
  release stream). Wire formats are **not frozen** until all three platforms exercise them.
- Proof obligation: Lean for the pure functions (canonical id, `⊆`, attenuation `⊑`, strength
  order); the coordination/replay properties (L2/L5) are TLA+. Never commit an unchecked spec.
- Distinct from `agent-bridle-ceremony`'s coarser `Authority`/`Scope` lattice — do not conflate.

---
Model: Claude Opus 4.8 (1M context) | Harness: Claude Code | Operator: Shawn Hartsock | Time: 15:09 EDT | Date: 2026-08-09
