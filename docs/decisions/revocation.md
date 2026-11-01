# Revocation: a user-signed log and `CertChain::verify_with`

**Status:** protocol slice implemented (agent-mesh#180); CLI is #181, transports #182.
**Date:** 2026-10-26

## Decision

A user revokes agents, and bumps the generation, by appending to a
**revocation log** signed by the user key. Verifiers fold the log into a
`RevocationState` and check certificate chains against it.

This extends the existing precedent, the epoch ratchet in
[flock.md](flock.md#the-epoch-ratchet): the generation caveat
(`Scope<u64>`, `CertChain::verify_at`) is the bulk revocation axis; the log
adds per-agent revocation and a signed, shareable record of the current
generation.

## Record

- `RevocationEntry`: `Genesis { user }`, `Revoke { agent }`, `Generation { current }`.
- The log is a chain of `MerkleNode<RevocationEntry>` (from `content-addressable`).
  The first node is the genesis with no parents; every later node has exactly
  one parent, the previous node's id. A node's identity is `MerkleNode::id()`.
  Nothing is hashed or encoded by hand.
- Each node is signed by the genesis user over
  `b"agent-mesh/revocation/v1\0" || cid_bytes`, kept beside the node (the
  `Assertion` shape).
- `RevocationLog`'s JSON form is a container. Integrity comes from the CIDs and
  signatures, re-checked by `verify()`.

## Verification (all fail closed)

- `RevocationLog::verify()`: genesis first; each parent is the previous id;
  every signature verifies under the genesis user; generations strictly
  increase from 0. Yields `RevocationState { user, head, len, generation, revoked }`.
- `CertChain::verify_with(&state)`: the chain's user must be the log's user;
  **every link** (leaf and each delegating ancestor) must be absent from
  `revoked`; then `verify_at(state.generation)`. Errors: `MeshError::Revoked`,
  `MeshError::RevocationState`.
- `RevocationLog::extends(&Seen)` refuses a log shorter than what a consumer
  saw (rollback) or whose node at that position is not the head they saw (fork).

## `All`-scoped chains

Issuance defaults are unchanged: `Caveats::top()` scopes a cert to every
generation, so a **generation bump does not touch it**. Such chains are
revoked per agent (`Revoke`), not by bump. Only certs issued with a bounded
`valid_for_generation` lapse on a bump.

## Consumer obligations

1. **Persist `Seen`** (`RevocationState::seen()`) after accepting a log and
   call `extends` on every later fetch; without it a stale or forked log
   silently un-revokes agents.
2. **Re-check live sessions.** `verify_with` is a point-in-time check. A
   session admitted before a revocation stays open until the consumer
   re-verifies it against the newer state.
3. Distribution of the log is out of scope here (#182).
