# Design note: `agent-mesh-store` — p2p shared agentic knowledge

**Status:** proposed (design note / RFC — no code yet)
**Date:** 2026-06-10
**Origin:** raised in `Gilamonster-Foundation/newt-agent` PR #243 review;
maintainer direction. Companion to [`bus_vs_nats.md`](./bus_vs_nats.md) — the
store rides the bus that document committed us to.

## Why this document exists

A user runs **many agents bound to one identity** (the ed25519 user root of
trust, cross-signed by their GitHub key). Today those agents can *talk*
(`agent-mesh-bus` pub/sub + request-reply) but they cannot **share durable
knowledge**. There is no mesh-side store: `agent-mesh` is protocol + discovery
+ transport + bus, and nothing persists, replicates, or merges state.

The need is concrete and already prototyped centrally in a different repo: the
`knowledge/board` pattern — a set of shared "cards" (notes, decisions, status)
that every agent working for the user can read and append to. We want that
**p2p over agent-mesh and independent of any single backing store**: no broker,
no central database, no "the board lives on machine X." Each agent holds its own
replica; the mesh reconciles them.

This note proposes `agent-mesh-store` as a new workspace member and fixes the
**coordination model** before any code is written. The model is the load-bearing
decision; the storage engine behind it is deliberately swappable.

## Non-negotiables inherited from agent-mesh

The store must not violate what the rest of the workspace already guarantees:

1. **No broker, no central authority.** Anti-entropy is peer-to-peer over the
   existing bus; there is no "primary" replica.
2. **Wall-clock time is a claim, never a coordination primitive.** This is
   already the law here (`agent-mesh-protocol` README; the repo coding rules).
   The bus orders peers by a **per-peer strictly-monotonic sequence number**
   (`agent-mesh-bus/src/replay.rs` `SequenceTracker`). The store uses the same
   shape. `created_at`/`updated_at` may ride *inside* a note as metadata — a
   claim — but never as the merge or ordering key.
3. **Identity-scoped.** All store traffic is namespaced to the user fingerprint,
   exactly as bus `Topic`s are. Cross-user collision is impossible by
   construction; cross-user reconciliation is out of scope.
4. **Everything is signed.** Every entry an agent contributes is signed by that
   agent's certified sub-key, verifiable up the chain to the user root.

## The model — each agent is its own clock; each node is its own merkle log

This is **not a new primitive.** It is the pragmatic per-node ratchet a system
like agent-mesh already implies, written down:

- **Each agent ticks its own counter and signs its ticks** (a Lamport clock per
  agent). An agent's contributions form an **append-only, hash-chained, signed
  log** — its own merkle log of operations in its own view of history.
- **Two agents naturally hold different merkle logs.** That is expected, not a
  fault. The global store state is the **merge of every known writer's log** — a
  causal DAG, not a single timeline. There is no moment at which "the truth"
  lives in one place.

### Log entry shape

Each entry in a writer's log:

```text
StoreOp {
  writer_fingerprint : Fp,        // which agent (BLAKE3 of its pubkey)
  seq                : u64,       // strictly monotonic per writer — the tick
  prev               : Option<Hash>,  // BLAKE3 of this writer's previous entry
  op                 : Put | Tombstone,
  note_id            : NoteId,    // stable id of the note this op concerns
  payload_cid        : Option<Cid>,   // BLAKE3 content address of the note body
  meta               : Json,      // created_at etc. — CLAIMS, never keys
}
+ signature over the canonical encoding, by the writer's certified sub-key
```

`(writer_fingerprint, seq)` totally orders one writer's entries; `prev` chains
them into a tamper-evident merkle log (any gap or rewrite breaks the chain and
fails verification). `payload_cid` keeps bodies content-addressed and lets large
notes be fetched lazily / deduplicated.

### Materialized view (the "board")

Folding all known logs yields the note set. Because ops are
add/update/tombstone over independent per-writer chains, the natural CRDT is an
**observed-remove set of notes**, which is conflict-free for the common case
(different agents add/retire different cards). **Concurrent edits to the *same*
note** by two agents are kept as **sibling versions** (each addressed by its
`payload_cid`, each carrying its writer + seq), surfaced for reconciliation
rather than silently clobbered — there is no clock to pick a "winner," and the
board pattern wants the divergence visible anyway. A registered deterministic
merge function per note-type can collapse siblings later; LWW-by-timestamp is
explicitly **rejected**.

## Reconciliation — by cross-signing, never by a shared clock

Anti-entropy runs as a background task on a dedicated bus topic:

1. **Gossip heads.** Each agent periodically publishes its **head vector** —
   `{writer_fp → (seq, hash)}` for every writer it tracks. Cheap; O(writers).
2. **Pull the delta.** A peer missing entries for some writer requests the range
   `(have_seq, their_seq]`; the owner (or any agent holding that segment) replies
   with the signed entries.
3. **Verify and append.** The receiver checks each entry's signature and that
   `prev` chains onto what it already has, then appends to its replica of that
   writer's log. A broken chain or bad signature rejects the whole segment.
4. **Cross-sign tips (confidence + pruning).** An agent that has fully verified a
   writer's log up to `(seq, hash)` may publish a **signed attestation** of that
   tip. Accumulated cross-signatures are how the mesh agrees a prefix is stable
   — enabling compaction/checkpoints **without** anyone trusting a wall clock.
   This is the "reconciliation by other means" the model promises.

No step consults time. Convergence is eventual and causal: given connectivity,
every agent's fold of the logs reaches the same note set.

## Crate shape & backing-store independence

`agent-mesh-store`, a new workspace member layered on `agent-mesh-bus`
(gossip/transport) and `agent-mesh-protocol` (identity/signing):

```text
Store::put(note)       -> Cid          // append a Put to our own log
Store::tombstone(id)   -> ()           // append a Tombstone
Store::get(id)         -> Option<Note>
Store::query(pred)     -> Vec<Note>     // fold of the materialized view
Store::heads()         -> HeadVector    // for gossip
+ a background Anti-entropy task bound to a Bus + a store Topic
```

The replication protocol — signed merkle logs + head-vector gossip + cross-sign
— is the contract. **Persistence is a `LogBackend` trait**, not part of the
contract: in-memory for tests, an embedded KV (sled/redb) for a daemon, or plain
files for a CLI. "Independent of any single backing store" means a user can run
one agent on an in-memory replica and another on disk and they still converge,
because convergence is defined by the log algebra, not the storage.

## Relationship to newt's conversation store

newt-agent PR #243 §6 binds its conversation store to the **same** primitive — a
signed per-writer tick / BLAKE3 content chain — precisely so it can later become
a **producer/consumer of `agent-mesh-store`**. Shared notes (the board) is the
first consumer; cross-device conversation continuity is a plausible second.
Building the store here, mesh-side, keeps that policy in one place instead of
re-deriving it in every consumer.

## Phased plan (each its own PR, per repo norms)

1. **S1 — log core (no bus).** `StoreOp`, signing/verification, per-writer chain,
   `LogBackend` trait + in-memory impl, fold→view, OR-set semantics. Property
   tests: chain integrity, signature rejection, fold determinism regardless of
   merge order.
2. **S2 — anti-entropy over the bus.** Head-vector gossip, delta pull, verify +
   append; two-process convergence example (mirrors `bus_dispatch.rs`).
3. **S3 — cross-sign + checkpoints.** Tip attestations; compaction of a
   cross-signed prefix. Convergence-after-compaction tests.
4. **S4 — `amesh store` CLI + a durable `LogBackend`.** `put`/`get`/`ls`/`watch`
   the board from the terminal.
5. **S5 — Python bindings** (`agent-mesh-py`) so non-Rust agents participate.

## Open questions / out of scope

- **Membership:** which writers' logs does an agent track? Floor: every agent
  it has authenticated under the user fingerprint. Bounded by the identity
  namespace; revocation rides the existing cert-chain story.
- **Byzantine writer / key compromise:** signatures + GitHub-rooted cert chain +
  revocation bound the blast radius; a revoked key's log is dropped. Full BFT is
  out of scope — single-user trust domain.
- **Large bodies:** `payload_cid` points at a content-addressed blob; a chunked
  blob transfer (git-elfs/kyln shape) is a later concern, not S1.
- **Per-note ACL:** none — single user, all agents equally trusted within the
  fingerprint namespace.
- **Compaction GC policy details** beyond the cross-signed-prefix mechanism.

## Decision requested

Adopt this model (signed per-writer merkle logs + cross-sign reconciliation, no
clock) and greenlight **S1** as the first `agent-mesh-store` PR? The model is
the commitment; the phases are reviewable one PR at a time.
