# Revocation: a user-signed log and `CertChain::verify_with`

**Status:** protocol slice implemented (agent-mesh#180); CLI is #181, transports #182 (implemented).
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
3. Distribution of the log is out of scope here.

## Transports (#182)

`agent-mesh-transport::RevocationGuard` is the one consumer of the log; every
transport takes one and nothing is checked without it.

- **Fail closed.** `RevocationGuard::open(<home>/revocation.json, user)` reads,
  verifies and checks the log at startup; a missing, unreadable, invalid or
  other user's log is an error, so no bus or transport binds and no handshake
  runs. If the file turns bad while running, every peer is refused until it is
  fixed. `RevocationGuard::in_memory(&UserKey)` (an empty log, nothing
  persisted) exists for tests and callers that keep no log.
- **`Seen` is persisted** beside the log as `revocation.seen.json`, and only
  ever advances. Read of the log, `extends` against the persisted `Seen`, and
  the write of a strictly longer head happen under one exclusive lock
  (`revocation.seen.lock`, `File::lock`), so guards and processes sharing a home
  cannot interleave and move it backwards. It is published through the shared
  `atomic_write` helper (exclusive `create_new` temp file with a random name and
  mode 0600, `sync_all`, rename, directory `sync_all`), also used by `amesh`.
  A log rolled back to an older copy, or forked, is refused at startup and while
  running.
- **Handshakes.** The iroh handshake (`handshake.rs::ensure_trustable`) and the
  SSH session handshake (`session.rs::validate_peer_hello`, and the local cert in
  `validate_local_identity`) call `verify_with` with the guard's state instead
  of `verify` / `verify_at`. The refusing side reports `Revoked` and says why
  to the peer; a dialer that refuses its acceptor just closes.
- **Live sessions and the admission point.** A `LiveCheck` holds the peer's
  chain and the last log head it passed; once it refuses, it refuses for good.
  Every received envelope passes `LiveCheck::admit` in one place, the
  transport crate's envelope decode (`recv_envelope`, and `EnvelopeReader::next`
  as each envelope leaves its buffer), so envelopes read ahead of a revocation
  are refused too, and so are `amesh listen` and the PyO3 `accept_envelope`
  (both call `recv_envelope`; there is no unchecked variant on an iroh path).
  The iroh transport also re-checks an admitted envelope when the bus takes it
  off its queue, and `Revocable` ends the stream's reads and writes. There is no
  unchecked reader: `EnvelopeReader` and `SessionStream` require a `LiveCheck`.
  SSH records are checked right after the record is read and before one is
  written; the SSH transport hands the same `LiveCheck` to everything that
  buffers beyond the record layer, so its queued messages are re-checked in
  `SshTransport::recv` and a bus session's bridge pipe is read through
  `EnvelopeReader::new(.., live)`. A refusal poisons the half, and the check
  stays refused. Descendants go with their revoked ancestor because
  `verify_with` checks every link.
- **Change detection** reads the log file on every check and compares its bytes
  with the ones last verified, and the cached verdict only stands while the
  persisted `Seen` is exactly the one it wrote: if another guard or process has
  advanced `Seen`, the check reloads under the lock, so a file restored to
  older bytes is refused even by a guard that cached them. Different bytes are
  verified afresh (signatures, parents, `Seen`), and an unreadable or
  non-extending file refuses every peer. File metadata is never trusted.
- **SSH generation.** The log's generation is the session's causal generation
  (`SessionParameters.current_generation` is overwritten), so two peers on
  different log states fail with a parameter mismatch rather than apply different
  views.
- **Not covered:** a connection that is idle when the revocation lands ends at its
  next read or write, not at once; envelope-level admission in the bus is still
  context-free (unchanged).

