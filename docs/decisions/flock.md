# Flock: a signed channel and roster for a team of agents

**Status:** proposed (design only, no code yet)
**Date:** 2026-10-15
**Driving consumer:** the
[herdr-flock](https://github.com/hartsock/shepherds-pi/blob/main/skills/herdr-flock/SKILL.md)
skill: a shepherd, an out-group reviewer and helper agents in terminal panes,
working one project.
**Review:** four rounds of out-group (Codex) review against agent-mesh 0.7.0
(`ad72f21`). The last round found no blocking issues.

## Why this document exists

A flock's handoffs run over files on disk, text typed into terminal panes, and
polling. #105 lists how that fails:
- a brief typed into a busy pane strands there;
- pickup is guessed from pane status;
- a killed push reads as done;
- approvals are copied out of chat by hand.

This document gives a flock three things:
- a **roster**;
- a **signed, append-only event log**, in which every event is named by its
  content ID;
- a **CLI** that any harness can use.

It also specifies a watch-only TUI.

**What the mesh owns.** It carries the events, admits them and stores them. It
decides nothing: dispatch, the review queue, merge gates and whether a head is
still current stay in the skill. Seats and launching belong to herdr or OpenRig
(see the OpenRig scoping doc on branch `research/openrig`). In that doc's terms,
the flock is the "verified senders" candidate, tried on our own rig first.

**The lane files stay plain text on disk.** Events cite them by content ID, and
every lane still works with the mesh switched off.

## Decisions

| | Decision |
|---|---|
| D1 | The channel carries content IDs, never file bodies |
| D2 | One home host per flock. Another host attaches the way ssh reaches a host, and that works in v1 |
| D3 | Approvals come from a human **delegate**, the member that has the screen, which collects a signing gesture. `amesh flock answer` is for the proof of concept |
| D4 | The CLI delivers. herdr only nudges, with a literal `amesh flock take <cid>` that carries no content and no authority |
| D5 | `amesh-herdr` is a binary crate in agent-mesh |
| D6 | No herdr fork: the adapter uses herdr's existing CLI |
| D7 | newt receives natively, as a harness-level integration |
| D8 | `amesh flock init` mints a server key, as with `git init`. Each harness session gets a random key, held by an ssh-agent-style process and destroyed when the session ends |
| D9 | Crash recovery is a hand-off ceremony, never a resurrected key |
| D10 | A hand-off carries the `HANDOFF.md` the new session resumes from, and also covers planned handovers |
| D11 | Certificates are bounded from v1 by an epoch ratchet; the transport keeps unbounded host keys |
| D12 | Enrollment uses a single-use invite token, then a possession challenge for the presented key |
| D13 | The session process limits how long a key lives. It doesn't isolate harnesses under the same account; that is agent-bridle's job |

## Reused, and what must land first

| Need | Existing piece | State |
|---|---|---|
| Key hierarchy | `AgentKey::delegate_external` with `PossessionChallenge` | built |
| Generation-aware verification | `CertChain::verify_at` | built; used only inside the flock layer |
| Event identity | `MerkleNode` in `content-addressable` | experimental. Freezing its bytes is prerequisite **P1** |
| Domain-tagged canonical form | `authority.rs` | built |
| Attaching from another host | session streams | iroh only. SSH sessions are prerequisite **P2** |
| Typed handoffs | #105 | open; this design closes part of it (see "Limits") |

#42 and #46 propose other state (nonces, per-peer sequences); the flock defines
its own cursor and doesn't wait on them.

## Keys and sessions

```
UserKey
 ├─ server key: an AgentKey minted by `amesh flock init`; generation scope ⊤
 │   ├─ signs genesis, admission records, and epoch, session and hand-off events
 │   └─ session keys, one per harness session
 │       • random, never derived (a derived key can't be destroyed)
 │       • the private half never leaves the session process
 │       • certified by the server (delegate_external), scoped ⊑ the server key
 │       • bounded: valid_for_generation = Only({current epoch})
 └─ operator device keys: certified by the UserKey and listed in the roster
```

**Server key storage.** The seed and certificate are kept in a file with mode
0600 and loaded with `AgentKey::from_seed_and_cert`. `AgentKey` has no save or
load API, so the flock defines this contract. A restarted server has to show it
can still certify a session and sign an event.

### The epoch ratchet

agent-mesh revokes causally, without a wall clock. `verify_at(g)` refuses a
certificate whose `valid_for_generation` set doesn't contain `g`.

- **The epoch is the flock's generation.** The server bumps it whenever
  authority shrinks: a session ends or is lost, a hand-off happens, or a member
  is removed.
- **Renewal is an exchange.** `certify_pubkey` is private, so renewal uses the
  public `delegate_external`:
  1. at each bump, the server challenges every live session over its stream;
  2. the session signs the challenge;
  3. the server admits a `renewal` event.

  A session that missed bumps while it was disconnected renews through the
  `renew` entry, and only if it hasn't been ended.
- **Every certificate is in the log.** Each admission record names the
  certificate its event was verified with, so a fresh reader can verify any old
  event at its own epoch.
- **Revocation is structural.** Anyone holding the log sees a dead session
  without trusting the server's table.
- **Limits.**
  - `Scope` holds sets, not ranges, so live sessions renew at every epoch.
  - The server certificate stays unbounded; rotating it is its own ceremony.
- **The transport stays unbounded.** Hosts authenticate streams with their
  usual keys, so the handshake is unchanged. The flock checks bounded session
  certificates inside the stream, and epochs never reach the bus.

### Enrollment

1. `amesh flock invite <member>` is signed by the roster role. The server keeps a
   single-use bearer token, and the `invite` event carries only a verifier for
   it.
2. `amesh flock session --token …` generates a key and presents the token and
   the public key at the `enroll` entry.
3. The server mints a `PossessionChallenge` for that key, and the session signs
   it.
4. In one transaction, the server consumes the token and the challenge,
   certifies the key, and admits `session-start`.

**A replacement session starts pending.** Any session after a member's first is
pending, whatever its predecessor's state, and can sign nothing. Only a hand-off
activates it, and a member has at most one active session.

### Entry points

| Entry | Authorized by | Allows |
|---|---|---|
| `enroll` | an invite token | enrollment only |
| `renew` | an earlier certificate of a session that hasn't ended, plus a fresh possession proof | one renewal |
| the stream | the bounded session key signing a fresh challenge bound to this flock and this stream | log and file data. A copied certificate isn't enough |

### The session process

`amesh flock session` is like `ssh-agent`.
- It keeps the key in memory only, locks that memory (`mlock`), disables core
  dumps, and zeroizes the key on exit.
- It serves the CLI over a socket with mode 0600.
- After a `kill -9` the key is unreachable, and the next epoch leaves it
  uncertified.
- The socket keeps out other Unix users, but not other harnesses under the same
  account.

### Hand-off

A hand-off moves a role from one session to another, either after a `lost`
session or as a planned handover such as a tab restart.
1. The roster's authority approves it: the shepherd for a helper, the operator
   for the shepherd or the delegate. The operator signs with a device key the
   roster lists; a key merely certified by the same `UserKey` doesn't count.
   Devices change only in a server-signed `roster` event, and the check uses
   the roster as of the approval's own admission index, so replay is stable
   after a device is removed. (Built for the shepherd; the delegate half waits
   on the delegate designation.) The approval is single-use and bound to
   `{flock, member, from, to, resume, context}`.
2. The server admits `handoff {from, to, resume, context}`. It ends `from` and
   activates `to` in the same step. `context` cites the `HANDOFF.md` the new
   session resumes from.
3. The new session's first event has `prev = handoff`. A zombie old process
   can't fork the chain.

Pre-rotated (KERI-style) recovery keys are deferred.

## Identity

- **Genesis** is `MerkleNode {parents: {}, payload: {kind: genesis, name,
  server cert, roster, salt}}`, signed by the server.
  - `flock_id = CID(genesis)`.
  - A restart re-verifies genesis and never mints a new one.
- **Every other event** is:
  ```
  { flock, kind, author, prev, refs: { role: event CID },
    files: [{root, path, RawContentId}], at, body }
  ```
  - Its parents are `prev` plus the `refs`; files are never parents.
  - `author` is hashed into the ID.
  - The signature is detached.
  - Operator answers have no `prev`.
- **`at` is only a claim.** Order is the server's admission index.
- **Corrections append, they never edit.**

## Admission

**One process owns the log.** It holds an exclusive lock, and each admission is
one transaction:
1. validate;
2. assign the next index;
3. write one frame, holding the event, its signature, the server-signed
   admission record, and any epoch or renewal records, then fsync it;
4. reply.

Recovery cuts off only an incomplete final frame, and fails closed on any
corruption inside committed history.

**The admission chain is signed.** Each record is `MerkleNode {parents:
{previous record}, payload: {index, epoch, event CID, cert CID}}`, signed by the
server. Verifiers check the signatures, that the index is contiguous, that the
root is bound to genesis, and that every epoch step has its matching `epoch`
event.

Checks, in order:

0. **Duplicate first.** An already-admitted CID returns its index, so retries
   are safe.
1. **Signer class:**

| Class | Valid when |
|---|---|
| server | the key is genesis's server key |
| session | `verify_at(current epoch)` passes; the certificate chains to this flock's server; the session is active; and it isn't ended or a hand-off's `from` |
| operator | certified by the same `UserKey` and listed as an operator in the roster |

2. **Writer chain** (session class only). `prev` must be the author's current
   head; a second child is logged as `fork-attempt`.
3. **References** exist, belong to this flock and this lane, and are of the
   right kind.
4. **Who may sign what:**

| Kind | Signer | `refs` | Closes |
|---|---|---|---|
| `roster` | server, or the roster role | `replaces` = current roster | |
| `brief`, `review` | the shepherd role | | |
| `ack` | the addressee, never the herdr adapter | `of` | receipt only |
| `result` | the brief's addressee | `brief` | the brief |
| `verdict` | the review's addressee | `review`; `head` = the review's | the review |
| `job` / `job-end` | any member / the same member | `job` | the job |
| `ask` | any member | `about`: a brief (optional) | |
| `answer` | operator class | `ask` | the ask |
| `relayed-answer` | any member | `ask` | nothing |
| `status`, `nudged` | the herdr adapter | | |
| `pane` | any active session | | nothing. A claim of the herdr pane/tab the session runs in: signed by the session, vouched for by no one (herdr can't). Short, printable. The latest from the member's *active* session counts |
| `epoch`, `renewal`, `session-*`, `handoff`, `invite` | server class | | |

A second closer is admitted as `conflict` and never replaces the first.

## The board

The fold runs in admission order, so every reader computes the same board. Each
brief is an attempt, and its state is the first row that applies:

| State | Condition |
|---|---|
| `completed` / `failed` | a result exists; its outcome decides which |
| `input-required` | an open `ask` names it |
| `working` | it has been acked |
| `submitted` | otherwise |

The state names are A2A's. A lane shows its latest attempt; older attempts and
conflicts stay visible. An attempt that is completed while a job is still open
shows as `completed, job open`.

## Delivery and failure

- **Watch.** `watch --from (index, signed head)` replays and then goes live on
  one stream. The server first proves its history extends that head. Readers
  never watch the directory.
- **Rollback.** Members keep the signed head they last saw. A history that
  doesn't extend it is refused, whether shorter, rewritten, or with an altered
  prefix.
- **Reader state.** Cursor, checkpoint and board are saved in one file written
  atomically: fsync the file, rename it, fsync the directory.
- **Home host down.** Writes fail loudly; readers show `stale since #n`.
- **Membership.** Streams require a live session of a current member, and they
  close when an epoch bump ends that session.
- **Files.** The home host serves a cited file only when it is under a root the
  roster declares, no symlink escapes that root, and the bytes still match the
  cited ID. Otherwise it answers `unavailable` or `changed since cited`.

## Joining

- **The CLI:** `join`, `inbox`, `take`, `result`, `verdict`, `run -- <cmd>`,
  `watch`, `answer`. It always goes through the session process.
  - `take` verifies the event, re-hashes its file, and emits the `ack`.
  - `run` wraps a job: a wrapper that dies leaves the `job` open.
- **herdr nudge:** `agent wait` (settles on idle, done or blocked; prompts on idle or done), then `agent prompt
  "amesh flock take <cid>"`, then emit `nudged`.
  - herdr can't prompt only-if-still-idle, so the adapter re-reads the target
    afterwards and emits `nudge-misfire` if it changed.
  - It refuses targets it can't identify, and never prompts the operator.
- **newt** subscribes natively, with no nudge. MCP clients use a session
  process too.
- **Trust.** A signature proves which session asserted something, not that an
  agent read it. Even an admitted brief can carry hostile instructions.

**The human delegate.** One member "has the screen": the shepherd, or newt on a
phone. It shows each open `ask` and collects a signing gesture, and the `answer`
is signed by the operator's device key, which the delegate can't forge. The
role moves through a `roster` event.

## amesh-tui

`amesh-tui` is a binary crate, `agent-mesh-tui`. It is watch-only and doesn't
link the emit API (#65). It is built on newtui components. It has four views,
each with a `self`/`herdr` trust tier on every row:
1. **Board** (the default): members, status and the lane state.
2. **Stream:** verified events with filters, plus refused events.
3. **Lane:** the attempt chain, with each cited file marked as matching,
   drifted, or unavailable.
4. **Waiting:** open asks, unanswered reviews, and queued briefs.

```
┌ Board ── flock bafy…k3q · home: local · log ✓ 412 · live ─────────────────┐
│ MEMBER    ROLE      STATUS        LANE      STATE                         │
│ shepherd  shepherd  working self  -         -                             │
│ reviewer  reviewer  working herdr review-12 review                        │
│ helper1   helper    idle    herdr lane-a    completed, job open           │
│ operator  operator  phone (delegate, has the screen)                      │
├ Open ─────────────────────────────────────────────────────────────────────┤
│ job   push  lane-a   no job-end yet                                       │
│ brief lane-b → helper2   queued: helper2 busy                             │
│ ask   publish release notes → operator   open                             │
└───────────────────────────────────────────────────────────────────────────┘
 1 board  2 stream  3 lane  4 waiting   ↑↓  ⏎ open  / filter  q quit
```

## Plan

One issue and one PR per step, in order. Each step's tests are in its issue.

| Step | Work | Key acceptance tests |
|---|---|---|
| P1 | Freeze `MerkleNode` bytes (content-addressable) | golden bytes in Rust and Python |
| P2 | SSH transport carries session streams | the session suite on both transports |
| 1 | Detached author signature over a `ContentId` | another flock's certificate fails, even under the same user |
| 2 | `agent-mesh-flock` model: schema, admission table, fold | every table row; the adapter can't `ack`; two readers get one board |
| 3 | Server part 1: `init`, the log, single-frame admission | crash at every write; forged or discontinuous chains refused; corruption fails closed |
| 4 | Server part 2: invites, sessions, epochs, renewal, hand-off | replayed or misbound tokens refused; pending can't sign; renew after missed epochs; competing hand-offs |
| 5 | `amesh flock session` | `kill -9` leaves the key uncertified; another Unix user is refused |
| 6 | Server part 3: `watch` | exactly-once across replay; altered prefix refused; power-loss checkpoint |
| 7 | CLI and MCP tools | `run` records signals; a forged `ack` is refused |
| 8 | `amesh-tui` | snapshot views; drift marks; no emit API |
| 9 | Attaching from another host | stream challenge rejects copied certificates; two flocks share a transport |
| 10 | `amesh-herdr` adapter | a swapped pane gives `nudge-misfire`; the operator is never prompted |
| 11 | shepherds-pi skill on the CLI | a real lane on three harnesses, all `self`-tier |
| 12 | newt native inbox | taken with no nudge |
| 13 | newt delegate gesture | `answer` verifies as the operator's |

## Limits

This design closes part of #105: delivery is checked at ingest, lifecycle
events are typed, and watchers subscribe. It doesn't check that a reviewed head
is still current, or that a push landed; those preconditions stay in the skill,
and the TUI shows the evidence.

## Out of scope

- **Dispatch, review and merge policy.**
- **Seats and launching.**
- **Free-text chat.**
- **Gesture design.**
- **TUI code in library crates** (#65).
- **Shared memory** such as ledgers (#67).
- **File retention** (#90).
- **Directory snapshots.** These need a tree type in content-addressable
  ([content-addressable#105](https://github.com/hartsock/content-addressable/issues/105)).
  A `files[]` entry could later cite one with no schema change.

Watching needs nothing but membership.

## Open questions

Each has a proposed answer.

- **Crate:** a new `agent-mesh-flock` library crate, rather than waiting for
  the store design.
- **Roster changes:** the server plus the shepherd role. Roles are roster data,
  not caveats.
- **OpenRig:** the roster holds identity only. Model, harness and worktree are
  labels; a RigSpec could generate a roster.
- **Log location:** the flock's own directory, beside its other plain-text
  files.
- **Operator keys:** one per device, certified by the `UserKey`, limited to
  `answer` by admission.
- **Gesture design:** a newt-agent issue beside newt-mobile.
- **Delegate:** any harness eventually; newt first.

<!-- markdownlint-disable-next-line MD013 -->
Model: claude-opus-5-5 | Harness: Claude Code | Operator: Shawn Hartsock | Date: 2026-10-15
