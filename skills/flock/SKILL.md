---
name: flock
description: What an agent-mesh flock is (a signed channel and roster for a team of agents), its roles, events and board, and which parts exist today versus planned. Load when working on or with `amesh flock`, the flock crates, or the flock epic (#109).
---

# Flock

Source of truth: [`docs/decisions/flock.md`](../../docs/decisions/flock.md). This
page is a map; it links rather than restates.

## What it is

A flock is a **signed, append-only event log plus a roster** for a team of
agents working one project. One home server owns the log; every event is named
by its content ID and the channel carries content IDs, never file bodies. The
mesh carries, admits and stores events. It decides nothing: dispatch, review
policy and merge gates stay in the
[herdr-flock skill](https://github.com/hartsock/shepherds-pi/blob/main/skills/herdr-flock/SKILL.md).
Lane files stay plain text on disk; events cite them by content ID.

## Roles and events

Roles: **operator**, **shepherd**, **reviewer**, **helper**, **adapter** (the
herdr bridge; it can nudge and report status but never `ack`).

A lane goes through: `brief` (shepherd) → `ack` (addressee) → `result` (addressee)
→ `review` (shepherd) → `verdict` (reviewer). Also `ask` / `answer` (operator
signs the answer), `job` / `job-end`, `status`, `nudged`, `roster` (server or
shepherd), and server-signed `epoch`, `renewal`, `session-*`, `handoff`, `invite`.

The **board** is a fold over the log in admission order, so every reader gets
the same board. A brief is `submitted`, `working` (acked), `input-required`
(open ask) or `completed` / `failed` (result). A second closer is logged as
`conflict`; corrections append, never edit. The signer table and admission
checks are in the decision doc ("Admission").

## Keys, sessions, epochs

The server key is minted by `amesh flock init`. Each harness session gets a
random key certified by the server and bounded to the current **epoch**; the
server bumps the epoch whenever authority shrinks (session ends, hand-off,
member removed), so a dead session is visible in the log itself. A replacement
session starts pending and can sign nothing until a hand-off activates it.

## Built vs planned

Built (plan steps 1–4, 4c read-only herdr view, 4d operator devices):
- the detached author `Assertion` (`agent-mesh-protocol`);
- the `agent-mesh-flock` model crate: schema, admission table, board fold, and
  real `invite`, `session-start`, `session-end`, `epoch` and `renewal` bodies;
- `agent-mesh-flock-server` (init, signed log, admission, recovery; the epoch
  counter is signed into each admission and verified on replay) and
  `amesh flock init`;
- server API for **invites and enrollment** (`invite`, `enroll_begin` /
  `enroll_finish`: a digest-only invite, a server-minted possession challenge,
  token and challenge consumed with `session-start` in one transaction);
- the **log-derived session resolver**: who may sign comes from replaying the
  log in order, and a session must present a certificate the log recorded for
  it, never a peer-issued one;
- **end-driven epoch bumps**: `end_session` writes `session-end` and `epoch`
  as one frame, enforced at admission and on replay;
- **renewal**: the renewal exchange after a bump and the `renew` entry for a
  session that missed bumps, each logged with its certificate. A member's
  later sessions start pending;
- **hand-off**: `handoff(approval, sig)` on a single-use approval bound to
  `{flock, member, from, to, resume, context}`; `context` (the `HANDOFF.md`
  file ref) is required. Signed by an active shepherd for a helper, or by a
  **listed operator device** for a shepherd; reviewer, adapter and operator
  members are refused, and so is a key merely certified by the user key but
  not listed. One
  frame: `handoff` ends `from`, activates the pending `to` and is followed by
  the `epoch` bump. The new session's first event must have `prev = handoff`;
  only a member's current holder can be handed off, so competing hand-offs
  yield one winner;
- **`amesh flock serve`** (owns the log; socket `<flock>/run/serve.sock`, dir
  0700, socket 0600), **`amesh flock invite`**, and **`amesh flock session`**
  (an ssh-agent-style process: the session key lives only in its memory,
  `mlock`ed, core dumps off, zeroized on exit; it serves the CLI over a 0600
  socket; the token comes from `AMESH_FLOCK_TOKEN`). A session's connection is
  its life: a drop without goodbye (`kill -9`) is recorded `lost`, and the
  epoch bump leaves its key uncertified. `mlock` denied means the session
  refuses to start, unless `--allow-unlocked`. The sockets keep out other Unix
  users, not other harnesses under the same account (agent-bridle's job). The
  CLI commands that use it are below (step 7a). Unix only.
- **operator devices**: an operator member in the roster carries `devices`
  (fingerprints of keys the user key certified). The check is "chains to this
  flock's user key" **and** "listed in the roster at that point in the log", so
  a removed device can't approve later, and an earlier hand-off still replays.
  Devices change only in a server-signed `roster` event (`replace_roster`) or
  genesis; a shepherd's roster must leave them as they are. Operator members
  only. Rosters without devices encode as before;
- **`Snapshot`** (`agent-mesh-flock-server`): reads and replays the log with no
  lock and no repair, stopping at a torn tail, so it runs beside a live server;
- **`amesh flock panes --name <flock> [--tab <id>] [--map member=pane]`**:
  read-only. Joins the roster to `herdr pane list` (a member is the pane whose
  label is its name, within `--tab`; `--map` overrides) and prints herdr's
  claims next to the verified flock state. It only ever lists; it never
  prompts, sends keys or renames. Off-roster panes are never shown. A VIA
  column says how a pane was linked: `map`, `session` or `label`;
- **the pane claim** (`Kind::Pane`): a session started inside a herdr pane
  (`HERDR_PANE_ID` and `HERDR_TAB_ID` both set) signs a `pane` event naming it;
  `CtlReq::Announce` repeats it. It is a *claim*: the signature proves the
  session said it, nothing proves the pane is real or still that pane. `panes`
  trusts only the active session's latest claim, only if herdr still lists
  that pane (in `--tab`, if given), ranks it below `--map` and above a label,
  and a pane two members claim is `ambiguous`. A replacement session is
  pending; once a hand-off activates it, the server's answer to "what is my
  head?" is the hand-off until its first event, so it can announce and emit.
  The server's first-link check is unchanged.

- **`watch --from (index, signed head)`** (library and `serve`; the `amesh flock
  watch` command is step 7b). One stream carries the replay, a `Caught` marker,
  then live frames, each exactly once: the server publishes a frame to a
  journal only after its fsync, and readers read the journal without the
  writer's lock. The resume token is the last signed admission record. The
  reader (`Reader`, in `agent-mesh-flock-session`) verifies every frame from
  its own saved head, so an older backup, a shorter history, or an altered
  prefix is refused as a `Rollback` whatever the server says; a server that
  forks different histories to different readers is not caught by one reader.
  The reader's state is one file (the verified frames) saved by write temp,
  fsync, rename, fsync directory; a head is witnessed only after that returns.
  A stream needs an *active* session of a *current* member signing a fresh
  challenge bound to the flock and the connection (a certified non-member, a
  pending or ended session, or a proof from another connection is refused),
  and it closes right after any epoch-bearing frame after which its session is no
  longer live or its member is no longer on the roster (a `session-end`, a
  hand-off away, or a roster change that drops a member). A `roster` that drops
  a name always carries its `epoch` in the same frame: the server's own roster
  path and a shepherd's roster event are sealed `roster, epoch`, and both readers
  (open/recovery and the follower) refuse a log where it is not. Adding members or
  changing devices or roles needs no bump. A request whose frame would not fit one
  stream message is refused (`TooLarge`) before it is committed, so every
  admitted frame can be watched. One reader per state directory (locked). Ceilings: the journal is in memory; the reader rewrites its
  whole file per save.

- **the CLI, first half (step 7a)**, Unix only, every write through a session
  process (the CLI holds no key and checks nothing admission decides):
  `join [--announce]` (who is this session), `inbox` (open briefs and reviews
  addressed to this session's member), `status` (lanes), `log [--from N]`
  (events with full content ids), and the writers `brief --to --lane`,
  `review --to --lane --head`, `take <cid>` (an `ack`), `result <brief>
  --outcome completed|failed`, `verdict <review> --head --approve|--reject`.
  The session is `--session <socket>`, else `AMESH_FLOCK_SESSION`, else the one
  live `run/session-*.sock` in `--dir`/`--name` (dead sockets skipped; none or
  several is an error that names them). Reads replay the log without its lock
  (as `panes` does) and do not check for rollback; only `watch` does.

**Planned, not built:** operator approval of a **delegate**
hand-off (#127's other half; waits on the delegate designation, step 13); device changes
signed by a listed device (server-signed only today); operator-signed events (`answer`); the rest of
the CLI (`run`, `watch`, `answer`) and the MCP tools (steps 7b, 7c); `amesh-tui`; attaching from another host; the
`amesh-herdr` adapter beyond the read-only view (nudges, `nudged`); native
newt receive. Until they land, lanes run on files
as the herdr-flock skill describes. Status: epic #109.

## Keep this current

Each flock step that changes behaviour updates this skill in the same PR.
