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
- **byte strings**: keys, signatures, fingerprints and nonces are CBOR byte
  strings in the canonical encoding and on the session wire (they were arrays of
  one integer per byte: about 22% larger frames, and a size that varied with the
  key's bytes). JSON paths are unchanged. This changed every record id, so a
  flock created before it cannot be opened, and `init` will not reuse its
  directory (it refuses an existing `server.key`, genesis or log): create a new
  flock in a fresh directory, or move the old one aside first. Release note for
  agent-mesh-protocol: the Rust API is unchanged, its CBOR encoding is not (minor
  bump);
- **cited certificates**: a stored or streamed event carries its signature only.
  The certificate it was signed under is the one the server-signed
  `record.cert` names, and both are already in the log: the server's in genesis,
  a session's in its `session-start` or a `renewal`. A reader holding the log up
  to that point resolves it; a record citing a certificate the log does not hold
  is refused, and the certificate must still be one recorded for the event's
  author at the record's epoch. Event, record and certificate ids did not change.
  A brief frame went from 1699 to 543 bytes. The request an event arrives in
  (`Admit`) still carries its chain, and a hand-off's operator-device approval
  keeps its inline chain (that certificate is not in the log). Flocks made before
  this cannot be opened either: new flock, fresh directory;
- **MCP tools** (`amesh mcp --flock-session <sock>` or `AMESH_FLOCK_SESSION`,
  Unix): `flock_whoami`, `flock_inbox`, `flock_status` and `flock_emit{kind,
  refs, body}` join the `mesh_*` tools, only when a session is given. The
  socket is fixed at startup, bound to its flock (a socket that is not a live
  session of the flock holding it stops the server), and no tool takes one. The
  tools hold no key and make no policy check: `flock_emit` is the same single
  `Emit` the CLI sends, so the session signs, admission decides, and a refusal
  (a non-addressee's `ack`, any server-signed kind) comes back as the tool
  error with the log unchanged;
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
  A session's first event is checked the same way live and on replay: an activated replacement writes exactly the hand-off that activated it as `prev`; any other session writes no `prev` (it cannot chain onto a hand-off that was not its own).

- **`watch --from (index, signed head)`** (library, `serve` and the `amesh flock
  watch` command). One stream carries the replay, a `Caught` marker,
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
  `join [--announce]` (who is this session; its `state` is read from the log when a flock is named, the session's own `pending` is labelled as the enrollment-time flag), `inbox` (open briefs and reviews
  addressed to this session's member), `status` (lanes), `log [--from N]`
  (events with full content ids), and the writers `brief --to --lane`,
  `review --to --lane --head`, `take <cid>` (an `ack`), `result <brief>
  --outcome completed|failed`, `verdict <review> --head --approve|--reject`.
  The session is `--session <socket>`, else `AMESH_FLOCK_SESSION`, else the one
  live `run/session-*.sock` in `--dir`/`--name` (dead sockets skipped; none or
  several is an error that names them). When a flock is named, the session must belong to it (any selector; a session of another flock is refused before anything is sent); with none named the session alone decides. Reads replay the log without its lock
  (as `panes` does) and do not check for rollback; only `watch` does.
- **`run` and `watch` (step 7b)**, Unix only. `run --lane L [--label T] --
  <cmd>` emits a `job`, runs the command with inherited stdio, emits a `job-end`
  and exits like a shell (128 + signal). A `job-end` carries exactly one of
  `code` (it exited) and `signal` (a signal ended it): explicit fields, each
  skipped when absent so the exit-code form keeps its pinned id; admission
  refuses neither or both (`BadExit`). A command that cannot start is recorded
  as exit 127; but once the command has started, a failed wait writes no
  `job-end` (its outcome is unknown) and the job stays open, as it does if the
  `run` process itself is killed. `watch [--from N] [--once]` follows the log through a
  `Reader` kept in `<flock>/watch/<id>/` (the content id of the member's name,
  never the name itself as a path; both directories must be the user's own and
  closed to others, or the watch is refused): each frame is verified against
  the saved head, saved, and only then printed, so a run shows only what is new
  to that reader (`--from` also replays saved events from an index; `--once`
  stops at the `-- caught up --` marker). The stream challenge is signed by the
  session (`CtlReq::ProveStream`, only for its own flock, after renewing its
  certificate to the current epoch), so the CLI holds no key. A closed stream is an error exit with the server's reason.

- **read-side features (step 8a)**: `agent-mesh-flock-server` has a `serve`
  feature (the `Server`, entry/enrollment, sockets, key file, log writer and
  journal) and `agent-mesh-flock-session` an `emit` feature (the session
  process, its locked key, `CtlReq::Emit`/`Announce`). Both are on by default
  and nothing else changes. Without them the crates still verify and follow a
  log: `Snapshot`, `Follower`, `Reader`/`Watch`, `session_prover` (the
  `ProveStream` client) and the types. The workspace entries are
  `default-features = false`, so a member that writes asks for the writer
  (the CLI does); a read-only member (the TUI, step 8b) takes them as they
  stand. With both off, no signing or mutating API resolves for a consumer:
  `seal`, `RefusalEntry::sign`, `Server`, `init`, `Session`, the request
  variants `Invite`/`EnrollBegin`/`EnrollFinish`/`Renew`/`RenewFinish`/`Head`/
  `Admit`/`End` and `CtlReq::{Emit, Announce, End}` are all gated, and the held-key
  `key_prover` lives only in test code. What stays is verify, follow and watch
  (`Snapshot`, `Follower`, `Reader`/`Watch`, `session_prover`, the stream
  requests, `read_msg`/`write_msg` as plain framing). The session's proof
  renews its own certificate first (intended). `read_side_api.rs` proves it by
  compiling a scratch consumer (writer APIs must fail, the same lines must
  compile with the writer on, the read API must compile), and
  `agent-mesh-flock-session/tests/read_side.rs` enforces the feature names from
  `cargo tree -p … --format "{p}|{f}"` (per-package resolution; `cargo
  metadata` unifies features across the workspace and would always see the
  CLI's).

- **`amesh-tui` (step 8b)**, Unix only, a separate crate (`agent-mesh-tui`, bin
  `amesh-tui`): a read-only terminal view. `amesh-tui --dir <flock dir> --session
  <session socket> [--once]` follows the log through a verified, saved `Reader`
  (state under `<flock>/tui/<id of the member's name>/`, private to the user);
  the stream challenge is signed by the session (`ProveStream`), and the view
  holds no key and has no emit path. A session of another flock is refused
  before anything is read. The model is a pure fold of the verified log
  (`model.rs`); views are newtui components over it. Built: the header (flock,
  id, member count, `log ✓ N`, epoch, `live` / `stale since #n` / `✗ reason`) and
  the **Board** (each roster member: role, session state from the log, its own
  latest `status`, open work: jobs without a `job-end`, lanes briefed to it still
  submitted or working, unanswered asks; events since it last wrote). Not shown,
  because the log has no record of them: model, the herdr status tier (step 10),
  the delegate line (step 13), and refused events (`!`), which live in the
  server's refusal chain, not on the stream (said in the footer). `--once` prints
  one frame as text. Proofs: golden text screens (`UPDATE_SNAPSHOTS=1` rewrites),
  newtui's explorer (selection in range; no key changes the displayed data), a
  real server and session feeding the model, and the same cargo-tree and
  compile-probe checks as the read side (`tests_common::readside`) run against
  the TUI: neither writer feature resolves and no writer API can be named by a
  consumer of the crate. The Board scrolls to keep the selected member on screen (header and footer fixed). A frame whose checkpoint cannot be saved is rolled back by the reader itself (`Reader::follow` keeps nothing it did not save, and `Reader::open` makes a checkpoint it finds durable (file and directory fsync) before showing it, or does not open: a rename left visible by a failed directory fsync is never presented as saved until it will survive power loss), so the view and `amesh flock watch` only ever show the saved prefix; the TUI header says `cannot save the checkpoint` and keeps the last saved state. **Stream (step 8c)**: a second tab (`Tab`, or `1`/`2`) lists every admitted event in order (index, kind, signer, lane, one-line summary; conflicts marked) with kind / lane / member filters (`k` `l` `m` cycle through what the log has and back to all, `c` clears) and a follow mode (on at the start; moving up leaves it, `f` or `End` returns). An event's lane is its own or that of the event it answers. `Enter` opens the raw view: id, "✓ signature, session certificate and admission checked", signer (member, role, session fingerprint), lane, claimed time, parents (`prev` then references, numbered; `1`-`9` jump to one, `Backspace` returns; a filter that hides the parent is cleared), cited files and the pretty-printed body. Everything is folded from the verified board; nothing is fetched or checked again, and the event list is shared and extended between models. Everything drawn passes one function, `inert` (`ui/inert.rs`), which spells out control characters (C0 including ESC/BEL/CR/TAB, DEL, C1 including U+009B, and line/bidi/zero-width controls) as `\x1b`, `\r`, `\x9b` ...: a signature says who spoke, not that the text is safe to print, so a member's status, lane, label, file path or name cannot send the operator's terminal a command (tests: the screens carry no control character, and the bytes sent through a real crossterm backend carry only the renderer's own escapes). A signer is shown as member and session, with no role (the log knows only today's roster). `amesh flock log`/`watch`/`inbox` print member text raw and need the same treatment (follow-up). Lane and Waiting views are 8d-8e.

**Planned, not built:** operator approval of a **delegate**
hand-off (#127's other half; waits on the delegate designation, step 13); device changes
signed by a listed device (server-signed only today); operator-signed events (`answer`); the rest of
the CLI's `answer`; `amesh-tui`; attaching from another host; the
`amesh-herdr` adapter beyond the read-only view (nudges, `nudged`); native
newt receive. Until they land, lanes run on files
as the herdr-flock skill describes. Status: epic #109.

## Keep this current

Each flock step that changes behaviour updates this skill in the same PR.
