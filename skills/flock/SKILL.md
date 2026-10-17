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

Built (plan steps 1–4 and the read-only herdr view, 4c):
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
  file ref) is required. Signed by an active shepherd, for a helper only: the
  shepherd, operator and adapter roles are refused, and so is a key merely
  certified by the user key (no operator approval until the roster binds
  operator devices). One
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
  CLI side so far is the library (`call`/`CtlReq`); the user-facing commands
  that use it come in step 7. Unix only.
- **`Snapshot`** (`agent-mesh-flock-server`): reads and replays the log with no
  lock and no repair, stopping at a torn tail, so it runs beside a live server;
- **`amesh flock panes --name <flock> [--tab <id>] [--map member=pane]`**:
  read-only. Joins the roster to `herdr pane list` (a member is the pane whose
  label is its name, within `--tab`; `--map` overrides) and prints herdr's
  claims next to the verified flock state. It only ever lists; it never
  prompts, sends keys or renames. Off-roster panes are never shown.

**Planned, not built:** the epoch bump when a member is removed from the
roster; operator device keys listed per device in the roster, and with them operator
approval of a shepherd or delegate hand-off (refused today), plus
operator-signed events; the pane announcement (a session telling the log which herdr pane it is in); `watch`; the rest of
the CLI (`join`, `inbox`, `take`, `result`, `verdict`, `run`, `answer`; only `init`,
`serve`, `invite`, `session` and `panes` exist); `amesh-tui`; attaching from another host; the
`amesh-herdr` adapter beyond the read-only view (nudges, `nudged`); native
newt receive. Until they land, lanes run on files
as the herdr-flock skill describes. Status: epic #109.

## Keep this current

Each flock step that changes behaviour updates this skill in the same PR.
