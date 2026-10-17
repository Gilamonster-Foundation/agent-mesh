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

Built (plan steps 1–3):
- the detached author `Assertion` (`agent-mesh-protocol`);
- the `agent-mesh-flock` model crate: schema, admission table, board fold;
- `agent-mesh-flock-server` (init, signed log, admission, recovery; the epoch
  counter is signed into each admission and verified on replay) and
  `amesh flock init`.

**Planned, not built:** invites, sessions, automatic epoch bumps, renewal and
hand-off;
`amesh flock session`; `watch`; the rest of the CLI (`join`, `inbox`, `take`,
`result`, `verdict`, `run`, `answer`); `amesh-tui`; attaching from another host;
the `amesh-herdr` adapter; native newt receive. Until they land, lanes run on
files as the herdr-flock skill describes. Status: epic #109.

## Keep this current

Each flock step that changes behaviour updates this skill in the same PR.
