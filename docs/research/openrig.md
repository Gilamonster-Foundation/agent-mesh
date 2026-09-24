# Agent Mesh × OpenRig: what each is for

**Status:** research and a scoping decision. No integration commitment.
**Date:** 2026-09-24
**Baseline:** agent-mesh `main` `14c145a` (v0.6.4) ·
[OpenRig](https://github.com/mvschwarz/openrig) `main` `c8fca9d` (v0.5.14)

---

## 1. Summary

**OpenRig coordinates multiple agents.** It is a TypeScript daemon
(Hono + SQLite) that boots Claude Code, Codex and Pi into tmux sessions from a
YAML **RigSpec**, gives each a stable seat address, relays messages between
seats, and snapshots and restores the whole team.

**Agent Mesh is about the conversation, not the team.** It covers messaging,
shared state and shared memory, and moving a conversation between harnesses,
hosts and surfaces. The in-repo statements of that purpose:

- [`floating_identity.md`](../decisions/floating_identity.md): "harnesses are
  fungible substrate — containers for conversational context; the context is
  the durable workload that floats over them."
- [`session_streams.md`](../decisions/session_streams.md): long-lived
  conversations over the bus. The founding use case is an operator's phone
  driving an agent.
- [`agent_mesh_store.md`](../decisions/agent_mesh_store.md): peer-to-peer
  shared knowledge for many agents bound to one identity.

The two overlap in messaging between agents. They are otherwise distinct.

## 2. Scoping decision

Agent Mesh had been expected to grow into multi-agent coordination: seats,
topologies, launch, and snapshot and restore. **It will not.** OpenRig already
does that, has real users, and is Apache-2.0. We adopt it for coordination.

Agent Mesh stays focused on its own purpose (§1). The features below may be
useful to OpenRig's community, but each is **tested on our own rigs before
anything is proposed upstream.** Nothing here has been offered to the OpenRig
maintainers.

## 3. What OpenRig is

| Concept | What it is |
|---|---|
| RigSpec | YAML: pods → members (runtime, agent_ref, cwd, model), edges, culture file, startup files, compose services, continuity policy |
| Seat | Stable role address `member@rig`; cross-host it becomes `member@rig@host` |
| Runtime adapters | `claude-code`, `codex`, `pi`, `terminal` (`packages/daemon/src/adapters/`) |
| Messaging | `rig send` / `broadcast` / `chatroom` → daemon → text envelope typed into the recipient's tmux pane |
| Snapshot / restore | `rig down --snapshot`, `rig up`; restore reports per-seat *resumed / fresh / failed* |
| RigBundle | Portable archive: spec + vendored agent specs + per-file SHA-256 manifest |
| Cross-host | Host registry with `transport: ssh` (run `rig` remotely) or `transport: http` (remote daemon, optional bearer token) |
| Surfaces | CLI, TUI, web UI, MCP server |

## 4. Where they differ

| Concern | OpenRig | Agent Mesh |
|---|---|---|
| Unit of work | A team of seats, in one daemon per host | A conversation, addressable by who it is and not where it runs |
| Continuity | Snapshot and restore a rig on its host | A conversation moves between harnesses, hosts and devices |
| Shared memory | Per-seat context, plus files the rig shares | Peer-to-peer store bound to one user identity (proposed) |
| Sender identity | `OPENRIG_SESSION_NAME` env var → `X-OpenRig-Session` header; header-less sends are delivered and labelled `<unknown sender>` (`cli/src/sender-identity.ts`) | `AgentKey` signed by `UserKey`; each frame a `SignedEnvelope` with replay defence |
| Cross-host trust | Optional bearer token; "the mesh is the auth boundary" (`cli/src/host-registry.ts`) | Cert chain checked at the handshake; auto-team rule, fail-closed |
| Bundle integrity | "self-consistency verification, not authenticity" (`docs/reference/rig-bundle.md`) | ed25519 user key; `content_addressable` CIDs |
| Topology edges | Only `delegates_to` / `spawned_by` affect launch order; edges "do NOT route messages … do NOT enforce delegation" (`docs/reference/edge-types.md`) | `Grant` / `Authority` with typed CIDs and an attenuation algebra (`agent-mesh-protocol/src/authority.rs`) |

## 5. Candidate augmentations: test first, then decide

Each is a hypothesis to try on our own rigs. Promote one only after it
survives use.

| Candidate | What it would add to OpenRig | Test that would justify it |
|---|---|---|
| Conversation mobility | Hand a seat's conversation to another surface (e.g. a phone) or host and back, with its state | Move a live seat's conversation off-host and back with no lost turns |
| Verified senders | `From:` gains *verified / unverified / unknown*, from a per-seat `AgentKey`; nothing delivered today is refused | A forged `OPENRIG_SESSION_NAME` renders *unverified*; normal sends are unchanged byte-for-byte |
| Signed RigBundles | Author authenticity on top of the existing SHA-256 self-consistency | A tampered bundle whose digest was recomputed fails install |
| Edges as grants | Only messages along a granted edge are admitted, each citing a content-addressed grant | A `rig send` along no edge is rejected, and the rejection is useful rather than obstructive |
| Shared tools (toolsmith role) | Seats share one toolchain: a toolsmith agent builds each tool and signs it with its agent-mesh identity; it is distributed through a Bazel-compatible REAPI cache and resolved by signed digest per job, so no seat installs its own. See the [Bazel Toolsmith Mesh epic](https://github.com/Gilamonster-Foundation/nessie-store/issues/120) | One tool, one toolsmith, one sandboxed seat: the seat resolves and runs the signed tool, and a tampered artifact is refused |

Mechanically, start with the `amesh` CLI as a subprocess. That is the same
pattern OpenRig's `cross-host-executor.ts` uses for `ssh`, and it needs no Node
binding until a measured need appears.

## 6. Non-goals

- Growing Agent Mesh into seats, topologies, launch or restore. That is
  OpenRig's job (§2).
- Taking on OpenRig's daemon, SQLite store or tmux transport.
- Proposing any of §5 upstream before it has been tested (§2).

## Sources

- OpenRig repository and reference docs: https://github.com/mvschwarz/openrig
  (`docs/reference/rig-spec.md`, `edge-types.md`, `rig-bundle.md`)
- Show HN, the author on isolation and trust:
  https://news.ycombinator.com/item?id=48241066
- Show HN, first launch: https://news.ycombinator.com/item?id=47772935
