# Agent Mesh × OpenRig — comparison and integration direction

**Status:** research + proposed direction. No implementation commitment.
**Date:** 2026-09-23
**Baseline:** agent-mesh `main` `14c145a` (v0.6.4) ·
[OpenRig](https://github.com/mvschwarz/openrig) `main` `c8fca9d` (v0.5.14)

---

## 1. Summary

OpenRig is a local control plane for multi-agent coding: a TypeScript daemon
(Hono + SQLite) that boots Claude Code, Codex and Pi into tmux panes from a
YAML **RigSpec**, snapshots and restores them, and relays messages between
them. Agent Mesh is an identity and transport layer. They sit at different
layers and barely overlap.

The useful finding is where OpenRig stops. It already runs across hosts and
already stamps a sender on every message. But its sender is a **self-asserted
name**, its cross-host trust is delegated to whatever network it runs on, its
bundles are checksummed but not signed, and its topology edges are drawn but
not enforced. Each of those is a gap Agent Mesh already fills.

**Direction:** make Agent Mesh the trust substrate under OpenRig, attached at
the four seams OpenRig already exposes (§4), as a sidecar rather than a fork.

## 2. What OpenRig is

| Concept | What it is |
|---|---|
| RigSpec | YAML: pods → members (runtime, agent_ref, cwd, model), edges, culture file, startup files, compose services, continuity policy |
| Seat | Stable role address `member@rig`; cross-host it becomes `member@rig@host` |
| Runtime adapters | `claude-code`, `codex`, `pi`, `terminal`, `stub` (`packages/daemon/src/adapters/`) |
| Messaging | `rig send` / `broadcast` / `chatroom` → daemon → text envelope injected into the recipient's tmux pane |
| Snapshot / restore | `rig down --snapshot`, `rig up`; restore reports per-seat *resumed / fresh / failed* |
| RigBundle | Portable archive: spec + vendored agent specs + per-file SHA-256 manifest |
| Cross-host | Host registry with `transport: ssh` (runs `rig` remotely over ssh) or `transport: http` (remote daemon, optional bearer token) |
| Surfaces | CLI, TUI, React UI, MCP server (`rig_up`, `rig_ps`, `rig_send`, …) |

A companion correction to earlier notes: OpenRig is **not** single-host. It
has had a cross-host host registry since the 0.5 line.

## 3. Where the trust boundary actually is

Each row quotes or cites OpenRig's own code or docs.

| Concern | OpenRig today | Agent Mesh equivalent |
|---|---|---|
| Sender identity | `OPENRIG_SESSION_NAME` env var → `X-OpenRig-Session` header; the daemon derives `From:` from it (`cli/src/sender-identity.ts`). A header-less send is delivered and labelled `<unknown sender>`. | `AgentKey` signed by `UserKey`; every frame is a `SignedEnvelope` with replay defence |
| Cross-host relay | The relay re-stamps the origin triple and it "rides verbatim" (`daemon/src/lib/pane-envelope.ts`) — the receiver trusts the forwarder | Cert chain checked at the QUIC handshake; the envelope signature survives relays |
| Cross-host auth | Bearer token optional: "host+VM are one founder-owned trust domain; **the mesh is the auth boundary**" (`cli/src/host-registry.ts`) | Auto-team rule, fail-closed: different user and no pact → rejected before any payload |
| Bundle integrity | "self-consistency verification, **not authenticity** … Future enhancement: cryptographic signing (Ed25519)" (`docs/reference/rig-bundle.md`) | ed25519 user key; `content_addressable` CIDs |
| Topology edges | `delegates_to` / `spawned_by` only order launches; edges "do NOT route messages … do NOT enforce delegation" (`docs/reference/edge-types.md`) | `Grant` / `Authority` with typed CIDs and the attenuation algebra (`agent-mesh-protocol/src/authority.rs`) |

OpenRig's "the mesh is the auth boundary" names an assumption, not a
component. Agent Mesh can be that component.

## 4. Integration direction: four seams, in order

Ordered by value per unit of coupling. Each seam stands alone and can be
tried, shipped or dropped without the others.

### S1 — Signed RigBundles (smallest; upstream already wants it)

Sign the bundle manifest with the author's `UserKey`, and identify the manifest
by a `content_addressable` CID instead of a hand-rolled map of SHA-256 hashes.
`rig bundle install` verifies both. This closes the gap OpenRig names as future
work, and it touches only the bundle path.

### S2 — Verified sender (the core value)

Issue one `AgentKey` per seat at `rig up`, with `AgentMetadata.role =
member@rig`. The seat sends a `SignedEnvelope` instead of a bare header, and the
daemon verifies it at ingress.

OpenRig's existing "deliver and label" policy maps onto this without a
behaviour break. The `From:` label gains a third state:

- **verified**: the envelope checks against a known seat key.
- **unverified**: a name was claimed with no valid signature.
- **unknown**: nothing was claimed; this is today's `<unknown sender>`.

Nothing is refused that is delivered today, so it can ship in observe mode
first. A per-rig flag can later turn it into rejection.

### S3 — `transport: amesh` host entries

Add a third `HostEntry` variant beside `ssh` and `http`. Cross-host `rig`
traffic then rides the authenticated QUIC transport, and the auto-team rule
replaces both optional bearer tokens and the tokenless "the network is trusted"
host. For hosts reached through a bastion, `agent-mesh-transport-ssh` already
covers what OpenRig's `ssh` transport does, with an authenticated inner session.

### S4 — Edges become grants (the product thesis; largest)

Compile each RigSpec edge into an agent-mesh `Grant`: `delegates_to`,
`escalates_to` and `collaborates_with` each become a scoped authority to
message a peer. The daemon then admits `rig send` only along a granted edge.
The topology the operator *draws* becomes the authority the system
*enforces*, and every admitted message cites a content-addressed grant.

This is the step that turns OpenRig's diagram into provenance. It needs its
own design pass, including the provenance audit and how grants rotate when a
seat's occupant changes on restore.

## 5. Shape of the integration

- **Sidecar, not fork.** OpenRig is TypeScript. Agent Mesh has Rust crates
  and Python bindings, but no Node binding. Start by calling the `amesh` CLI
  as a subprocess, which is the same pattern OpenRig's `cross-host-executor.ts`
  already uses to spawn `ssh`. Add a napi binding only if measured latency
  requires it.
- **Upstream-first.** S1 and S2 are small, self-contained changes to OpenRig.
  Propose them to the maintainer before building anything, and read the
  maintainer's own plans for signing first.
- **Other runtimes plug in by adapter.** OpenRig's runtime adapters are the
  extension point. Any harness we care about joins a rig the same way `pi` does
  (`pi-runtime-adapter.ts`), and that work is independent of this proposal.

## 6. Non-goals

- Adopting OpenRig's daemon, SQLite store or tmux transport into Agent Mesh.
- Building an orchestration or topology layer in Agent Mesh. That is
  OpenRig's layer; the charter keeps Agent Mesh below it, the same boundary
  drawn against A2A in [`a2a_interop.md`](a2a_interop.md).
- Choosing an operator cockpit. OpenRig overlaps heavily with Herdr-based
  dispatching, and that choice is separate from this proposal.

## 7. Falsification: first spike

The claim to test is that S2 fits OpenRig's send path without behaviour change.
Test it with one host and a two-seat rig:

1. Wrap `rig send` so the body travels in a `SignedEnvelope`, using the
   `amesh` CLI.
2. In the daemon's transport route, verify the envelope before
   `wrapPaneEnvelope` and render the three-state label.
3. Pass if existing sends are delivered byte-for-byte as before, forged
   `OPENRIG_SESSION_NAME` sends render **unverified**, and the added latency
   per send is measured and recorded.

If the spike needs changes beyond the transport route and `rig send`, the seam
is in the wrong place. Revisit §4 before going further.

## Sources

- OpenRig repository and reference docs: https://github.com/mvschwarz/openrig
  (`docs/reference/rig-spec.md`, `edge-types.md`, `rig-bundle.md`)
- Show HN, author's reply on isolation and trust:
  https://news.ycombinator.com/item?id=48241066
- Show HN, first launch: https://news.ycombinator.com/item?id=47772935
