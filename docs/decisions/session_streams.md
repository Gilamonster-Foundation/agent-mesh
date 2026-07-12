# Session streams: long-lived conversations over the bus

**Status:** proposed (design-only; awaiting review)
**Date:** 2026-07-12
**Driving consumer:** newt-mobile — the operator's phone driving a
newt-agent. This is the founding use case of agent-mesh: an operator
device and an agent finding each other and talking with cryptographic
trust, no broker, no copied tokens.

## Why this document exists

`agent-mesh-bus` today exposes `request`/`handle_requests` (one-shot)
and `publish_to`/`subscribe` (fire-and-forget). Its first consumer
(newt-mesh inference dispatch) was request/reply-shaped, so the bus
grew exactly that primitive — correctly.

The phone use case is conversation-shaped: a session that spans many
turns, where the agent pushes events (turn progress, token deltas,
diffs) without being polled. Nothing below the bus needs to change to
support this:

- `agent-mesh-transport::stream` already frames `SignedEnvelope`s over
  an iroh **bidi stream**, verified on receipt.
- The handshake, auto-team rule, and caveat machinery are
  session-agnostic — they gate the connection, not the exchange count.
- QUIC gives per-stream flow control (backpressure) for free.

The gap is one bus-level primitive: **keep the bidi stream open and
exchange N envelopes instead of 1.**

## Proposal

```rust
// Initiator
let session = bus.open_session(peer_fp, &topic).await?;   // Topic e.g. "newt/session/v1"
session.send(payload).await?;            // one SignedEnvelope per message
while let Some(msg) = session.recv().await? { /* verified payload */ }
session.close().await?;

// Responder
bus.handle_sessions(topic, |mut session| async move {
    while let Some(msg) = session.recv().await? {
        session.send(reply_bytes).await?;   // or push unprompted events
    }
    Ok(())
});
```

Semantics:

- **One QUIC bidi stream per session.** Stream close = session close;
  a clean-close frame distinguishes goodbye from failure.
- **One `SignedEnvelope` per message**, monotonic `sequence` per
  direction. Same signing/verification as every other envelope; a
  sequence gap or verify failure kills the session (fail-closed, like
  the handshake).
- **Authorization at open.** The responder checks the initiator's
  caveats against the session topic's capability tag before accepting
  (e.g. an AgentKey caveated to `newt-session` can open
  `newt/session/v1` and nothing else).
- **Full duplex.** Either side may send at any time — this is the
  property request/reply cannot fake and the reason polling is not an
  acceptable substitute.
- **Idle timeout + keepalive** with conservative defaults; mobile
  clients roam and sleep.

## Non-goals

- **No store, no replay.** agent-mesh is a causal-ordered messaging
  fabric, not a store (see standing project doctrine). A dropped
  session is re-opened by the initiator; recovering conversational
  state is the *consumer's* job (newt owns its session state).
- **No multi-party sessions.** Point-to-point only; fan-out stays in
  pub/sub.
- **No new discovery mechanism.** Sessions dial a fingerprint. mDNS
  remains the LAN convenience; direct-dial by fingerprint covers peers
  mDNS can't see (k8s pods behind a UDP NodePort, future off-LAN
  peers over Homestead).

## First consumers

1. **newt-agent** — a `newt/session/v1` responder: a gateway wrapping
   `TurnDriver` that streams turn events down the session. This is
   also newt's missing streaming seam — token-level streaming falls
   out of the transport instead of being bolted onto stdio ACP.
2. **newt-mobile** — the phone as a first-class mesh peer: its own
   caveat-limited AgentKey under the operator's UserKey, agent-mesh
   core built for Android via cargo-ndk behind flutter_rust_bridge
   (the PyO3 module already proves the FFI seam discipline).

## Alternatives considered

- **Request/reply polling.** Simulates push with a poll loop; wrong
  duplexity, wastes radio on mobile, and smuggles session state into
  every consumer. Rejected.
- **WebSocket gateway over SSH.** Works, but stands up a second trust
  system (SSH keys in a phone app, host-key pinning) that this
  project exists to replace. Rejected as a dead-end.
- **NATS.** Already litigated in `bus_vs_nats.md`; nothing here
  changes that verdict.

## Verification gates (implementation PRs, not this one)

- Companion example pair, matching the `bus_dispatch` precedent:
  `examples/session_chat.rs` — initiator + responder, multi-turn, one
  process.
- Loopback integration test: open/send/recv/push/close, sequence-gap
  kill, caveat-rejection at open.
- Cross-host LAN smoke via `amesh` (new `amesh session` subcommand,
  mirroring `send`/`listen`).
- `just check` + coverage bar per AGENTS.md.
