# Session streams: long-lived conversations over the bus

**Status:** implemented (agent-mesh#84) — see "As built" below
**Date:** 2026-07-12 (proposed), 2026-09-29 (implemented)
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

## As built (agent-mesh#84)

The shape above shipped with these decisions made concrete:

- **API.** `Bus::open_session(peer_fp, &topic)` /
  `Bus::open_session_direct(PeerEndpoint, &topic)` return a `Session` once
  the responder accepts. `Bus::handle_sessions(topic, handler)` hands each
  open to `handler` as an `IncomingSession` **before any data flows**; the
  handler reads `peer()` (verified user + agent fingerprints and the
  `CertChain` that signed the open) and calls `accept()` or
  `refuse(reason)`. Dropping it undecided drops the stream, which the opener
  sees as a failed open. An open on a topic with no handler is refused.
  Authorization is the handler's call on that certificate — the bus carries
  the evidence rather than guess a topic→capability mapping.
- **Wire.** Every frame is an ordinary `SignedEnvelope` addressed
  `Recipient::Direct` to the peer, with a JSON payload
  `{"session": <16-byte id>, "kind": open|accept|refuse|data|keepalive|close, …}`.
  The opener picks the random id; `open` carries the wire-form topic,
  `refuse` a reason, `data` the message bytes.
- **Ordering.** The envelope `sequence` is the frame's position in its own
  direction, from `0` for the first frame (`open` / `accept` / `refuse`), and
  must arrive exactly next: a duplicate, regression or gap ends the session.
- **Admission.** Each frame passes the same immutable checks as every other
  envelope (`inbox::admit`: verify, carrier is signer, same user, addressed
  here) against the peer the stream authenticated at open. Frames bypass the
  bus-wide nonce cache and sequence tracker — the stream binding, session id
  and exact-next sequence are the replay defense, and a session never spends
  the sender's one-shot sequence space.
- **Close vs failure.** `close()` sends a `close` frame and finishes the
  stream; the peer's `recv` returns `Ok(None)`. A stream that ends without
  one is `BusError::PeerDisconnected`. Any failure ends the session for good.
- **Liveness.** A session with nothing arriving for 60 s fails with
  `BusError::Timeout`; each side sends a `keepalive` every 15 s while its
  writer is idle. The keepalive task is aborted when the session's last half
  is dropped.
- **Backpressure.** `recv` reads straight off the stream and is cancel-safe;
  nothing buffers frames a consumer has not asked for, so a stalled consumer
  stalls its peer's `send` through QUIC flow control. A `send` cancelled
  mid-frame ends the session for sending rather than follow a torn frame.
- **Shutdown.** Dropping or closing the bus ends every session it opened or
  accepted (`BusError::NotRunning`).
- **Transports.** `Transport` gained `open_stream_to` /
  `open_stream_to_endpoint` (default: unsupported) and `Inbound.stream`; only
  `IrohTransport` carries sessions today.

Not yet built from the gates below: the `session_chat` example and the
`amesh session` subcommand. Timings are fixed defaults, not options.

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
