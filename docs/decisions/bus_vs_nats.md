# Gate-1 decision: agent-mesh-bus vs async-nats

**Status:** decided
**Date:** 2026-05-28 (Phase 3 close)
**Verdict:** **GO** — proceed to Phase 4 (newt-mesh integration).

## Why this document exists

Phase 3 of agent-mesh ships a working high-level pub/sub +
request-reply API (`agent-mesh-bus`). Before we invest in Phase 4
— wiring the bus into newt-mesh as the dispatch backbone — we owe
ourselves an honest comparison against the incumbent we'd otherwise
adopt: `async-nats` + a running `nats-server`. If async-nats turns
out to be the better tool for the drake-foreman dispatch loop, the
right answer is to halt this effort and reinvest in fixing NATS
pain points directly. If the bus is genuinely better for our
shape of problem, Phase 4 proceeds.

The two reference implementations are companion `[[example]]`
binaries in `agent-mesh-bus`:

* `examples/bus_dispatch.rs` — drake-foreman shape over agent-mesh-bus
* `examples/nats_dispatch.rs` — same shape over async-nats

Both must compile (`cargo build --example bus_dispatch -p agent-mesh-bus`,
`cargo build --example nats_dispatch -p agent-mesh-bus`). The bus
example runs end-to-end in one process. The NATS example needs a
running `nats-server`; that operational cost is itself a data point.

## The shared scenario

A foreman issues one task to a worker and reads the reply.

```text
Foreman: publishes a "job offer" with prompt "rename foo to bar"
Worker:  receives the offer, processes it, returns TaskReply {diff, model_id}
Foreman: prints the diff
```

This is intentionally the simplest drake-foreman shape — one job,
one worker, one reply. Both reference impls model the request as a
typed `TaskRequest` and the reply as a typed `TaskReply`, JSON-
encoded across the wire. The implementations live in
`agent-mesh-bus/examples/`.

## Side-by-side: setup cost

### agent-mesh-bus

```text
$ cargo build --example bus_dispatch -p agent-mesh-bus
$ cargo run   --example bus_dispatch -p agent-mesh-bus
worker qwen2.5-coder:32b: replied with diff:
--- a/foo
+++ b/bar
@@ -1 +1 @@
-rename foo to bar
+bar
```

Zero external services. The trust root is an in-memory
`UserKey::generate()`. Two `Bus` instances bind QUIC endpoints on
ephemeral ports, the same user fingerprint auto-teams them, the
job runs. No config files, no auth setup, no broker process.

### async-nats

```text
$ nats-server &        # not handled by `cargo run`; needs separate provisioning
[INF] Server is ready
$ cargo build --example nats_dispatch -p agent-mesh-bus
$ cargo run   --example nats_dispatch -p agent-mesh-bus
worker qwen2.5-coder:32b: replied with diff:
...
```

Compilation matches the bus exactly — `async_nats::connect` plus
`subscribe` / `request` / `publish`. Running requires a separate
`nats-server` process; in our production loop that means
provisioning, NKey credentials, subject permissions, monitoring,
TLS, and version-skew management. None of that lives in the
example file, but all of it lives in the operational footprint
that the example silently assumes.

This isn't theoretical. The pain that motivated agent-mesh in
the first place came from exactly this gap:

* NATS NKey duplication (gilabot#1334) — long-running tech debt
* NATS broker bootstrap on NUC k3s — port-allocation churn,
  service-account configs, `pipeline-secrets` Vault role missing
* Inter-machine credential plumbing — drake-codex-keys never landed
  cleanly because cred rotation across the NATS broker fanned out
  across three repos and a Vault scope.

## Side-by-side: the dispatch loop itself

Body counts come from `wc -l` on the example sources (whitespace,
comments, imports included — apples-to-apples).

| Dimension | agent-mesh-bus | async-nats |
|---|---|---|
| Lines of code (dispatch loop file) | 92 | 85 |
| Lines of running-services setup | 0 | ~30 (server config + Vault scope + systemd unit; not in the file) |
| Failure mode when peer is down | `BusError::Unreachable` immediate | `request` times out; broker still up |
| Failure mode when broker is down | N/A — there is no broker | total outage; every worker offline |
| Auth model | per-user ed25519 cert chain, auto-teamed | NKeys / JWT per subject, broker-enforced |
| Observability | per-peer logs; no central tap | central broker logs; `nats-top`, `nats stream report` |
| Crypto guarantee | each envelope signed by sender's agent key, payload BLAKE3-CID-bound | TLS between client+broker; payload integrity is application-level |
| Replay defense | nonce cache + per-peer monotonic sequence | application-level only (subject + reply-to don't carry one) |
| Cross-host story | mDNS today; QUIC underneath; NAT-traversal is a Phase 4 concern | broker forwards; cross-region needs JetStream replication or leaf nodes |
| Durability | none; messages live only as long as the connection | with JetStream: ack-tracked, persisted, replayable |
| Dependencies in the wire path | iroh QUIC + ed25519 | tokio TCP + broker + (optionally) JetStream storage |

## Honest downsides of the bus

The bus is not strictly better. Real costs:

1. **No central tap.** With NATS you can attach `nats-top` to a
   running broker and see every subject in the system. With the
   bus, observability is per-peer; the operator has to grep N logs
   instead of one. Until we ship an "observer" agent (a Phase 4.x
   item) this is genuinely worse.

2. **No durability or queue semantics.** If a worker is offline
   when the foreman publishes, the message is gone. NATS JetStream
   gives us ack-tracked, persisted, replayable streams; the bus
   does not. For drake-foreman this is acceptable because workers
   pull jobs (the foreman waits for a present worker via mDNS),
   but it's a real difference.

3. **mDNS is LAN-scoped.** Cross-network peers need either iroh's
   relay network (currently disabled — see `endpoint.rs`'s
   `N0DisableRelay`) or a separate rendezvous mechanism. NATS leaf
   nodes solve cross-network out of the box. Phase 4 will need to
   answer this.

4. **One agent per bus.** No per-process key rotation today;
   restart the bus to rotate. NATS clients can rotate credentials
   without restart.

5. **92 lines of dispatch-loop code vs 85.** The bus example is
   ~8% longer because the auto-team trust setup is explicit (you
   see the `UserKey`, the `AgentKey`s, the topic construction).
   With NATS, all of that is hidden behind `connect`. In
   production, where the trust setup is one-time and shared, this
   disappears — but it's a real ergonomic cost for "hello world".

## What the bus genuinely buys us

These map directly to the original NATS pain points:

1. **Broker-free.** There is no `nats-server` to provision,
   monitor, or rotate creds against. Every pain point listed in the
   "NATS NKey duplication" memory item collapses to zero.

2. **Per-message provenance.** Every envelope is signed by an
   agent key, which is signed by a user key. The receiver can
   prove, post-hoc, who sent each message. NATS only proves who
   *connected* to the broker; the broker is a trust bottleneck.

3. **Replay defense is in the protocol.** The nonce cache and
   per-peer sequence tracker run on every incoming envelope. With
   NATS we'd be writing this at the application layer for every
   subject.

4. **Trust setup is the cert chain, not a config file.** Two
   agents with the same `user_fp` auto-team. Setting up the
   matching NATS user/JWT for a new worker is multi-step and
   often fails silently in production.

5. **Operational footprint matches the problem.** drake-foreman
   runs N small worker processes on a handful of machines; the
   bus is N processes that find each other and talk. NATS is N
   processes plus a broker plus the broker's credentials plus the
   broker's HA story.

## Verdict: GO

**Phase 4 (newt-mesh integration) proceeds.**

Reasoning:

The bus's ~8% line-count overhead in the example file is real
but trivial once amortized — most of it is the trust-setup that's
done once per deployment in production. The genuine downsides
(no central tap, no durability, LAN-only today) are addressable
within the agent-mesh roadmap and are smaller than the operational
gain of deleting the NATS broker from our stack. The provenance
and replay-defense gains are properties we'd otherwise be
implementing on top of NATS anyway.

The dispatch loop compiles and runs against `agent-mesh-bus` with
zero external services. That is the bar. Everything past it is
Phase 4 work.

Proceeding to Phase 4 (newt-mesh integration).
