<div align="center">
  <img src="docs/logo/agent-mesh-256.png" alt="agent-mesh" width="160" height="160">

  # agent-mesh

  **Cryptographic peer-to-peer agent coordination.**

  *No broker. No scp'd tokens. No centralized configuration.*

  [![CI](https://github.com/Gilamonster-Foundation/agent-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/Gilamonster-Foundation/agent-mesh/actions/workflows/ci.yml)
  [![PyPI](https://img.shields.io/pypi/v/agent-mesh.svg)](https://pypi.org/project/agent-mesh/)
  [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
</div>

---

A small Rust workspace that gives multi-agent systems a shared root of
trust (ed25519 user key, cross-signed by your existing GitHub SSH key)
and direct, verifiable peer messaging.

Two agents that share a user identity discover each other on the LAN,
authenticate via cert chain at the QUIC handshake, and exchange signed
envelopes — without a broker in the middle and without scp'ing tokens
around.

CLI: `amesh` (workspace member `agent-mesh-cli`).
Libraries:

- `agent-mesh-core` — identity types, signed envelopes.
- `agent-mesh-discovery` — LAN discovery via mDNS.
- `agent-mesh-transport` — authenticated QUIC transport via iroh.
- `agent-mesh-bus` — high-level pub/sub + request/reply.
- `agent-mesh-py` — Python bindings (PyPI package `agent-mesh`).

License: Apache-2.0.

## Python install

```sh
pip install newt-agent-mesh
```

(The PyPI distribution name is `newt-agent-mesh` because `agent-mesh`
is blocked by PyPI's similarity check — see the note in
`pyproject.toml`. The Python import path is unchanged:
`import agent_mesh.core`.)

This installs the Python package `agent_mesh` with submodules
`.core`, `.discovery`, `.transport`, `.bus`. The `amesh` CLI binary
ships separately — install it with `cargo install --path agent-mesh-cli`
if you want it on `$PATH`.

## Discovery (Phase 1)

`amesh` can announce itself on the LAN and list every other agent it
sees there, with no broker or central registry. Service type:
`_agent-mesh._udp.local.`

```sh
# Terminal A — announce this agent for 5 minutes, advertising
# `ollama` and `vllm` capabilities under the role `inference-worker`.
amesh announce --capability ollama --capability vllm \
                --role inference-worker --duration 5m

# Terminal B — list everyone on the LAN for the next 5 seconds.
amesh peers --listen 5s

# Or only those sharing our user fingerprint:
amesh peers --listen 5s --same-user
```

Sample `amesh peers` output:

```
listening for peers for 5s...

discovered 2 peer(s):

AGENT          SAME?  ROLE@HOST                     PORT   CAPABILITIES
abcd12345678   yes    inference-worker@host-a       0      ollama,vllm
ef9876543210   no     orchestrator@host-b           0      orchestrator
```

The fingerprints in mDNS TXT records are *claims*; verification
happens during the Phase 2 transport handshake (below).

## Transport (Phase 2)

Phase 2 layers an authenticated QUIC transport on top of Phase 1
discovery. Two architectural notes:

- The agent's ed25519 signing key doubles as its iroh `EndpointId`,
  so a peer who knows your agent fingerprint already knows enough to
  address your iroh endpoint. No separate "node ID" to manage.
- After ALPN negotiation (`agent-mesh/v1`), both ends exchange cert
  chains and enforce the **auto-team rule** fail-closed: if peer
  `user_pubkey != ours` and no pact exists, the handshake rejects
  before any payload data crosses the boundary.

The CLI splits "I want to be discovered" from "I want to be
reachable":

| Subcommand | Discoverable? | Reachable (QUIC)? |
|------------|---------------|-------------------|
| `amesh announce` | yes | no (publishes port 0) |
| `amesh listen`   | yes | yes (binds + announces) |

End-to-end smoke (same user on two terminals):

```sh
# Terminal A — bind QUIC, announce on mDNS, accept envelopes
amesh listen --duration 60s
# prints:
#   listening on udp/<port>
#     agent_fp=<fp>
#     user_fp =<user_fp>

# Terminal B — within that 60s window:
amesh send <fp-from-terminal-A> --payload '{"hello":"world"}'
# Terminal A then prints one JSON line per received envelope:
#   {"sender_agent_fp":"...","sender_user_fp":"...","sequence":0,
#    "payload":{"encoding":"utf8","text":"{\"hello\":\"world\"}"}}
```

If you point `amesh send` at a peer that belongs to a different
user, the handshake closes the connection cleanly and both sides
report `auto-team check failed: ...`.

## Python Usage

Install the wheel:

```sh
pip install newt-agent-mesh
```

(See the install section above for why the distribution name is
`newt-agent-mesh` and not `agent-mesh`. The import path is unchanged.)

Identity round-trip — no network required:

```python
import agent_mesh.core as core

# Generate a user key (root of trust).
user = core.UserKey.generate()
print("user fp:", user.fingerprint().hex())

# Issue an agent key signed by that user.
meta = core.AgentMetadata(
    role="my-agent",
    host="my-machine",
    capabilities=["inference"],
    issued_at="2026-05-29T00:00:00Z",
)
agent = core.AgentKey.issue(user, meta)
print("agent fp:", agent.fingerprint().hex())

# Build and verify a signed envelope.
recipient = core.Recipient.topic("hello/world")
env = core.SignedEnvelope(agent, recipient, sequence=1, payload=b"hi")
env.verify()  # raises core.MeshError on tamper
```

Request/reply over an authenticated mesh — needs mDNS on the LAN:

```python
import asyncio
import agent_mesh.core as core
import agent_mesh.bus as bus


async def main() -> None:
    user = core.UserKey.generate()
    meta = core.AgentMetadata(
        role="echo",
        host="localhost",
        capabilities=["test"],
        issued_at="2026-05-29T00:00:00Z",
    )
    server_agent = core.AgentKey.issue(user, meta)
    client_agent = core.AgentKey.issue(user, meta)

    server_bus = await bus.Bus.bind(user, server_agent, 0)
    client_bus = await bus.Bus.bind(user, client_agent, 0)

    topic = bus.Topic(user.fingerprint(), "echo")
    server_bus.handle_requests(topic, lambda body: b"echo: " + body)

    # Let mDNS settle.
    await asyncio.sleep(0.5)

    reply = await client_bus.request(
        server_bus.agent_fingerprint(),
        topic,
        b"hi",
        timeout_ms=5000,
    )
    print(reply)  # b'echo: hi'

    await server_bus.close()
    await client_bus.close()


asyncio.run(main())
```

The handler must return `bytes` directly. Async handlers (callables
that return a coroutine) are recognized and rejected in this release;
wrap any async work in `asyncio.run(...)` inside the sync handler.
