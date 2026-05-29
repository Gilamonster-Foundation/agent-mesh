# agent-mesh

Cryptographic peer-to-peer agent coordination.

A small Rust workspace that gives multi-agent systems a shared root of
trust (ed25519 user key, cross-signed by your existing GitHub SSH key)
and direct, verifiable peer messaging — no broker, no scp'd tokens,
no centralized configuration.

CLI: `amesh` (workspace member `agent-mesh-cli`).
Libraries:

- `agent-mesh-core` — identity types, signed envelopes.
- `agent-mesh-discovery` — LAN discovery via mDNS.
- `agent-mesh-transport` — authenticated QUIC transport via iroh.

License: Apache-2.0.

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
