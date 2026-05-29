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

License: Apache-2.0.

## Discovery (Phase 1)

`amesh` can announce itself on the LAN and list every other agent it
sees there, with no broker or central registry. Service type:
`_agent-mesh._udp.local.`

```sh
# Terminal A — announce this agent for 5 minutes, advertising
# `ollama` and `vllm` capabilities under the role `newt-worker`.
amesh announce --capability ollama --capability vllm \
                --role newt-worker --duration 5m

# Terminal B — list everyone on the LAN for the next 5 seconds.
amesh peers --listen 5s

# Or only those sharing our user fingerprint:
amesh peers --listen 5s --same-user
```

Sample `amesh peers` output:

```
listening for peers for 5s...

discovered 2 peer(s):

AGENT          SAME?  ROLE@HOST                PORT   CAPABILITIES
abcd12345678   yes    newt-worker@geforcenuc   0      ollama,vllm
ef9876543210   no     drake-foreman@gnuc       0      orchestrator
```

The fingerprints in mDNS TXT records are *claims* — Phase 2 will add
the transport handshake that verifies them against the actual peer
public key. For now, discovery + listing only; no messaging yet.

See the commit history (and the phased plan referenced therein) for
the current shape and trajectory of the project.
