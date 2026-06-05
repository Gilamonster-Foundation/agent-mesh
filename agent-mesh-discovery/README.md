# agent-mesh-discovery

LAN discovery for agent-mesh via mDNS. Each agent advertises itself under the
service type `_agent-mesh._udp.local.` with a TXT record carrying BLAKE3
fingerprints of the agent and user public keys plus capability/role hints.
Records carry fingerprints only — full public keys are fetched later through
the authenticated transport handshake.

Key types:

- `Announcer` — starts an mDNS responder for this agent, alive until its `AnnouncerHandle` is dropped
- `Browser` — starts an mDNS browser and emits resolved `PeerInfo` records over a tokio `mpsc` channel

Part of [agent-mesh](https://github.com/Gilamonster-Foundation/agent-mesh), cryptographic peer-to-peer agent coordination — no broker, no centralized configuration.

## License

Apache-2.0
