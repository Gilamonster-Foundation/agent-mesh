# agent-mesh-bus

High-level pub/sub + request-reply API over the agent-mesh transport. Topics
are namespaced to the issuing user's fingerprint, so two unrelated users on
the same LAN can never collide, and a replay defense layer rejects duplicate
nonces and out-of-order sequence numbers from known peers.

Key types:

- `Bus` — the high-level pub/sub + request/reply surface
- `Topic` — pub/sub names scoped to the issuing user's fingerprint
- `Inbox` / `BusMessage` — application-level message dispatch
- `replay::NonceCache` / `replay::SequenceTracker` — replay defense

Part of [agent-mesh](https://github.com/Gilamonster-Foundation/agent-mesh), cryptographic peer-to-peer agent coordination — no broker, no centralized configuration.

## License

Apache-2.0
