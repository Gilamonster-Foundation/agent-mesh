# agent-mesh-protocol

Cryptographic identity types and signed envelopes for agent-mesh. This crate
is the identity layer the rest of the workspace builds on: a per-user ed25519
root of trust, short-lived per-process agent sub-keys certified via cert
chains, and the signed wire format every mesh message is wrapped in. Wall-clock
time is treated as a claim, never as a coordination primitive.

Key types:

- `UserKey` — root of trust, one ed25519 keypair per user
- `AgentKey` / `CertChain` — short-lived per-process sub-key, certified by a `UserKey`;
  `AgentKey::issue_derived` derives a stable agent identity from the root and a
  name, without persisting the agent key
- `GitHubBinding` — cross-signature linking a `UserKey` to the ed25519 SSH key GitHub already knows
- `SignedEnvelope` — the wire format for every mesh message
- `Fingerprint` — short BLAKE3 identifier for keys and content

Part of [agent-mesh](https://github.com/Gilamonster-Foundation/agent-mesh), cryptographic peer-to-peer agent coordination — no broker, no centralized configuration.

## License

Apache-2.0
