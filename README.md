# agent-mesh

Cryptographic peer-to-peer agent coordination.

A small Rust workspace that gives multi-agent systems a shared root of
trust (ed25519 user key, cross-signed by your existing GitHub SSH key)
and direct, verifiable peer messaging — no broker, no scp'd tokens,
no centralized configuration.

CLI: `amesh` (workspace member `agent-mesh-cli`).
Library: `agent-mesh-core` (identity types, signed envelopes).

License: Apache-2.0.

See the commit history (and the phased plan referenced therein) for
the current shape and trajectory of the project.
