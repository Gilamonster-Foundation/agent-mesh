# agent-mesh-cli

Command-line interface for agent-mesh, shipped as the `amesh` binary. The
binary is a thin wrapper around the library's `Cli::parse` + `dispatch`, so
the surface area tested is the surface area shipped. Subcommands cover key
generation, binding your mesh identity to an external key system (GitHub),
identity inspection, peer verification, LAN announce/listen, and sending
messages.

Key subcommands:

- `amesh keygen` — generate a new user key
- `amesh bind` — bind your agent-mesh identity to an external key system
- `amesh whoami` — print the local user identity
- `amesh verify` — verify a peer's GitHub binding by fetching their public keys

Part of [agent-mesh](https://github.com/Gilamonster-Foundation/agent-mesh), cryptographic peer-to-peer agent coordination — no broker, no centralized configuration.

## License

Apache-2.0
