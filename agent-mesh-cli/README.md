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
- `amesh mcp` — serve the mesh over MCP (stdio JSON-RPC) so MCP-capable
  agents can drive it as tool calls

## MCP server

`amesh mcp` turns the mesh into three MCP tools — `mesh_whoami`,
`mesh_peers`, and `mesh_request` — so any MCP client (Claude Code,
drake, codex workers) can discover peers and exchange request/reply
messages without writing bus client code. Add it to an MCP client
config as:

```json
{ "mcpServers": { "amesh": { "command": "amesh", "args": ["mcp"] } } }
```

`mesh_request` forwards the topic and body verbatim (the payload schema
is the caller's contract with the peer — e.g. newt's
`newt/inference/v1` takes `{"prompt": ...}`). Pass `--quiet` to bind
without announcing: the server is a dial-out-only consumer and replies
still reach it via the bus's dial-back path.

Part of [agent-mesh](https://github.com/Gilamonster-Foundation/agent-mesh), cryptographic peer-to-peer agent coordination — no broker, no centralized configuration.

## License

Apache-2.0
