# agent-mesh-py

Python bindings for agent-mesh. This crate is the umbrella PyO3 extension
module: one cdylib (`_agent_mesh`) that stitches together the `pyo3_module`
registrations from the protocol, discovery, transport, and bus crates. It is
not published to crates.io; it ships to PyPI as the `newt-agent-mesh` package
(`pip install newt-agent-mesh`).

Part of [agent-mesh](https://github.com/Gilamonster-Foundation/agent-mesh), cryptographic peer-to-peer agent coordination — no broker, no centralized configuration.

## License

Apache-2.0
