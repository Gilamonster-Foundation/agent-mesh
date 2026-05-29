"""agent-mesh: cryptographic peer-to-peer agent coordination.

Submodules
----------
- ``agent_mesh.core``       identity types, signed envelopes
- ``agent_mesh.discovery``  mDNS-based LAN discovery
- ``agent_mesh.transport``  authenticated QUIC transport via iroh
- ``agent_mesh.bus``        high-level pub/sub + request/reply
- ``agent_mesh.cli``        wrapper for the bundled ``amesh`` binary

Install: ``pip install agent-mesh``

A short example::

    import agent_mesh.core as core

    user = core.UserKey.generate()
    meta = core.AgentMetadata(
        role="my-agent",
        host="my-machine",
        capabilities=["inference"],
        issued_at="2026-05-29T00:00:00Z",
    )
    agent = core.AgentKey.issue(user, meta)
    print("agent fp:", agent.fingerprint().hex())
"""

from __future__ import annotations

import sys as _sys

# The native PyO3 extension module ships as `_agent_mesh` next to this
# package. It registers the four submodules below as attributes of
# the parent module.
from . import _agent_mesh as _native  # type: ignore[attr-defined]

# Re-export the four native submodules as plain Python attributes so
# users can write ``import agent_mesh.core`` (works via the import
# system mediated by ``_native.core``). We also stitch them into
# ``sys.modules`` so ``import agent_mesh.core`` works (Python's
# import system needs the submodule entries to resolve the dotted
# import).
core = _native.core
discovery = _native.discovery
transport = _native.transport
bus = _native.bus

_sys.modules["agent_mesh.core"] = core
_sys.modules["agent_mesh.discovery"] = discovery
_sys.modules["agent_mesh.transport"] = transport
_sys.modules["agent_mesh.bus"] = bus

# CLI wrapper around the bundled ``amesh`` binary.
from . import cli

__all__ = ["core", "discovery", "transport", "bus", "cli"]
