"""Tier-C smoke tests: agent_mesh.transport endpoint bind/close."""

from __future__ import annotations

import pytest

import agent_mesh.core as core
import agent_mesh.transport as transport


def _agent() -> core.AgentKey:
    user = core.UserKey.generate()
    meta = core.AgentMetadata(
        role="test",
        host="test-host",
        capabilities=["test"],
        issued_at="2026-05-29T00:00:00Z",
    )
    return core.AgentKey.issue(user, meta)


@pytest.mark.asyncio
@pytest.mark.network
async def test_endpoint_bind_and_close() -> None:
    agent = _agent()
    ep = await transport.Endpoint.bind(agent, 0)
    port = await ep.local_port()
    assert isinstance(port, int)
    assert port > 0
    addrs = await ep.local_socket_addrs()
    assert isinstance(addrs, list)
    assert len(addrs) >= 1
    await ep.close()
    # close is idempotent
    await ep.close()


def test_alpn_constant_exported() -> None:
    assert hasattr(transport, "ALPN")
    assert isinstance(transport.ALPN, bytes)
    assert transport.ALPN == b"agent-mesh/v1"
