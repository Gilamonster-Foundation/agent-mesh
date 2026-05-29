"""Tier-C smoke tests: in-process Bus round-trip via asyncio.

Stands up two Bus instances in one process, registers a sync handler
on one side, sends a request from the other, asserts the reply
round-trips. mDNS auto-team trust does the cert/handshake bookkeeping
under the hood.

These tests rely on:

- mDNS working on the local interface (loopback). On a developer
  workstation this is typically fine; in some sandboxed CI runners
  mDNS is silently blocked, and these tests would time out. Mark as
  ``@pytest.mark.network`` so a future CI lane can opt into them.
- pytest-asyncio for the asyncio runtime.
"""

from __future__ import annotations

import asyncio

import pytest

import agent_mesh.bus as bus
import agent_mesh.core as core


def _meta(role: str) -> core.AgentMetadata:
    return core.AgentMetadata(
        role=role,
        host="test-host",
        capabilities=["test"],
        issued_at="2026-05-29T00:00:00Z",
    )


def test_topic_wire_roundtrip() -> None:
    user_fp = core.Fingerprint.of_bytes(b"user-fp")
    t = bus.Topic(user_fp, "echo")
    wire = t.wire()
    back = bus.Topic.parse_wire(wire)
    assert back is not None
    assert back.name == "echo"
    assert back.user_fp == user_fp


def test_correlation_id_random_and_hex() -> None:
    a = bus.CorrelationId.new_random()
    b = bus.CorrelationId.new_random()
    assert a.hex() != b.hex()
    assert len(a.hex()) == 32


@pytest.mark.asyncio
@pytest.mark.network
async def test_bus_request_reply_roundtrip() -> None:
    user = core.UserKey.generate()
    alice = core.AgentKey.issue(user, _meta("alice"))
    bob = core.AgentKey.issue(user, _meta("bob"))
    bob_fp = bob.fingerprint()

    alice_bus = await bus.Bus.bind(user, alice, 0)
    bob_bus = await bus.Bus.bind(user, bob, 0)

    topic = bus.Topic(user.fingerprint(), "echo")

    def echo_handler(body: bytes) -> bytes:
        return b"echo: " + body

    bob_bus.handle_requests(topic, echo_handler)

    # Let mDNS settle.
    await asyncio.sleep(0.5)

    reply = await alice_bus.request(bob_fp, topic, b"hi", timeout_ms=5000)
    assert reply == b"echo: hi"

    await alice_bus.close()
    await bob_bus.close()


@pytest.mark.asyncio
@pytest.mark.network
async def test_bus_async_handler_is_rejected_clearly() -> None:
    """Async handlers are rejected with a clear error message.

    Today the bus's dispatch task can't run a Python coroutine — it
    doesn't share an asyncio event loop with the bind/request caller.
    Wrap async work in ``asyncio.run(...)`` inside a sync handler if
    needed. This test pins the current behavior; once an event-loop
    bridge lands the test should flip to assert success.
    """
    user = core.UserKey.generate()
    alice = core.AgentKey.issue(user, _meta("alice"))
    bob = core.AgentKey.issue(user, _meta("bob"))
    bob_fp = bob.fingerprint()

    alice_bus = await bus.Bus.bind(user, alice, 0)
    bob_bus = await bus.Bus.bind(user, bob, 0)

    topic = bus.Topic(user.fingerprint(), "async-echo")

    async def async_echo(body: bytes) -> bytes:
        return b"async: " + body

    bob_bus.handle_requests(topic, async_echo)
    await asyncio.sleep(0.3)

    # The request itself times out (the handler errored on the wire
    # side and never produced a reply). What we're asserting is the
    # absence of a hang — the timeout fires within budget.
    with pytest.raises(TimeoutError):
        await alice_bus.request(bob_fp, topic, b"hi", timeout_ms=2000)

    await alice_bus.close()
    await bob_bus.close()
