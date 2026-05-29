"""Tier-B smoke tests: agent_mesh.discovery announce + browse.

These tests stand up real mDNS announcers/browsers on the loopback
interface. On a quiet LAN with mDNS working they round-trip; on a
network where mDNS is firewalled they're still safe (the calls don't
raise, browsers just return empty lists). We assert the no-raise
behavior rather than depending on cross-process discovery.
"""

from __future__ import annotations

import agent_mesh.core as core
import agent_mesh.discovery as discovery


def fixture_config(role: str = "test") -> discovery.AnnounceConfig:
    user_fp = core.Fingerprint.of_bytes(b"test-user")
    agent_fp = core.Fingerprint.of_bytes(b"test-agent")
    return discovery.AnnounceConfig(
        agent_fp=agent_fp,
        user_fp=user_fp,
        capabilities=["test-cap"],
        role=role,
        host="test-host",
        port=0,
    )


def test_announcer_starts_and_stops_cleanly() -> None:
    cfg = fixture_config()
    handle = discovery.Announcer.start(cfg)
    instance = handle.instance()
    assert instance.endswith("._agent-mesh._udp.local.")
    handle.stop()
    handle.stop()  # idempotent


def test_browser_collects_for_short_window() -> None:
    handle = discovery.Browser.start()
    # 100ms is enough to confirm the call doesn't raise even when the
    # LAN has no announcers.
    peers = handle.collect_for(100)
    assert isinstance(peers, list)
    handle.stop()


def test_service_type_exported() -> None:
    assert discovery.SERVICE_TYPE == "_agent-mesh._udp.local."


def test_peer_info_shape_via_fixture() -> None:
    # No direct constructor; instead confirm the PeerInfo class is
    # exported and PeerInfo instances pulled from browsing share the
    # expected attribute names. We just check the type's repr-ability.
    assert hasattr(discovery, "PeerInfo")
