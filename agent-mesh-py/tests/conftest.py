"""Shared pytest fixtures + markers."""

from __future__ import annotations


def pytest_configure(config):  # noqa: D401 (pytest hook)
    config.addinivalue_line(
        "markers",
        "network: tests that exercise real UDP/mDNS/QUIC — may fail in "
        "sandboxed CI runners with broadcast restrictions.",
    )
