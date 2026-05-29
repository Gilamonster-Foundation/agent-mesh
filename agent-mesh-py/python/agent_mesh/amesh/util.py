"""Shared helpers for the amesh CLI subcommand modules.

Only utilities that more than one subcommand needs live here:

* ``parse_duration`` — small-and-fast `5s` / `2m` / `1h` parser
  mirroring `agent-mesh-cli/src/util.rs::parse_duration`.
* ``current_hostname`` — best-effort hostname; falls back to
  ``"unknown-host"`` like the Rust CLI.
* ``now_rfc3339`` — current UTC time, second granularity, suitable as
  an ``issued_at`` claim on an agent metadata cert. Wall-clock here is
  an *audit claim* in a signed cert, not a coordination primitive —
  same caveat as the Rust side.
"""

from __future__ import annotations

import datetime as _dt
import socket as _socket
from typing import Final

_BAD_DURATION: Final = (
    "invalid duration {s!r} — expected e.g. '5s', '2m', '1h', '500ms'"
)


def parse_duration(s: str) -> float:
    """Parse `'100ms'` / `'5s'` / `'2m'` / `'1h'` into a float of seconds.

    Bare digits are interpreted as seconds, matching the Rust CLI's
    duration parser. Raises :class:`ValueError` on garbage so callers
    can surface a clean error message.
    """
    if not s:
        raise ValueError(_BAD_DURATION.format(s=s))
    try:
        if s.endswith("ms"):
            return int(s[:-2]) / 1000.0
        if s.endswith("s"):
            return float(int(s[:-1]))
        if s.endswith("m"):
            return float(int(s[:-1]) * 60)
        if s.endswith("h"):
            return float(int(s[:-1]) * 3600)
        return float(int(s))
    except ValueError as e:
        raise ValueError(_BAD_DURATION.format(s=s)) from e


def current_hostname() -> str:
    """Best-effort short hostname. Falls back to ``'unknown-host'``."""
    try:
        h = _socket.gethostname().strip()
        return h or "unknown-host"
    except OSError:
        return "unknown-host"


def now_rfc3339() -> str:
    """Current UTC time as ``YYYY-MM-DDTHH:MM:SSZ`` (seconds, UTC).

    Used as the ``issued_at`` claim on ephemeral agent cert metadata.
    """
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    # `isoformat()` would render `+00:00`; the Rust CLI's
    # `to_rfc3339_opts(SecondsFormat::Secs, true)` renders `Z`. Match it.
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")
