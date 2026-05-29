"""Subcommand handlers for the native-Python ``amesh`` CLI.

Each submodule implements one subcommand (``keygen``, ``whoami``,
``bind``, ``verify``, ``announce``, ``peers``, ``listen``, ``send``).
The dispatcher in :mod:`agent_mesh.cli` parses argv and calls into
these modules; nothing here knows about argparse.
"""

from __future__ import annotations

from . import (
    announce,
    bind,
    keygen,
    listen,
    peers,
    send,
    util,
    verify,
    whoami,
)

__all__ = [
    "announce",
    "bind",
    "keygen",
    "listen",
    "peers",
    "send",
    "util",
    "verify",
    "whoami",
]
