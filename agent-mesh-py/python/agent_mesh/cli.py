"""Wrapper around the bundled ``amesh`` CLI binary.

When the user installs ``agent-mesh`` from a wheel that bundles the
``amesh`` binary (the recommended distribution), the binary is placed
on ``$PATH`` automatically by pip's wheel installer. This module
exposes ``amesh`` from Python via ``os.execvp`` so callers can do::

    python -m agent_mesh announce --capability ollama --role demo

or simply::

    amesh announce --capability ollama --role demo

A separately-installed ``amesh`` binary works the same way.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import NoReturn, Sequence


def binary_path() -> str:
    """Locate the ``amesh`` binary, raising if it's missing."""
    found = shutil.which("amesh")
    if found is None:
        raise RuntimeError(
            "amesh binary not on PATH. "
            "Did `pip install agent-mesh` complete successfully? "
            "If you installed from source, try `cargo install --path agent-mesh-cli`."
        )
    return found


def main(argv: Sequence[str] | None = None) -> NoReturn:
    """Hand off to the ``amesh`` binary with the given argv."""
    if argv is None:
        argv = sys.argv[1:]
    # Confirm the binary exists before exec — gives a much nicer error
    # than a bare OSError if the user typo'd their install path.
    binary_path()
    os.execvp("amesh", ["amesh", *argv])
