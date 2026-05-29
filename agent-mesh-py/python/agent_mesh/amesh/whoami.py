"""``amesh whoami`` — print the local user identity.

Mirror of ``agent-mesh-cli/src/whoami.rs``. Loads ``<home>/user.key``,
prints its fingerprint, then reports the GitHub binding state from
``<home>/user.github.sig`` (if present).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_mesh.core import UserKey


def run(home: Path) -> int:
    """Print user fingerprint + github binding hint.

    Returns 0 on success, 1 if no user key exists yet.
    """
    key_path = home / "user.key"
    if not key_path.exists():
        print(
            f"error: load {key_path} — run `amesh keygen` first?",
            file=sys.stderr,
        )
        return 1

    key = UserKey.load(str(key_path))
    fp = key.fingerprint()
    print(f"user fingerprint: {fp.hex()}")
    print(f"short:            {fp.short()}")

    binding_path = home / "user.github.sig"
    if binding_path.exists():
        # We only need the optional `github_username` field for the
        # hint — read the raw JSON rather than rebuilding the binding
        # object, so whoami doesn't fail loud on a partially-corrupt
        # binding file.
        try:
            data = json.loads(binding_path.read_text())
            username = data.get("github_username")
        except (json.JSONDecodeError, OSError):
            username = None
        if username:
            print(f"github binding:   {username} (hint)")
        else:
            print("github binding:   (no username hint)")
    else:
        print("github binding:   none (run `amesh bind github` to add one)")
    return 0
