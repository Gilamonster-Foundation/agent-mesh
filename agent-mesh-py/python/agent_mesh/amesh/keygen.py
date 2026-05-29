"""``amesh keygen`` — generate a new user key file on disk.

Mirror of ``agent-mesh-cli/src/keygen.rs``. Refuses to overwrite an
existing key — destroying a user's root key would silently invalidate
every binding and cert chain they've ever issued.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from agent_mesh.core import UserKey


def run(home: Path, path: Optional[Path]) -> int:
    """Generate a fresh user key and persist it.

    Returns a process exit code: 0 on success, 1 if a key already
    exists at the target path.
    """
    key_path = path or (home / "user.key")
    if key_path.exists():
        print(
            f"error: key already exists at {key_path} — refusing to overwrite",
            file=sys.stderr,
        )
        return 1

    key = UserKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key.save(str(key_path))

    fp = key.fingerprint()
    print(f"generated user key at {key_path}")
    print(f"fingerprint: {fp.hex()}")
    print(f"short:       {fp.short()}")
    return 0
