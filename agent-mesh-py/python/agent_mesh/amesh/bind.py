"""``amesh bind github`` — cross-sign the user key with a GitHub SSH key.

Mirror of ``agent-mesh-cli/src/bind.rs``. The SSH key parse +
ed25519 cross-signature happen in Rust via
:class:`agent_mesh.core.GitHubBinding`; this module is the I/O shell
around it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from agent_mesh.core import GitHubBinding, UserKey


def default_ssh_key_path() -> Path:
    """``~/.ssh/id_ed25519``. Matches the Rust CLI default."""
    return Path.home() / ".ssh" / "id_ed25519"


def github(
    home: Path,
    ssh_key: Optional[Path],
    username: Optional[str],
) -> int:
    """Produce a :class:`GitHubBinding` and persist it as JSON.

    Mirrors the Rust binding command's output format byte-for-byte:
    the binding is written as ``user.github.sig`` (pretty-printed JSON
    via ``json.dumps(..., indent=2)``), and stdout reports the binding
    path, the optional username hint, and the first 16 hex chars of
    the SSH pubkey for visual confirmation.
    """
    user_key_path = home / "user.key"
    if not user_key_path.exists():
        print(
            f"error: load user key at {user_key_path} — "
            "run `amesh keygen` first",
            file=sys.stderr,
        )
        return 1
    user = UserKey.load(str(user_key_path))

    ssh_path = ssh_key or default_ssh_key_path()
    if not ssh_path.exists():
        print(
            f"error: read SSH key from {ssh_path}: file not found",
            file=sys.stderr,
        )
        return 1
    try:
        ssh_pem_bytes = ssh_path.read_bytes()
    except OSError as e:
        print(f"error: read SSH key from {ssh_path}: {e}", file=sys.stderr)
        return 1

    try:
        binding = GitHubBinding.sign(user.public(), ssh_pem_bytes, username)
    except Exception as e:  # noqa: BLE001 — surface any signing failure as a clean CLI error
        print(f"error: {e}", file=sys.stderr)
        return 1

    binding_path = home / "user.github.sig"
    binding_path.parent.mkdir(parents=True, exist_ok=True)
    binding_path.write_text(json.dumps(binding.to_json(), indent=2))

    print(f"github binding written to {binding_path}")
    if username:
        print(f"username hint: {username}")
    print(
        "ssh pubkey fingerprint (first 16 hex chars): "
        f"{binding.ssh_pubkey_hex()[:16]}"
    )
    return 0
