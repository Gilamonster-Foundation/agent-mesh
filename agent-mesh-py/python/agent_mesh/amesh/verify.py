"""``amesh verify`` — verify a peer's GitHub binding.

Mirror of ``agent-mesh-cli/src/verify.rs``. Fetches
``https://github.com/<user>.keys`` (stdlib urllib, no extra deps) and
walks the response line-by-line until one ed25519 key validates the
binding, or we exhaust the list.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from agent_mesh.core import GitHubBinding


async def run(binding_path: Path, github_user: str) -> int:
    """Fetch GitHub keys and try each ed25519 line against the binding.

    The fetch is sync (stdlib urllib) but the surrounding entry point
    is async so the CLI dispatcher can treat verify/announce/peers/
    listen/send uniformly via ``asyncio.run``.
    """
    if not binding_path.exists():
        print(
            f"error: read binding from {binding_path}: file not found",
            file=sys.stderr,
        )
        return 1
    try:
        binding_data = json.loads(binding_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"error: read binding from {binding_path}: {e}", file=sys.stderr)
        return 1
    try:
        binding = GitHubBinding.from_json(binding_data)
    except Exception as e:  # noqa: BLE001 — surface parse failures cleanly
        print(f"error: parse binding: {e}", file=sys.stderr)
        return 1

    url = f"https://github.com/{github_user}.keys"
    try:
        with urlopen(url, timeout=10) as resp:  # noqa: S310 — github keys are public
            keys_text = resp.read().decode("utf-8")
    except URLError as e:
        print(f"error: fetch {url}: {e.reason}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 — last-ditch defensive
        print(f"error: fetch {url}: {e}", file=sys.stderr)
        return 1

    tried = 0
    for raw in keys_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Only attempt ed25519 lines; the binding signature is ed25519
        # so anything else is structurally incompatible.
        if not line.startswith("ssh-ed25519 "):
            continue
        tried += 1
        if binding.try_verify_ssh_line(line):
            print("binding verified")
            print(f"  agent-mesh user: {binding.user_public().fingerprint().hex()}")
            print(f"  github user:     {github_user}")
            return 0

    print(
        f"error: no ed25519 key in github.com/{github_user}.keys "
        f"verified the binding (tried {tried} keys)",
        file=sys.stderr,
    )
    return 1
