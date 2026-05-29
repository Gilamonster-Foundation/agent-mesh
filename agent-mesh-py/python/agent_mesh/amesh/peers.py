"""``amesh peers`` — list LAN peers seen via mDNS.

Mirror of ``agent-mesh-cli/src/peers.rs``. Collects ``Resolved``/
``Removed`` events for the requested listen window via
:class:`agent_mesh.discovery.Browser`, then prints a tabular summary
tagged with ``SAME?`` based on the local user fingerprint.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from agent_mesh.core import UserKey
from agent_mesh.discovery import Browser

from . import util


async def run(home: Path, listen: str, same_user_only: bool) -> int:
    """Browse for ``listen`` seconds, then print the table.

    Returns 0 even on an empty result — discovery silence is a valid
    state (no peers on the LAN). Returns 1 if the user key is missing
    or the listen duration parses badly.
    """
    key_path = home / "user.key"
    if not key_path.exists():
        print(
            f"error: load {key_path} — run `amesh keygen` first",
            file=sys.stderr,
        )
        return 1
    user = UserKey.load(str(key_path))
    our_user_fp = user.fingerprint()

    try:
        dur_s = util.parse_duration(listen)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"listening for peers for {dur_s}s...")

    handle = Browser.start()
    try:
        # The pyo3 Browser binding is synchronous (mDNS daemon runs in
        # a background thread); run the blocking collect in a worker
        # thread so we don't peg the asyncio loop.
        duration_ms = int(dur_s * 1000)
        peers = await asyncio.to_thread(handle.collect_for, duration_ms)
    finally:
        handle.stop()

    # Dedupe by instance name (Resolved events can repeat as TTLs
    # refresh); the Rust CLI uses a HashMap keyed on instance.
    seen: dict[str, object] = {}
    for p in peers:
        seen[p.instance] = p

    filtered = [
        p
        for p in seen.values()
        if (not same_user_only) or p.is_same_user(our_user_fp)
    ]
    filtered.sort(key=lambda p: (p.role, p.host))

    print()
    print(f"discovered {len(filtered)} peer(s):")
    print()
    print(
        f"{'AGENT':<14} {'SAME?':<6} {'ROLE@HOST':<24} {'PORT':<6} CAPABILITIES"
    )
    for p in filtered:
        same_marker = "yes" if p.is_same_user(our_user_fp) else "no"
        role_host = f"{p.role}@{p.host}"
        caps = ",".join(p.capabilities)
        agent_short = p.agent_fp.short()
        print(
            f"{agent_short:<14} {same_marker:<6} {role_host:<24} "
            f"{p.port:<6} {caps}"
        )
    return 0
