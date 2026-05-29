"""``amesh announce`` — broadcast this agent's presence on the LAN.

Mirror of ``agent-mesh-cli/src/announce.rs``. Issues an ephemeral
AgentKey, stands up an mDNS announcer, and holds it alive either for
a bounded duration or until Ctrl-C.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

from agent_mesh.core import AgentKey, AgentMetadata, UserKey
from agent_mesh.discovery import AnnounceConfig, Announcer

from . import util


async def run(
    home: Path,
    capabilities: List[str],
    role: str,
    host: Optional[str],
    duration: Optional[str],
) -> int:
    """Start the announcer and block until duration / Ctrl-C.

    ``duration=None`` runs forever (until SIGINT). Returns 0 on a
    clean shutdown, 1 if the user key is missing or duration parses
    badly.
    """
    key_path = home / "user.key"
    if not key_path.exists():
        print(
            f"error: load {key_path} — run `amesh keygen` first",
            file=sys.stderr,
        )
        return 1
    user = UserKey.load(str(key_path))

    resolved_host = host or util.current_hostname()
    meta = AgentMetadata(
        role=role,
        host=resolved_host,
        capabilities=list(capabilities),
        issued_at=util.now_rfc3339(),
    )
    # Ephemeral per-announce agent — never persisted, lives only as
    # long as the announcer task. Matches the Rust CLI's posture.
    agent = AgentKey.issue(user, meta)
    agent_fp = agent.fingerprint()
    user_fp = user.fingerprint()

    config = AnnounceConfig(
        agent_fp=agent_fp,
        user_fp=user_fp,
        capabilities=list(capabilities),
        role=role,
        host=resolved_host,
        port=0,
        # `amesh announce` is discovery-only — no transport bound, so
        # no agent pubkey is published. Peers who want to dial us
        # should use `amesh listen` instead.
        agent_pubkey=None,
    )
    handle = Announcer.start(config)

    print(
        f"announcing as agent_fp={agent_fp.hex()} user_fp={user_fp.hex()}"
    )
    print(
        f"  role={role} host={resolved_host} "
        f"capabilities={list(capabilities)!r}"
    )

    try:
        if duration is not None:
            try:
                dur_s = util.parse_duration(duration)
            except ValueError as e:
                handle.stop()
                print(f"error: {e}", file=sys.stderr)
                return 1
            print(f"  duration={dur_s}s")
            await asyncio.sleep(dur_s)
            print(f"announce duration {dur_s}s elapsed; stopping")
        else:
            print("  ctrl-c to stop")
            # Block forever; KeyboardInterrupt is handled in the
            # outer dispatcher.
            await asyncio.Event().wait()
    finally:
        handle.stop()
    return 0
