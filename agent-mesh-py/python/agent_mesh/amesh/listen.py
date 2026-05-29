"""``amesh listen`` — bind QUIC, announce on mDNS, print received envelopes.

Mirror of ``agent-mesh-cli/src/listen.rs``. Each accepted envelope is
verified inside the pyo3 binding (cert chain, payload CID, agent
signature) before it lands here; we just format the audit record.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from agent_mesh.core import AgentKey, AgentMetadata, UserKey
from agent_mesh.discovery import AnnounceConfig, Announcer
from agent_mesh.transport import Endpoint

from . import util


def _payload_view(payload: bytes) -> Dict[str, Any]:
    """UTF-8 if valid, else hex. Mirrors `listen.rs::PayloadView`."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return {"encoding": "hex", "hex": payload.hex()}
    return {"encoding": "utf8", "text": text}


async def run(home: Path, duration: Optional[str]) -> int:
    """Bind, announce, accept envelopes until duration / Ctrl-C.

    Returns 0 on a clean shutdown. Returns 1 if the user key is
    missing or duration parses badly. Per-envelope handshake failures
    are logged to stderr but don't abort the listener — same posture
    as the Rust CLI.
    """
    key_path = home / "user.key"
    if not key_path.exists():
        print(
            f"error: load {key_path} — run `amesh keygen` first",
            file=sys.stderr,
        )
        return 1
    user = UserKey.load(str(key_path))
    host = util.current_hostname()

    meta = AgentMetadata(
        role="amesh-listen",
        host=host,
        capabilities=[],
        issued_at=util.now_rfc3339(),
    )
    agent = AgentKey.issue(user, meta)
    agent_fp = agent.fingerprint()
    user_fp = user.fingerprint()
    cert = agent.cert()

    # Bind iroh first so we know the port to announce.
    endpoint = await Endpoint.bind(agent, 0)
    port = await endpoint.local_port()

    config = AnnounceConfig(
        agent_fp=agent_fp,
        user_fp=user_fp,
        capabilities=[],
        role="amesh-listen",
        host=host,
        port=port,
        agent_pubkey=bytes(agent.public_bytes()),
    )
    announcer = Announcer.start(config)

    print(f"listening on udp/{port}")
    print(f"  agent_fp={agent_fp.hex()}")
    print(f"  user_fp ={user_fp.hex()}")
    print(f"  host    ={host}")

    stop_deadline = None
    if duration is not None:
        try:
            dur_s = util.parse_duration(duration)
        except ValueError as e:
            announcer.stop()
            await endpoint.close()
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"  duration={dur_s}s")
        stop_deadline = asyncio.get_event_loop().time() + dur_s
    else:
        print("  ctrl-c to stop")

    try:
        while True:
            if stop_deadline is not None:
                now = asyncio.get_event_loop().time()
                remaining = stop_deadline - now
                if remaining <= 0:
                    break
                # accept_envelope itself bounds its wait by
                # timeout_ms — pass the remaining window so the call
                # returns promptly when the deadline elapses.
                timeout_ms = max(1, int(remaining * 1000))
            else:
                # Long poll window so we don't busy-loop; Ctrl-C
                # still interrupts the awaitable.
                timeout_ms = 60_000
            try:
                accepted = await endpoint.accept_envelope(cert, timeout_ms)
            except Exception as e:  # noqa: BLE001 — log per-conn failures, keep listening
                print(f"connection error: {e}", file=sys.stderr)
                continue
            if accepted is None:
                # Timeout fired with no incoming connection — loop
                # around (or fall through to the deadline check).
                continue
            env = accepted.envelope
            record = {
                "sender_agent_fp": accepted.peer_agent_fp.hex(),
                "sender_user_fp": accepted.peer_user_fp.hex(),
                "sequence": env.sequence,
                "payload": _payload_view(env.payload()),
            }
            print(json.dumps(record))
    finally:
        announcer.stop()
        await endpoint.close()
    return 0
