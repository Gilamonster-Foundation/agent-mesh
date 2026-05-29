"""``amesh send`` — dial a peer by fingerprint and ship one envelope.

Mirror of ``agent-mesh-cli/src/send.rs``. The flow:

1. Load ``user.key``, issue an ephemeral agent for this send.
2. Start a :class:`agent_mesh.transport.PeerResolver`; wait up to
   ``--timeout`` for the peer fingerprint to appear on mDNS.
3. Build a :class:`agent_mesh.core.SignedEnvelope` addressed to the
   resolved peer's agent fingerprint.
4. Bind a local ephemeral :class:`agent_mesh.transport.Endpoint`.
5. Dial + handshake + send via ``Endpoint.send_envelope_to`` (the
   pyo3 facade for the dial-handshake-send loop).
"""

from __future__ import annotations

import sys
from pathlib import Path

from agent_mesh.core import (
    AgentKey,
    AgentMetadata,
    Fingerprint,
    Recipient,
    SignedEnvelope,
    UserKey,
)
from agent_mesh.transport import Endpoint, PeerResolver

from . import util


async def run(
    home: Path,
    peer_fp_hex: str,
    payload: str,
    timeout: str,
) -> int:
    """Run the send subcommand. Returns 0 on success, non-zero on error."""
    key_path = home / "user.key"
    if not key_path.exists():
        print(
            f"error: load {key_path} — run `amesh keygen` first",
            file=sys.stderr,
        )
        return 1
    user = UserKey.load(str(key_path))

    try:
        target_fp = Fingerprint.from_hex(peer_fp_hex)
    except Exception as e:  # noqa: BLE001 — surface parse failures cleanly
        print(
            f"error: parse peer fingerprint {peer_fp_hex!r}: {e}",
            file=sys.stderr,
        )
        return 1
    try:
        dur_s = util.parse_duration(timeout)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    host = util.current_hostname()
    meta = AgentMetadata(
        role="amesh-send",
        host=host,
        capabilities=[],
        issued_at=util.now_rfc3339(),
    )
    agent = AgentKey.issue(user, meta)

    print(f"resolving peer {peer_fp_hex} (timeout {dur_s}s)...")
    resolver = PeerResolver.start()
    try:
        peer = await resolver.resolve(target_fp, int(dur_s * 1000))
    finally:
        resolver.stop()
    if peer is None:
        print(
            f"error: peer {peer_fp_hex} did not appear within {dur_s}s",
            file=sys.stderr,
        )
        return 1

    if not peer.is_same_user(user.fingerprint()):
        print(
            f"error: peer {peer_fp_hex} belongs to user "
            f"{peer.user_fp.hex()} (we are {user.fingerprint().hex()}); "
            "no pact exists",
            file=sys.stderr,
        )
        return 1
    if peer.port == 0:
        print(
            f"error: peer {peer_fp_hex} advertised port 0 — discovery-only, "
            "not reachable. ask the peer to run `amesh listen` instead of "
            "`amesh announce`.",
            file=sys.stderr,
        )
        return 1
    pubkey = peer.agent_pubkey
    if pubkey is None:
        print(
            f"error: peer {peer_fp_hex} did not publish its ed25519 pubkey "
            "in mDNS — older `amesh announce`? need `amesh listen`.",
            file=sys.stderr,
        )
        return 1

    local_ep = await Endpoint.bind(agent, 0)
    socket_addrs = [f"{ip}:{peer.port}" for ip in peer.addrs]
    print(f"dialing peer at {socket_addrs} (alpn agent-mesh/v1)...")

    envelope = SignedEnvelope(
        agent,
        Recipient.direct(peer.agent_fp),
        0,
        payload.encode("utf-8"),
    )

    try:
        peer_agent_fp = await local_ep.send_envelope_to(
            agent.cert(),
            bytes(pubkey),
            socket_addrs,
            envelope,
        )
    except Exception as e:  # noqa: BLE001 — handshake / dial failures
        await local_ep.close()
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(
        f"sent envelope to {peer_agent_fp.short()} "
        f"({len(payload.encode('utf-8'))} bytes payload)"
    )
    await local_ep.close()
    return 0
