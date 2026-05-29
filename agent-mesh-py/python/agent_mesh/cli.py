"""Native Python implementation of the ``amesh`` CLI.

The ``amesh`` entry point installed by ``pip install newt-agent-mesh``
points here. The dispatcher uses :mod:`argparse` (stdlib only — no
click/typer dependency in the wheel) and delegates each subcommand to
a handler in :mod:`agent_mesh.amesh`.

Surface parity with the Rust binary at ``agent-mesh-cli/`` is
load-bearing: both CLIs operate on the same ``~/.agent-mesh/`` layout
and accept the same flags, so a user can swap between them freely.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import NoReturn, Optional, Sequence

from . import amesh as _commands


def default_home() -> Path:
    """``~/.agent-mesh``. Matches the Rust CLI default."""
    return Path.home() / ".agent-mesh"


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse tree mirroring the Rust ``clap`` definition.

    Kept in its own function so tests can drive it independently of
    the dispatcher (and the global ``sys.argv``).
    """
    parser = argparse.ArgumentParser(
        prog="amesh",
        description="agent-mesh CLI",
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=None,
        help=(
            "Override the default config dir (~/.agent-mesh). "
            "Also honored via the AMESH_HOME environment variable."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # keygen
    p = sub.add_parser("keygen", help="Generate a new user key.")
    p.add_argument("--path", type=Path, default=None)

    # bind <target>
    p = sub.add_parser(
        "bind",
        help="Bind your agent-mesh identity to an external key system.",
    )
    bind_sub = p.add_subparsers(dest="bind_target", required=True)
    p_gh = bind_sub.add_parser(
        "github", help="Cross-sign with your GitHub SSH key."
    )
    p_gh.add_argument("--ssh-key", type=Path, default=None)
    p_gh.add_argument("--username", default=None)

    # whoami
    sub.add_parser("whoami", help="Print the local user identity.")

    # verify
    p = sub.add_parser(
        "verify", help="Verify a peer's GitHub binding."
    )
    p.add_argument("--binding", type=Path, required=True)
    p.add_argument("--github-user", required=True)

    # announce
    p = sub.add_parser(
        "announce", help="Announce this agent on the LAN via mDNS."
    )
    p.add_argument(
        "--capability", action="append", default=[], dest="capabilities"
    )
    p.add_argument("--role", default="amesh-cli")
    p.add_argument("--host", default=None)
    p.add_argument("--duration", default=None)

    # peers
    p = sub.add_parser("peers", help="List peers seen on the LAN.")
    p.add_argument("--listen", default="5s")
    p.add_argument("--same-user", action="store_true", dest="same_user")

    # listen
    p = sub.add_parser(
        "listen",
        help="Bind a QUIC endpoint, announce on mDNS, accept envelopes.",
    )
    p.add_argument("--duration", default=None)

    # send
    p = sub.add_parser(
        "send", help="Send a signed envelope to a peer discovered on the LAN."
    )
    p.add_argument("peer_fp")
    p.add_argument("--payload", required=True)
    p.add_argument("--timeout", default="10s")

    return parser


def _resolve_home(arg: Optional[Path]) -> Path:
    """Apply the same precedence rule as the Rust CLI's ``--home``:
    explicit flag > ``AMESH_HOME`` env var > default."""
    if arg is not None:
        return arg
    env = os.environ.get("AMESH_HOME")
    if env:
        return Path(env)
    return default_home()


def main(argv: Optional[Sequence[str]] = None) -> NoReturn:
    """Entry point — parse argv, dispatch, exit with the handler's rc."""
    if argv is None:
        argv = sys.argv[1:]
    args = build_parser().parse_args(list(argv))
    home = _resolve_home(args.home)

    try:
        rc = _dispatch(args, home)
    except KeyboardInterrupt:
        # 130 is the conventional exit code for SIGINT.
        sys.exit(130)
    sys.exit(rc)


def _dispatch(args: argparse.Namespace, home: Path) -> int:
    """Route to the matching subcommand handler. Async ones get
    ``asyncio.run``'d here so handlers never see the loop boilerplate.
    """
    cmd = args.cmd
    if cmd == "keygen":
        return _commands.keygen.run(home, args.path)
    if cmd == "bind":
        if args.bind_target == "github":
            return _commands.bind.github(home, args.ssh_key, args.username)
        # argparse's required=True guards against this, but be loud
        # if a future bind target ships without a dispatch arm.
        raise ValueError(f"unknown bind target {args.bind_target!r}")
    if cmd == "whoami":
        return _commands.whoami.run(home)
    if cmd == "verify":
        return asyncio.run(
            _commands.verify.run(args.binding, args.github_user)
        )
    if cmd == "announce":
        return asyncio.run(
            _commands.announce.run(
                home,
                args.capabilities,
                args.role,
                args.host,
                args.duration,
            )
        )
    if cmd == "peers":
        return asyncio.run(
            _commands.peers.run(home, args.listen, args.same_user)
        )
    if cmd == "listen":
        return asyncio.run(_commands.listen.run(home, args.duration))
    if cmd == "send":
        return asyncio.run(
            _commands.send.run(
                home,
                args.peer_fp,
                args.payload,
                args.timeout,
            )
        )
    raise ValueError(f"unknown command {cmd!r}")


if __name__ == "__main__":
    main()
