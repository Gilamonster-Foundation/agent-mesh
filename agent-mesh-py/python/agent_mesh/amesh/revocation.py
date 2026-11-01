"""``amesh revoke`` and ``amesh revocation ...`` — the user's signed revocation log.

Mirror of ``agent-mesh-cli/src/revocation.rs``. The log itself lives in the
protocol crate (``core.RevocationLog``); nothing here re-implements it. Same
guarantees as the Rust CLI: every write holds an exclusive lock on a sibling
``.lock`` file across read -> verify -> extends-check -> rename, verifies the
log on disk first, and saves by exclusive temp file + fsync + rename +
directory fsync. Key material is never printed.
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, Iterator, Optional, TypeVar

from agent_mesh.core import Fingerprint, MeshError, RevocationLog, UserKey

LOG_FILE = "revocation.json"
T = TypeVar("T")


class RevocationError(Exception):
    """A user-facing failure; the message goes to stderr, rc 1."""


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on ``<path>.lock`` (never truncated)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock


def _read(path: Path) -> Optional[RevocationLog]:
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    try:
        return RevocationLog.from_json(text)
    except MeshError as e:
        raise RevocationError(f"parse {path}: {e}") from e


def _load_log(path: Path) -> RevocationLog:
    log = _read(path)
    if log is None:
        raise RevocationError(
            f"no revocation log at {path} — run `amesh revocation init`"
        )
    try:
        log.verify()
    except MeshError as e:
        raise RevocationError(f"{path} failed verification; refusing: {e}") from e
    return log


def _save(path: Path, log: RevocationLog) -> None:
    """Save atomically; if a log is there it must verify and ``log`` must extend it."""
    try:
        log.verify()
    except MeshError as e:
        raise RevocationError(f"refusing to save an invalid log: {e}") from e
    old = _read(path)
    if old is not None:
        try:
            seen = old.verify().seen_json()
            log.extends(seen)
        except MeshError as e:
            raise RevocationError(
                f"new log does not extend {path}: {e}"
            ) from e
        if old.to_json() == log.to_json():
            return
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    # mkstemp: O_EXCL, 0600, unpredictable name; never follows an existing path.
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(log.to_json())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if os.name != "nt":
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _load_key(home: Path) -> UserKey:
    p = home / "user.key"
    if not p.exists():
        raise RevocationError(f"load {p} — run `amesh keygen` first?")
    return UserKey.load(str(p))


def preflight_new_key(key_path: Path) -> None:
    """Fail before ``keygen`` writes a key if a log already sits beside it."""
    path = key_path.with_name(LOG_FILE)
    if path.exists():
        raise RevocationError(
            f"revocation log already exists at {path} — "
            "move it aside before generating a new key"
        )


def init_beside(key_path: Path, key: UserKey) -> None:
    """Write the genesis log beside ``key_path`` (used by ``amesh keygen``)."""
    path = key_path.with_name(LOG_FILE)
    with _locked(path):
        _save(path, RevocationLog.genesis(key))
    print(f"revocation log:   {path}")


def init(home: Path) -> int:
    """``amesh revocation init``."""
    path = home / LOG_FILE
    key = _load_key(home)
    with _locked(path):
        if path.exists():
            raise RevocationError(f"revocation log already exists at {path}")
        _save(path, RevocationLog.genesis(key))
    print(f"created revocation log at {path}")
    return 0


def revoke(home: Path, agent: str) -> int:
    """``amesh revoke <agent-fingerprint>``."""
    try:
        fp = Fingerprint.from_hex(agent)
    except MeshError as e:
        raise RevocationError(f"bad agent fingerprint: {e}") from e
    key = _load_key(home)
    path = home / LOG_FILE
    with _locked(path):
        log = _load_log(path)
        if any(r.hex() == fp.hex() for r in log.verify().revoked):
            print(f"already revoked: {fp.hex()}")
            return 0
        try:
            log.revoke(key, fp)
        except MeshError as e:
            raise RevocationError(str(e)) from e
        _save(path, log)
    print(f"revoked {fp.hex()}")
    return 0


def bump(home: Path) -> int:
    """``amesh revocation bump``."""
    key = _load_key(home)
    path = home / LOG_FILE
    with _locked(path):
        log = _load_log(path)
        current = log.verify().generation + 1
        try:
            log.bump_generation(key, current)
        except MeshError as e:
            raise RevocationError(str(e)) from e
        _save(path, log)
    print(f"generation {current}")
    return 0


def show(home: Path) -> int:
    """``amesh revocation show``."""
    st = _load_log(home / LOG_FILE).verify()
    print(f"user:       {st.user.hex()}")
    print(f"length:     {st.len}")
    print(f"head:       {st.head}")
    print(f"generation: {st.generation}")
    revoked = sorted(r.hex() for r in st.revoked)
    print(f"revoked:    {len(revoked)}")
    for r in revoked:
        print(f"  {r}")
    return 0


def export(home: Path, dest: Path) -> int:
    """``amesh revocation export <path>``."""
    log = _load_log(home / LOG_FILE)
    with _locked(dest):
        _save(dest, log)
    print(f"exported to {dest}")
    return 0


def run(fn: Callable[[], int]) -> int:
    """Run a handler, turning :class:`RevocationError` into stderr + rc 1."""
    try:
        return fn()
    except RevocationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
