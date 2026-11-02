"""``amesh revoke`` / ``amesh revocation`` through the pip entry point (#181).

Drives ``python -m agent_mesh.cli`` against a temp home. The Python CLI uses the
protocol crate's ``RevocationLog`` through PyO3; these tests prove it keeps the
Rust CLI's guarantees and writes the same file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

from agent_mesh.core import RevocationLog

AGENT = "ab" + "00" * 30 + "01"
OTHER = "cd" + "00" * 30 + "02"


def amesh(home: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agent_mesh.cli", "--home", str(home), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def log_of(home: Path) -> RevocationLog:
    return RevocationLog.from_json((home / "revocation.json").read_text())


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "amesh"
    assert amesh(h, "keygen").returncode == 0
    return h


def test_keygen_writes_a_genesis_log(home: Path) -> None:
    st = log_of(home).verify()
    assert (st.len, st.generation) == (1, 0)
    assert "length:     1" in amesh(home, "revocation", "show").stdout


def test_init_backfills_and_refuses_twice(home: Path) -> None:
    (home / "revocation.json").unlink()
    assert amesh(home, "revocation", "init").returncode == 0
    r = amesh(home, "revocation", "init")
    assert r.returncode == 1 and "already exists" in r.stderr


def test_revoke_extends_and_second_revoke_is_a_noop(home: Path) -> None:
    before = log_of(home).verify()
    assert amesh(home, "revoke", AGENT).returncode == 0
    after = log_of(home)
    after.extends(before.seen_json())
    st = after.verify()
    assert st.len == 2 and [r.hex() for r in st.revoked] == [AGENT]
    again = amesh(home, "revoke", AGENT)
    assert again.returncode == 0 and "already revoked" in again.stdout
    assert log_of(home).verify().len == 2


def test_malformed_fingerprint_is_refused(home: Path) -> None:
    assert amesh(home, "revoke", "nothex").returncode == 1
    assert log_of(home).verify().len == 1


def test_bump_raises_the_generation(home: Path) -> None:
    assert "generation 1" in amesh(home, "revocation", "bump").stdout
    assert "generation 2" in amesh(home, "revocation", "bump").stdout
    assert log_of(home).verify().generation == 2


def test_corrupted_log_blocks_every_command(home: Path, tmp_path: Path) -> None:
    assert amesh(home, "revoke", AGENT).returncode == 0
    path = home / "revocation.json"
    data = json.loads(path.read_text())
    data["entries"][1]["node"]["payload"]["Revoke"]["agent"][31] = 9
    path.write_text(json.dumps(data))
    before = path.read_text()
    out = tmp_path / "out.json"
    for args in (
        ("revoke", OTHER),
        ("revocation", "bump"),
        ("revocation", "show"),
        ("revocation", "export", str(out)),
    ):
        assert amesh(home, *args).returncode == 1, args
    assert path.read_text() == before and not out.exists()


def test_export_writes_a_copy_and_refuses_a_log_that_does_not_extend(
    home: Path, tmp_path: Path
) -> None:
    out = tmp_path / "export.json"
    assert amesh(home, "revocation", "export", str(out)).returncode == 0
    assert RevocationLog.from_json(out.read_text()).to_json() == log_of(home).to_json()
    other = tmp_path / "other"
    assert amesh(other, "keygen").returncode == 0
    assert amesh(other, "revocation", "export", str(out)).returncode == 1
    assert RevocationLog.from_json(out.read_text()).to_json() == log_of(home).to_json()


def test_concurrent_revokes_lose_nothing(home: Path) -> None:
    agents = [f"{i:02x}" + "11" * 31 for i in range(8)]
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "agent_mesh.cli", "--home", str(home), "revoke", a],
            stdout=subprocess.DEVNULL,
        )
        for a in agents
    ]
    assert all(p.wait() == 0 for p in procs)
    st = log_of(home).verify()
    assert st.len == 9
    assert {r.hex() for r in st.revoked} == set(agents)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_planted_symlink_is_never_followed(home: Path, tmp_path: Path) -> None:
    victim = home / "user.key"
    key_before = victim.read_bytes()
    dest = tmp_path / "export.json"
    for name in (f"export.tmp.{os.getpid()}", "export.json.tmp", ".export.json.tmp"):
        (tmp_path / name).symlink_to(victim)
    assert amesh(home, "revocation", "export", str(dest)).returncode == 0
    assert victim.read_bytes() == key_before


def test_keygen_beside_an_existing_log_creates_no_key(tmp_path: Path) -> None:
    h = tmp_path / "amesh"
    h.mkdir()
    (h / "revocation.json").write_text("not a log")
    r = amesh(h, "keygen")
    assert r.returncode == 1 and "revocation log already exists" in r.stderr
    assert not (h / "user.key").exists()
