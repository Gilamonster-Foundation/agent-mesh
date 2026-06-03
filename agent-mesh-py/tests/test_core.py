"""Tier-A smoke tests: agent_mesh.core round-trips."""

from __future__ import annotations

import os
import tempfile

import pytest

import agent_mesh.core as core


def test_userkey_generate_unique() -> None:
    a = core.UserKey.generate()
    b = core.UserKey.generate()
    assert a.fingerprint() != b.fingerprint()


def test_userkey_sign_verify() -> None:
    key = core.UserKey.generate()
    msg = b"hello"
    sig = key.sign(msg)
    assert isinstance(sig, bytes)
    assert len(sig) == 64

    pub = key.public()
    pub.verify(msg, sig)  # should not raise

    with pytest.raises(Exception):
        pub.verify(b"different", sig)


def test_userkey_save_load_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "user.key")
        key = core.UserKey.generate()
        fp = key.fingerprint()
        key.save(path)
        loaded = core.UserKey.load(path)
        assert loaded.fingerprint() == fp


def test_agent_key_issue_and_cert_verify() -> None:
    user = core.UserKey.generate()
    meta = core.AgentMetadata(
        role="test",
        host="test-host",
        capabilities=["test"],
        issued_at="2026-05-29T00:00:00Z",
    )
    agent = core.AgentKey.issue(user, meta)
    cert = agent.cert()
    cert.verify()  # raises on failure
    assert cert.agent_fingerprint() == agent.fingerprint()
    assert cert.user_fingerprint() == user.fingerprint()


def test_signed_envelope_roundtrip() -> None:
    user = core.UserKey.generate()
    meta = core.AgentMetadata(
        role="test",
        host="test-host",
        capabilities=["test"],
        issued_at="2026-05-29T00:00:00Z",
    )
    agent = core.AgentKey.issue(user, meta)
    recipient = core.Recipient.topic("test/topic")
    env = core.SignedEnvelope(agent, recipient, 1, b"hello payload")
    env.verify()
    assert env.sequence == 1
    assert env.payload() == b"hello payload"
    assert env.sender_agent_fp() == agent.fingerprint()
    assert env.sender_user_fp() == user.fingerprint()


def test_recipient_constructors() -> None:
    fp = core.Fingerprint.of_bytes(b"some bytes")
    d = core.Recipient.direct(fp)
    t = core.Recipient.topic("ns/foo")
    a = core.Recipient.anycast("inference")
    # repr should mention the variant
    assert "direct" in repr(d)
    assert "topic" in repr(t)
    assert "anycast" in repr(a)


def test_fingerprint_hex_roundtrip() -> None:
    fp = core.Fingerprint.from_bytes(b"\x42" * 32)
    hex_str = fp.hex()
    assert len(hex_str) == 64
    fp2 = core.Fingerprint.from_hex(hex_str)
    assert fp == fp2
    assert hash(fp) == hash(fp2)
    # short() is the 12-char prefix
    assert fp.short() == hex_str[:12]


def test_fingerprint_of_bytes_is_stable() -> None:
    a = core.Fingerprint.of_bytes(b"same input")
    b = core.Fingerprint.of_bytes(b"same input")
    c = core.Fingerprint.of_bytes(b"different")
    assert a == b
    assert a != c


def test_agent_metadata_attrs() -> None:
    meta = core.AgentMetadata(
        role="r",
        host="h",
        capabilities=["c1", "c2"],
        issued_at="2026-05-29T00:00:00Z",
        expires_at="2027-01-01T00:00:00Z",
    )
    assert meta.role == "r"
    assert meta.host == "h"
    assert meta.capabilities == ["c1", "c2"]
    assert meta.issued_at == "2026-05-29T00:00:00Z"
    assert meta.expires_at == "2027-01-01T00:00:00Z"


def test_caveats_top_is_unrestricted() -> None:
    top = core.Caveats.top()
    # Every axis on ⊤ is "unrestricted", which we represent as None.
    assert top.fs_read is None
    assert top.fs_write is None
    assert top.exec is None
    assert top.net is None
    assert top.valid_for_generation is None
    assert top.max_calls is None


def test_caveats_construct_restricted() -> None:
    c = core.Caveats(
        fs_read=["/repo"],
        fs_write=[],
        exec=["git"],
        net=[],
        max_calls=10,
        valid_for_generation=[7],
    )
    assert c.fs_read == ["/repo"]
    assert c.fs_write == []  # bounded-to-nothing, not unrestricted
    assert c.exec == ["git"]
    assert c.net == []
    assert c.max_calls == 10
    assert c.valid_for_generation == [7]


def test_caveats_leq_shows_attenuation() -> None:
    restricted = core.Caveats(
        fs_read=["/repo"],
        exec=["git"],
        max_calls=10,
    )
    top = core.Caveats.top()
    # restricted ⊑ top, but ⊤ is NOT ⊑ restricted (no escalation upward).
    assert restricted.leq(top)
    assert not top.leq(restricted)
    # reflexive
    assert restricted.leq(restricted)


def test_caveats_meet_never_amplifies() -> None:
    a = core.Caveats(fs_read=["/repo", "/tmp"], max_calls=10)
    b = core.Caveats(fs_read=["/repo"], max_calls=4)
    m = a.meet(b)
    # meet ⊑ both operands — composing authority can only narrow it.
    assert m.leq(a)
    assert m.leq(b)
    # intersection of paths, tighter call bound.
    assert m.fs_read == ["/repo"]
    assert m.max_calls == 4
    # commutative
    assert m == b.meet(a)


def test_caveats_to_json_from_json_roundtrip() -> None:
    c = core.Caveats(
        fs_read=["/repo"],
        exec=["git", "cargo"],
        max_calls=3,
        valid_for_generation=[42],
    )
    blob = c.to_json()  # a plain dict
    assert isinstance(blob, dict)
    back = core.Caveats.from_json(blob)
    assert back == c
    # A JSON-encoded string is accepted too.
    import json

    back2 = core.Caveats.from_json(json.dumps(blob))
    assert back2 == c


def test_agent_metadata_caveats_roundtrip() -> None:
    restricted = core.Caveats(
        fs_read=["/repo"],
        exec=["git"],
        max_calls=5,
    )
    meta = core.AgentMetadata(
        role="worker",
        host="host",
        capabilities=["build"],
        issued_at="2026-05-29T00:00:00Z",
        caveats=restricted,
    )
    assert meta.caveats == restricted


def test_agent_metadata_caveats_default_top() -> None:
    # No caveats declared → unrestricted (⊤), the back-compatible default.
    meta = core.AgentMetadata(
        role="worker",
        host="host",
        capabilities=["build"],
        issued_at="2026-05-29T00:00:00Z",
    )
    assert meta.caveats == core.Caveats.top()


def test_mesh_error_is_exported() -> None:
    assert hasattr(core, "MeshError")
    # Failing verify should raise our exception class.
    with pytest.raises(core.MeshError):
        # Fingerprint.from_hex of garbage raises MeshError.
        core.Fingerprint.from_hex("not-hex")
