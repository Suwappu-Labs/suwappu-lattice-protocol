"""
Unit tests for canonicalize_shape() and Entity.compute_id().
"""

import struct

import pytest

from src.ltp.entity import Entity, canonicalize_shape
from src.ltp.keypair import KeyPair


class TestCanonicalizeShape:
    def test_lowercase(self):
        assert canonicalize_shape("TEXT/PLAIN") == "text/plain"

    def test_strip_param_whitespace(self):
        assert canonicalize_shape("text/plain; charset=utf-8") == "text/plain;charset=utf-8"

    def test_sort_params(self):
        result = canonicalize_shape("application/json; schema=v1; charset=utf-8")
        assert result == "application/json;charset=utf-8;schema=v1"

    def test_ltp_extension_type(self):
        assert canonicalize_shape("x-ltp/state-snapshot") == "x-ltp/state-snapshot"

    def test_no_subtype_raises(self):
        with pytest.raises(ValueError, match="type/subtype"):
            canonicalize_shape("plaintext")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            canonicalize_shape("")

    def test_none_raises(self):
        with pytest.raises(ValueError):
            canonicalize_shape(None)

    def test_param_without_equals_raises(self):
        with pytest.raises(ValueError, match="missing"):
            canonicalize_shape("text/plain; broken")

    def test_idempotent(self):
        shape = "application/json;charset=utf-8"
        assert canonicalize_shape(shape) == canonicalize_shape(canonicalize_shape(shape))


class TestEntity:
    def test_shape_canonicalized_on_init(self):
        e = Entity(content=b"x", shape="TEXT/PLAIN")
        assert e.shape == "text/plain"

    def test_compute_id_deterministic(self):
        kp = KeyPair.generate("sender")
        e = Entity(content=b"hello", shape="text/plain")
        ts = 1740000000.0
        assert e.compute_id(kp.vk, ts) == e.compute_id(kp.vk, ts)

    def test_compute_id_prefixed(self):
        kp = KeyPair.generate("sender")
        e = Entity(content=b"data", shape="application/json")
        eid = e.compute_id(kp.vk, 1.0)
        assert eid.startswith("sha3-256:")

    def test_compute_id_changes_with_content(self):
        kp = KeyPair.generate("sender")
        ts = 1740000000.0
        e1 = Entity(content=b"content A", shape="text/plain")
        e2 = Entity(content=b"content B", shape="text/plain")
        assert e1.compute_id(kp.vk, ts) != e2.compute_id(kp.vk, ts)

    def test_compute_id_changes_with_shape(self):
        kp = KeyPair.generate("sender")
        ts = 1740000000.0
        e1 = Entity(content=b"same", shape="text/plain")
        e2 = Entity(content=b"same", shape="text/html")
        assert e1.compute_id(kp.vk, ts) != e2.compute_id(kp.vk, ts)

    def test_compute_id_changes_with_timestamp(self):
        kp = KeyPair.generate("sender")
        e = Entity(content=b"same", shape="text/plain")
        assert e.compute_id(kp.vk, 1.0) != e.compute_id(kp.vk, 2.0)

    def test_compute_id_changes_with_sender_vk(self):
        kp1 = KeyPair.generate("alice")
        kp2 = KeyPair.generate("bob")
        e = Entity(content=b"same", shape="text/plain")
        ts = 1740000000.0
        assert e.compute_id(kp1.vk, ts) != e.compute_id(kp2.vk, ts)

    def test_compute_id_1bit_content_flip_changes_id(self):
        kp = KeyPair.generate("sender")
        ts = 1740000000.0
        content = b"immutable content"
        e1 = Entity(content=content, shape="text/plain")
        flipped = bytearray(content)
        flipped[0] ^= 0x01
        e2 = Entity(content=bytes(flipped), shape="text/plain")
        assert e1.compute_id(kp.vk, ts) != e2.compute_id(kp.vk, ts)

    def test_no_collision_in_10k_entities(self):
        import os

        kp = KeyPair.generate("tester")
        seen: set[str] = set()
        for i in range(10_000):
            content = os.urandom(32) + struct.pack(">I", i)
            e = Entity(content=content, shape="x-ltp/collision-test")
            eid = e.compute_id(kp.vk, float(i))
            assert eid not in seen, f"Collision at entity {i}"
            seen.add(eid)
