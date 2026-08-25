"""SealedBox v2 receiver-bound envelope (whitepaper §3.3.3 KEM-binding fix).

ML-KEM is not MAL-BIND-K-PK / MAL-BIND-K-CT, so the protocol supplies the
binding: v2 envelopes carry AEAD associated data derived from the receiver's
encapsulation key and the KEM ciphertext. These tests cover the v2 format,
the binding (splice and re-target failures), legacy v1 compatibility with
its 0x02-collision fallback, strict mode, and the sealed_at freshness gate.
"""

from __future__ import annotations

import os

import pytest

from src.ltp.commitment import CommitmentNetwork
from src.ltp.entity import Entity
from src.ltp.keypair import KeyPair, SealedBox
from src.ltp.lattice import LatticeKey
from src.ltp.primitives import AEAD, MLKEM
from src.ltp.protocol import LTPProtocol, ProtocolConfig


def _seal_v1(plaintext: bytes, receiver_ek: bytes) -> bytes:
    """Reproduce the legacy (pre-binding) envelope: no version byte, no AAD."""
    shared_secret, kem_ct = MLKEM.encaps(receiver_ek)
    nonce = os.urandom(AEAD.NONCE_SIZE)
    return kem_ct + nonce + AEAD.encrypt(shared_secret, plaintext, nonce)


class TestSealedBoxV2:
    def test_v2_roundtrip_and_format(self):
        kp = KeyPair.generate("r")
        sealed = SealedBox.seal(b"payload", kp.ek)
        assert sealed[0] == SealedBox.VERSION_V2
        assert len(sealed) == 1 + MLKEM.CT_SIZE + AEAD.NONCE_SIZE + len(b"payload") + AEAD.TAG_SIZE
        assert SealedBox.unseal(sealed, kp) == b"payload"

    def test_kem_ct_splice_fails(self):
        """K-CT binding: a payload spliced onto a different (valid)
        encapsulation for the same receiver must fail tag verification."""
        kp = KeyPair.generate("r")
        sealed_a = SealedBox.seal(b"payload A", kp.ek)
        sealed_b = SealedBox.seal(b"payload B", kp.ek)
        ct_size = MLKEM.CT_SIZE
        spliced = sealed_a[:1] + sealed_b[1 : 1 + ct_size] + sealed_a[1 + ct_size :]
        with pytest.raises(ValueError):
            SealedBox.unseal(spliced, kp)

    def test_receiver_key_binding_in_aad(self):
        """K-PK binding: opening under a different receiver ek must fail even
        if decapsulation were to yield the same shared secret — the AAD is
        recomputed from the opener's own ek. Simulated by forcing the same
        shared secret and differing only the ek."""
        kp = KeyPair.generate("r")
        sealed = SealedBox.seal(b"bound payload", kp.ek)
        kem_ct = sealed[1 : 1 + MLKEM.CT_SIZE]
        nonce = sealed[1 + MLKEM.CT_SIZE : 1 + MLKEM.CT_SIZE + AEAD.NONCE_SIZE]
        aead_ct = sealed[1 + MLKEM.CT_SIZE + AEAD.NONCE_SIZE :]
        shared_secret = kp.decaps(kem_ct)

        good_aad = SealedBox._aad_v2(kp.ek, kem_ct)
        assert AEAD.decrypt(shared_secret, aead_ct, nonce, aad=good_aad) == b"bound payload"

        other = KeyPair.generate("other")
        evil_aad = SealedBox._aad_v2(other.ek, kem_ct)
        with pytest.raises(ValueError):
            AEAD.decrypt(shared_secret, aead_ct, nonce, aad=evil_aad)

    def test_wrong_receiver_fails(self):
        alice, eve = KeyPair.generate("a"), KeyPair.generate("e")
        sealed = SealedBox.seal(b"for alice", alice.ek)
        with pytest.raises(ValueError):
            SealedBox.unseal(sealed, eve)

    def test_version_byte_tamper_fails_or_misroutes_safely(self):
        kp = KeyPair.generate("r")
        sealed = SealedBox.seal(b"payload", kp.ek)
        tampered = bytes([0x01]) + sealed[1:]
        with pytest.raises(ValueError):
            SealedBox.unseal(tampered, kp)


class TestLegacyV1Compatibility:
    def test_v1_envelope_still_unseals_by_default(self):
        kp = KeyPair.generate("r")
        sealed = _seal_v1(b"legacy payload", kp.ek)
        assert SealedBox.unseal(sealed, kp) == b"legacy payload"

    def test_v1_starting_with_0x02_falls_back(self):
        """1-in-256 collision: a v1 envelope whose kem_ct begins 0x02 is
        first tried as v2, fails the tag, and falls back to the v1 parse."""
        kp = KeyPair.generate("r")
        for _ in range(2048):
            sealed = _seal_v1(b"collision payload", kp.ek)
            if sealed[0] == SealedBox.VERSION_V2:
                assert SealedBox.unseal(sealed, kp) == b"collision payload"
                return
        pytest.skip("no 0x02-leading kem_ct in 2048 tries (p ~ 3e-4)")

    def test_strict_mode_rejects_v1(self, monkeypatch):
        kp = KeyPair.generate("r")
        v1 = _seal_v1(b"legacy", kp.ek)
        v2 = SealedBox.seal(b"current", kp.ek)
        monkeypatch.setenv("LTP_SEALEDBOX_STRICT_V2", "1")
        with pytest.raises(ValueError, match="legacy"):
            SealedBox.unseal(v1, kp)
        assert SealedBox.unseal(v2, kp) == b"current"


@pytest.fixture
def rig():
    network = CommitmentNetwork()
    for i in range(8):
        network.add_node(f"node-{i}", ["us", "eu", "ap", "sa"][i % 4])
    alice = KeyPair.generate("alice")
    bob = KeyPair.generate("bob")
    content = b"freshness-gate payload"
    return network, alice, bob, content


class TestSealFreshness:
    def test_sealed_at_stamped_and_recovered(self, rig):
        network, alice, bob, content = rig
        protocol = LTPProtocol(network)
        entity_id, record, cek = protocol.commit(
            Entity(content=content, shape="text/plain"), alice, n=8, k=4
        )
        sealed = protocol.lattice(entity_id, record, cek, bob)
        key = LatticeKey.unseal(sealed, bob)
        assert key.sealed_at > 1_600_000_000  # a real recent timestamp

    def test_max_seal_age_rejects_stale_key(self, rig):
        network, alice, bob, content = rig
        protocol = LTPProtocol(network, config=ProtocolConfig(max_seal_age_seconds=3600))
        entity_id, record, cek = protocol.commit(
            Entity(content=content, shape="text/plain"), alice, n=8, k=4
        )
        sealed = protocol.lattice(entity_id, record, cek, bob)
        key = LatticeKey.unseal(sealed, bob)
        fresh_now = float(key.sealed_at + 100)
        stale_now = float(key.sealed_at + 3601)
        assert protocol.materialize(sealed, bob, record, now=fresh_now) == content
        assert protocol.materialize(sealed, bob, record, now=stale_now) is None

    def test_max_seal_age_fail_closed_for_unstamped_legacy_key(self, rig):
        """A legacy key with no sealed_at stamp is rejected when a maximum
        seal age is configured — fail-closed, per §2.2.1's philosophy."""
        network, alice, bob, content = rig
        protocol = LTPProtocol(network, config=ProtocolConfig(max_seal_age_seconds=3600))
        entity_id, record, cek = protocol.commit(
            Entity(content=content, shape="text/plain"), alice, n=8, k=4
        )
        from src.ltp.primitives import canonical_hash

        legacy = LatticeKey(
            entity_id=entity_id,
            cek=cek,
            commitment_ref=canonical_hash(record.to_bytes()),
            access_policy={"type": "unrestricted"},
        )
        # Seal WITHOUT stamping (bypass seal()'s stamp, as a legacy sender).
        sealed = SealedBox.seal(legacy._plaintext_payload(), bob.ek)
        assert LatticeKey.unseal(sealed, bob).sealed_at == 0
        assert protocol.materialize(sealed, bob, record) is None

        # Without the age limit, the same unstamped key is accepted.
        lax = LTPProtocol(network)
        assert lax.materialize(sealed, bob, record) == content

    def test_sealed_size_constant_across_entity_sizes(self, rig):
        """The v2 envelope keeps the O(1) sealed-size invariant."""
        network, alice, bob, _ = rig
        protocol = LTPProtocol(network)
        sizes = set()
        for size in (64, 4096, 262144):
            content = os.urandom(size)
            entity_id, record, cek = protocol.commit(
                Entity(content=content, shape="application/octet-stream"), alice, n=8, k=4
            )
            sealed = protocol.lattice(entity_id, record, cek, bob)
            sizes.add(len(sealed))
            assert protocol.materialize(sealed, bob, record) == content
        assert len(sizes) == 1, f"sealed size varied with entity size: {sizes}"
