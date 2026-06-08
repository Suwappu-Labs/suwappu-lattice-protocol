"""
Tests for the SUWAPPU Dual-Lane Cryptographic Architecture.

Covers:
  - Lane isolation (canonical → sha3-256:, internal → blake3: or sha3-256: fallback)
  - Compliance strict mode rejects non-canonical algorithms
  - FIPS mode forces both lanes to SHA3
  - SecurityProfile convenience constructors (defi, cefi)
  - CryptoLane enum classification
  - Full protocol round-trip with dual-lane profile
  - Cross-lane determinism (same input, different algorithms → different output)
"""

import os

import pytest

from src.ltp import Entity, LTPProtocol
from src.ltp.primitives import (
    CryptoLane,
    HashFunction,
    SecurityProfile,
    _blake3_available,
    canonical_hash,
    canonical_hash_bytes,
    get_compliance_strict,
    get_security_profile,
    internal_hash,
    internal_hash_bytes,
    set_compliance_strict,
    set_security_profile,
)


@pytest.fixture(autouse=True)
def _restore_profile():
    """Restore the global security profile after each test."""
    original = get_security_profile()
    strict = get_compliance_strict()
    yield
    set_security_profile(original)
    set_compliance_strict(strict)


# ---------------------------------------------------------------------------
# Lane isolation
# ---------------------------------------------------------------------------


class TestLaneIsolation:
    def test_canonical_hash_uses_sha3_prefix(self):
        result = canonical_hash(b"test data")
        assert result.startswith("sha3-256:")
        assert len(result.split(":")[1]) == 64  # 32 bytes hex

    def test_canonical_hash_bytes_length(self):
        result = canonical_hash_bytes(b"test data")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_canonical_hash_deterministic(self):
        assert canonical_hash(b"abc") == canonical_hash(b"abc")

    def test_canonical_hash_bytes_matches_hex(self):
        data = b"consistency check"
        hex_part = canonical_hash(data).split(":")[1]
        assert canonical_hash_bytes(data).hex() == hex_part

    def test_internal_hash_prefix(self):
        result = internal_hash(b"test data")
        if _blake3_available:
            assert result.startswith("blake3:")
        else:
            assert result.startswith("sha3-256:")

    def test_internal_hash_bytes_length(self):
        result = internal_hash_bytes(b"test data")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_internal_hash_deterministic(self):
        assert internal_hash(b"abc") == internal_hash(b"abc")

    def test_internal_hash_bytes_matches_hex(self):
        data = b"internal consistency"
        hex_part = internal_hash(data).split(":")[1]
        assert internal_hash_bytes(data).hex() == hex_part

    def test_lanes_produce_different_function_names(self):
        """canonical_hash and internal_hash are distinct functions."""
        assert canonical_hash is not internal_hash
        assert canonical_hash_bytes is not internal_hash_bytes


# ---------------------------------------------------------------------------
# Cross-lane determinism
# ---------------------------------------------------------------------------


class TestCrossLaneDeterminism:
    def test_same_input_different_lanes(self):
        """Same input to both lanes should produce different outputs if algorithms differ."""
        data = b"cross-lane test"
        canonical = canonical_hash_bytes(data)
        internal = internal_hash_bytes(data)

        if _blake3_available:
            # Different algorithms → different output
            assert canonical != internal
        else:
            # Fallback: both use SHA3-256, so same output
            assert canonical == internal

    def test_cross_lane_prefix_mismatch_when_blake3_available(self):
        """With blake3 installed, prefixes must differ between lanes."""
        c = canonical_hash(b"data")
        i = internal_hash(b"data")
        c_prefix = c.split(":")[0]
        i_prefix = i.split(":")[0]

        if _blake3_available:
            assert c_prefix != i_prefix
        else:
            assert c_prefix == i_prefix  # both sha3-256


# ---------------------------------------------------------------------------
# Compliance strict mode
# ---------------------------------------------------------------------------


class TestComplianceStrictMode:
    def test_strict_mode_allows_sha3(self):
        set_compliance_strict(True)
        result = canonical_hash(b"approved")
        assert result.startswith("sha3-256:")

    def test_strict_mode_allows_sha384(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_384))
        set_compliance_strict(True)
        result = canonical_hash(b"approved 384")
        assert result.startswith("sha384:")

    def test_strict_mode_allows_sha512(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_512))
        set_compliance_strict(True)
        result = canonical_hash(b"approved 512")
        assert result.startswith("sha512:")

    def test_strict_mode_rejects_blake2b(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.BLAKE2B_256))
        set_compliance_strict(True)
        with pytest.raises(ValueError, match="FIPS-approved"):
            canonical_hash(b"rejected")

    def test_strict_mode_rejects_blake3(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.BLAKE3_256))
        set_compliance_strict(True)
        with pytest.raises(ValueError, match="FIPS-approved"):
            canonical_hash(b"rejected")

    def test_strict_mode_does_not_affect_internal_lane(self):
        """Internal lane is not subject to compliance restrictions."""
        set_compliance_strict(True)
        # Internal lane should still work regardless of strict mode
        result = internal_hash(b"internal ok")
        assert ":" in result

    def test_strict_mode_toggle(self):
        assert not get_compliance_strict()
        set_compliance_strict(True)
        assert get_compliance_strict()
        set_compliance_strict(False)
        assert not get_compliance_strict()


# ---------------------------------------------------------------------------
# SecurityProfile dual-lane configuration
# ---------------------------------------------------------------------------


class TestSecurityProfileDualLane:
    def test_default_profile_canonical_sha3(self):
        p = SecurityProfile.level3()
        assert p.canonical_hash_fn == HashFunction.SHA3_256

    def test_default_profile_internal_blake3(self):
        p = SecurityProfile.level3()
        assert p.internal_hash_fn == HashFunction.BLAKE3_256

    def test_defi_profile(self):
        p = SecurityProfile.defi()
        assert p.canonical_hash_fn == HashFunction.SHA3_256
        assert p.internal_hash_fn == HashFunction.BLAKE3_256
        assert p.level == 3

    def test_cefi_profile(self):
        p = SecurityProfile.cefi()
        assert p.canonical_hash_fn == HashFunction.SHA3_256
        assert p.internal_hash_fn == HashFunction.SHA3_256
        assert p.level == 3

    def test_cnsa2_profile(self):
        p = SecurityProfile.cnsa2()
        assert p.canonical_hash_fn == HashFunction.SHA_384
        assert p.internal_hash_fn == HashFunction.SHA_384
        assert p.level == 5

    def test_level5_default(self):
        p = SecurityProfile.level5()
        assert p.canonical_hash_fn == HashFunction.SHA_384
        assert p.level == 5

    def test_label_includes_both_lanes(self):
        p = SecurityProfile.defi()
        assert "sha3-256" in p.label
        assert "blake3" in p.label

    def test_repr_includes_both_lanes(self):
        p = SecurityProfile.cefi()
        r = repr(p)
        assert "canonical=sha3-256" in r
        assert "internal=sha3-256" in r


# ---------------------------------------------------------------------------
# CryptoLane enum
# ---------------------------------------------------------------------------


class TestCryptoLane:
    def test_canonical_value(self):
        assert CryptoLane.CANONICAL.value == "canonical"

    def test_internal_value(self):
        assert CryptoLane.INTERNAL.value == "internal"

    def test_enum_members(self):
        assert set(CryptoLane) == {CryptoLane.CANONICAL, CryptoLane.INTERNAL}


# ---------------------------------------------------------------------------
# FIPS mode forces both lanes to SHA3
# ---------------------------------------------------------------------------


class TestFIPSModeDualLane:
    def test_cefi_profile_both_sha3(self):
        """CeFi profile uses SHA3 for both lanes — equivalent to FIPS-only."""
        set_security_profile(SecurityProfile.cefi())
        c = canonical_hash(b"fips test")
        i = internal_hash(b"fips test")
        assert c.startswith("sha3-256:")
        assert i.startswith("sha3-256:")
        # Same algorithm → same output
        assert c == i

    def test_cefi_bytes_match(self):
        set_security_profile(SecurityProfile.cefi())
        data = b"bytes match"
        assert canonical_hash_bytes(data) == internal_hash_bytes(data)


# ---------------------------------------------------------------------------
# Full protocol round-trip with dual-lane profile
# ---------------------------------------------------------------------------


class TestDualLaneProtocolRoundTrip:
    def test_transfer_with_default_dual_lane(self, protocol, alice, bob):
        """Full commit → lattice → materialize with default SHA3+BLAKE3 profile."""
        content = b"dual-lane transfer test"
        entity = Entity(content=content, shape="text/plain")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        assert entity_id.startswith("sha3-256:")

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content

    def test_transfer_with_cefi_profile(self, protocol, alice, bob):
        """Full round-trip with CeFi (all-SHA3) profile."""
        set_security_profile(SecurityProfile.cefi())
        content = b"cefi transfer test"
        entity = Entity(content=content, shape="text/plain")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        assert entity_id.startswith("sha3-256:")

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content

    def test_transfer_with_defi_profile(self, protocol, alice, bob):
        """Full round-trip with DeFi (SHA3+BLAKE3) profile."""
        set_security_profile(SecurityProfile.defi())
        content = b"defi transfer test"
        entity = Entity(content=content, shape="text/plain")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        assert entity_id.startswith("sha3-256:")

        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content

    def test_entity_id_canonical_across_profiles(self, protocol, alice, bob):
        """Entity IDs always use the canonical lane — prefix reflects canonical algo."""
        for profile in [SecurityProfile.defi(), SecurityProfile.cefi()]:
            set_security_profile(profile)
            entity = Entity(content=b"profile test", shape="text/plain")
            eid, _, _ = protocol.commit(entity, alice)
            assert eid.startswith("sha3-256:")
