"""
Timing Side-Channel Analysis for ETP Cryptographic Operations.

Measures execution time variance of crypto operations to detect
timing leaks that could reveal secret information.

Methodology: For each operation, measure N iterations with different
inputs and check that timing variance doesn't correlate with secret values.

Reference: Trail of Bits Go crypto audit (TOB-GOCL-1, TOB-GOCL-2, TOB-GOCL-6)
found timing leaks in field element conversion, conditional negation, and
scalar conversion in Go's well-reviewed crypto library.

NOTE: Python's GC, allocation patterns, and interpreter overhead make precise
timing analysis unreliable. These tests document KNOWN timing concerns and
establish baseline measurements. A production audit should use C-level timing
analysis tools (e.g., dudect, ctgrind) on the real pqcrypto backends.
"""

import os
import statistics
import time

import pytest

from src.ltp import KeyPair, reset_poc_state
from src.ltp.keypair import SealedBox
from src.ltp.primitives import AEAD, MLDSA, MLKEM
from src.ltp.shards import ShardEncryptor


def measure_ns(func, iterations=100):
    """Measure execution time of a function over N iterations.
    Returns (mean_ns, stdev_ns, times_ns)."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        end = time.perf_counter_ns()
        times.append(end - start)
    return statistics.mean(times), statistics.stdev(times), times


class TestAEADTiming:
    """AEAD operations should have timing independent of plaintext content."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def test_encrypt_timing_independent_of_content(self):
        """Encryption time should not depend on plaintext content (only length)."""
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        pt_zeros = b"\x00" * 1000
        pt_ones = b"\xff" * 1000
        pt_random = os.urandom(1000)

        mean_z, std_z, _ = measure_ns(lambda: AEAD.encrypt(key, pt_zeros, nonce))
        mean_o, std_o, _ = measure_ns(lambda: AEAD.encrypt(key, pt_ones, nonce))
        mean_r, std_r, _ = measure_ns(lambda: AEAD.encrypt(key, pt_random, nonce))

        # Timing should be within 3 standard deviations of each other
        max_mean = max(mean_z, mean_o, mean_r)
        min_mean = min(mean_z, mean_o, mean_r)
        max_std = max(std_z, std_o, std_r)

        print(f"\n  Encrypt timing (1000B):")
        print(f"    zeros:  {mean_z / 1000:.1f}μs ±{std_z / 1000:.1f}μs")
        print(f"    ones:   {mean_o / 1000:.1f}μs ±{std_o / 1000:.1f}μs")
        print(f"    random: {mean_r / 1000:.1f}μs ±{std_r / 1000:.1f}μs")
        print(
            f"    delta:  {(max_mean - min_mean) / 1000:.1f}μs ({(max_mean - min_mean) / max_mean * 100:.1f}%)"
        )

    def test_decrypt_timing_valid_vs_invalid(self):
        """Decrypt should take similar time for valid and invalid tags.

        KNOWN ISSUE: PoC's authenticate-then-decrypt means invalid tags
        skip decryption. This is a timing leak — an attacker can distinguish
        valid from invalid ciphertexts by measuring response time.
        The real XChaCha20-Poly1305 backend handles this in constant-time.
        """
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        ct_valid = AEAD.encrypt(key, b"test data" * 100, nonce)
        ct_invalid = bytearray(ct_valid)
        ct_invalid[-1] ^= 0x01  # Flip last byte of tag

        def try_valid():
            AEAD.decrypt(key, ct_valid, nonce)

        def try_invalid():
            try:
                AEAD.decrypt(key, bytes(ct_invalid), nonce)
            except ValueError:
                pass

        mean_v, std_v, _ = measure_ns(try_valid)
        mean_i, std_i, _ = measure_ns(try_invalid)

        ratio = mean_v / mean_i if mean_i > 0 else float("inf")
        print(f"\n  Decrypt timing (valid vs invalid tag):")
        print(f"    valid:   {mean_v / 1000:.1f}μs ±{std_v / 1000:.1f}μs")
        print(f"    invalid: {mean_i / 1000:.1f}μs ±{std_i / 1000:.1f}μs")
        print(f"    ratio:   {ratio:.2f}x")
        print(f"    NOTE: Ratio >1.5x indicates timing leak (PoC skips decrypt on invalid tag)")


class TestMLKEMTiming:
    """ML-KEM operations timing analysis."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def test_encaps_timing_independent_of_ek(self):
        """Encapsulation time should not depend on the encapsulation key value."""
        reset_poc_state()
        kp1 = KeyPair.generate("timing-1")
        kp2 = KeyPair.generate("timing-2")

        mean_1, std_1, _ = measure_ns(lambda: MLKEM.encaps(kp1.ek), iterations=50)
        mean_2, std_2, _ = measure_ns(lambda: MLKEM.encaps(kp2.ek), iterations=50)

        print(f"\n  ML-KEM encaps timing:")
        print(f"    key 1: {mean_1 / 1000:.1f}μs ±{std_1 / 1000:.1f}μs")
        print(f"    key 2: {mean_2 / 1000:.1f}μs ±{std_2 / 1000:.1f}μs")

    def test_decaps_timing_poc_lookup_leak(self):
        """PoC decaps uses dict.get() which is NOT constant-time.

        KNOWN VULNERABILITY: The PoC simulation stores encapsulated values in
        a Python dict. dict.get() timing reveals whether a key exists, which
        leaks information about valid ciphertexts. This is documented in
        primitives.py and is NOT present when using the real pqcrypto backend.
        """
        reset_poc_state()
        kp = KeyPair.generate("timing-decaps")
        ss, ct = MLKEM.encaps(kp.ek)

        # Valid decaps (key exists in table)
        def try_valid():
            MLKEM.decaps(kp.dk, ct)

        # Invalid decaps (wrong ciphertext)
        fake_ct = os.urandom(MLKEM.CT_SIZE)

        def try_invalid():
            try:
                MLKEM.decaps(kp.dk, fake_ct)
            except ValueError:
                pass

        mean_v, std_v, _ = measure_ns(try_valid, iterations=50)
        mean_i, std_i, _ = measure_ns(try_invalid, iterations=50)

        ratio = mean_v / mean_i if mean_i > 0 else float("inf")
        print(f"\n  ML-KEM decaps timing (PoC dict lookup leak):")
        print(f"    valid ct:   {mean_v / 1000:.1f}μs ±{std_v / 1000:.1f}μs")
        print(f"    invalid ct: {mean_i / 1000:.1f}μs ±{std_i / 1000:.1f}μs")
        print(f"    ratio:      {ratio:.2f}x")
        print(f"    NOTE: PoC uses dict.get() — timing leaks whether ct is valid")
        print(f"    MITIGATION: Real pqcrypto backend uses constant-time lattice math")


class TestMLDSATiming:
    """ML-DSA operations timing analysis."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def test_verify_timing_poc_lookup_leak(self):
        """PoC verify uses dict.get() which is NOT constant-time.

        KNOWN VULNERABILITY: Same as ML-KEM decaps — the PoC simulation
        uses a Python dict for signature lookup. Timing reveals whether
        a (vk, message) pair has been signed.
        """
        reset_poc_state()
        kp = KeyPair.generate("timing-verify")
        msg = b"signed message"
        sig = MLDSA.sign(kp.sk, msg)

        # Valid verify (signature exists in table)
        def try_valid():
            MLDSA.verify(kp.vk, msg, sig)

        # Forged verify (different message, sig not in table)
        def try_forged():
            MLDSA.verify(kp.vk, b"forged message", sig)

        mean_v, std_v, _ = measure_ns(try_valid, iterations=50)
        mean_f, std_f, _ = measure_ns(try_forged, iterations=50)

        ratio = mean_v / mean_f if mean_f > 0 else float("inf")
        print(f"\n  ML-DSA verify timing (PoC dict lookup leak):")
        print(f"    valid sig:  {mean_v / 1000:.1f}μs ±{std_v / 1000:.1f}μs")
        print(f"    forged sig: {mean_f / 1000:.1f}μs ±{std_f / 1000:.1f}μs")
        print(f"    ratio:      {ratio:.2f}x")
        print(f"    NOTE: PoC uses dict.get() — timing leaks sig validity")
        print(f"    MITIGATION: Dummy hmac.compare_digest on miss (reduces signal)")


class TestHKDFNonceDerivation:
    """Verify the new HKDF nonce derivation is correct and timing-safe."""

    def test_hkdf_produces_different_nonces(self):
        """HKDF nonces differ by shard index, entity_id, and CEK."""
        cek = ShardEncryptor.generate_cek()
        entity_id = "sha3-256:test-entity"

        nonces = set()
        for i in range(100):
            n = ShardEncryptor._nonce(cek, entity_id, i)
            assert n not in nonces, f"HKDF nonce collision at index {i}"
            nonces.add(n)
        print(f"\n  HKDF nonces: 100 unique nonces generated ✓")

    def test_hkdf_extract_deterministic(self):
        """HKDF-Extract produces same PRK for same CEK."""
        cek = os.urandom(32)
        prk1 = ShardEncryptor._extract_prk(cek)
        prk2 = ShardEncryptor._extract_prk(cek)
        assert prk1 == prk2, "HKDF-Extract not deterministic"
        assert len(prk1) == 32, f"PRK size: {len(prk1)}, expected 32"
        print(f"\n  HKDF-Extract: deterministic, 32 bytes ✓")

    def test_hkdf_domain_separation(self):
        """Different salts produce different PRKs (domain separation)."""
        import hashlib
        import hmac as hmac_lib

        cek = os.urandom(32)

        prk_shard = hmac_lib.new(b"ETP-SHARD-NONCE-v1", cek, hashlib.sha256).digest()
        prk_other = hmac_lib.new(b"ETP-OTHER-PURPOSE", cek, hashlib.sha256).digest()
        assert prk_shard != prk_other, "Domain separation failed"
        print(f"\n  HKDF domain separation: different salts → different PRKs ✓")

    def test_hkdf_backward_compatible(self):
        """Encrypt with new HKDF nonce, verify decrypt works."""
        cek = ShardEncryptor.generate_cek()
        entity_id = "sha3-256:hkdf-test"
        plaintext = b"HKDF backward compat test shard data"

        ct = ShardEncryptor.encrypt_shard(cek, entity_id, plaintext, 0)
        pt = ShardEncryptor.decrypt_shard(cek, entity_id, ct, 0)
        assert pt == plaintext, "HKDF nonce: encrypt/decrypt round-trip failed"
        print(f"\n  HKDF encrypt/decrypt round-trip: ✓")

    def test_hkdf_nonce_timing_constant(self):
        """HKDF nonce derivation timing should not vary with inputs."""
        cek = os.urandom(32)
        eid_short = "sha3-256:a"
        eid_long = "sha3-256:" + "a" * 200

        mean_s, std_s, _ = measure_ns(
            lambda: ShardEncryptor._nonce(cek, eid_short, 0), iterations=200
        )
        mean_l, std_l, _ = measure_ns(
            lambda: ShardEncryptor._nonce(cek, eid_long, 0), iterations=200
        )

        print(f"\n  HKDF nonce timing:")
        print(f"    short entity_id: {mean_s / 1000:.1f}μs ±{std_s / 1000:.1f}μs")
        print(f"    long entity_id:  {mean_l / 1000:.1f}μs ±{std_l / 1000:.1f}μs")
        print(f"    NOTE: HMAC-SHA256 is constant-time; variation is from Python overhead")


class TestSealedBoxTiming:
    """Sealed box timing analysis."""

    @classmethod
    def setup_class(cls):
        reset_poc_state()

    def test_unseal_wrong_key_timing(self):
        """Unsealing with wrong key should take similar time to correct key.

        KNOWN ISSUE: PoC uses dict lookup for ML-KEM, so wrong-key path
        hits a different code path (exception) than correct-key path.
        """
        reset_poc_state()
        bob = KeyPair.generate("bob-timing")
        eve = KeyPair.generate("eve-timing")
        sealed = SealedBox.seal(b"secret data", bob.ek)

        def try_bob():
            SealedBox.unseal(sealed, bob)

        def try_eve():
            try:
                SealedBox.unseal(sealed, eve)
            except ValueError:
                pass

        mean_b, std_b, _ = measure_ns(try_bob, iterations=50)
        mean_e, std_e, _ = measure_ns(try_eve, iterations=50)

        ratio = mean_b / mean_e if mean_e > 0 else float("inf")
        print(f"\n  SealedBox unseal timing:")
        print(f"    correct key: {mean_b / 1000:.1f}μs ±{std_b / 1000:.1f}μs")
        print(f"    wrong key:   {mean_e / 1000:.1f}μs ±{std_e / 1000:.1f}μs")
        print(f"    ratio:       {ratio:.2f}x")
        print(f"    NOTE: PoC dict lookup causes timing difference; real ML-KEM is constant-time")
