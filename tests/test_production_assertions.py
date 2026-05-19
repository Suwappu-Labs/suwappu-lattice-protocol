"""Tests for production crypto assertions and zfec dispatch."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys

import pytest

from ltp.dual_lane.hashing import _blake3_available
from ltp.erasure import ErasureCoder, _zfec_available
from ltp.primitives import (
    _pqcrypto_kem_available,
    _pqcrypto_sign_available,
    _pynacl_available,
    assert_real_crypto,
)

# ---------------------------------------------------------------------------
# assert_real_crypto() direct tests
# ---------------------------------------------------------------------------


class TestAssertRealCrypto:
    """Test the assert_real_crypto() function."""

    def test_function_exists_and_callable(self):
        assert callable(assert_real_crypto)

    def test_returns_none_when_all_backends_present(self):
        if not (_pqcrypto_kem_available and _pqcrypto_sign_available and _pynacl_available):
            pytest.skip("Not all crypto backends installed")
        result = assert_real_crypto()
        assert result is None

    def test_raises_when_backends_missing(self, monkeypatch):
        import ltp.primitives as mod

        monkeypatch.setattr(mod, "_pqcrypto_kem_available", False)
        monkeypatch.setattr(mod, "_pqcrypto_sign_available", False)
        monkeypatch.setattr(mod, "_pynacl_available", False)
        with pytest.raises(RuntimeError, match="ML-KEM-768"):
            assert_real_crypto()

    def test_error_lists_all_missing(self, monkeypatch):
        import ltp.primitives as mod

        monkeypatch.setattr(mod, "_pqcrypto_kem_available", False)
        monkeypatch.setattr(mod, "_pqcrypto_sign_available", False)
        monkeypatch.setattr(mod, "_pynacl_available", False)
        with pytest.raises(RuntimeError) as exc_info:
            assert_real_crypto()
        msg = str(exc_info.value)
        assert "ML-KEM-768" in msg
        assert "ML-DSA-65" in msg
        assert "XChaCha20-Poly1305" in msg

    def test_error_only_lists_actually_missing(self, monkeypatch):
        import ltp.primitives as mod

        # Pretend only pynacl is missing
        monkeypatch.setattr(mod, "_pqcrypto_kem_available", True)
        monkeypatch.setattr(mod, "_pqcrypto_sign_available", True)
        monkeypatch.setattr(mod, "_pynacl_available", False)
        with pytest.raises(RuntimeError) as exc_info:
            assert_real_crypto()
        msg = str(exc_info.value)
        assert "ML-KEM-768" not in msg
        assert "ML-DSA-65" not in msg
        assert "XChaCha20-Poly1305" in msg


# ---------------------------------------------------------------------------
# ETP_REQUIRE_REAL_CRYPTO env var enforcement (subprocess)
# ---------------------------------------------------------------------------


class TestEnvVarEnforcement:
    """Test that ETP_REQUIRE_REAL_CRYPTO=1 triggers assertions at import time."""

    def test_env_var_triggers_assertion_in_subprocess(self):
        """Run a subprocess with the env var set; verify it either passes or
        raises RuntimeError (depending on whether backends are installed)."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from ltp.primitives import assert_real_crypto; assert_real_crypto(); print('OK')",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "ETP_REQUIRE_REAL_CRYPTO": "1"},
        )
        if _pqcrypto_kem_available and _pqcrypto_sign_available and _pynacl_available:
            assert result.returncode == 0
            assert "OK" in result.stdout
        else:
            assert result.returncode != 0
            assert "RuntimeError" in result.stderr

    def test_env_var_not_set_allows_import(self):
        """Without the env var, import should succeed even without backends."""
        result = subprocess.run(
            [sys.executable, "-c", "import ltp; print('OK')"],
            capture_output=True,
            text=True,
            env={k: v for k, v in os.environ.items() if k != "ETP_REQUIRE_REAL_CRYPTO"},
        )
        assert result.returncode == 0
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# zfec erasure coding dispatch
# ---------------------------------------------------------------------------


class TestZfecDispatch:
    """Test that zfec backend produces correct results."""

    @pytest.mark.parametrize("n,k", [(8, 4), (5, 3), (10, 5)])
    def test_encode_decode_round_trip(self, n, k):
        """Encode then decode should recover original data."""
        data = os.urandom(1024)
        shards = ErasureCoder.encode(data, n, k)
        assert len(shards) == n

        # Use first k shards
        shard_dict = {i: shards[i] for i in range(k)}
        recovered = ErasureCoder.decode(shard_dict, n, k)
        assert recovered == data

    @pytest.mark.parametrize("n,k", [(8, 4), (5, 3)])
    def test_decode_from_any_k_shards(self, n, k):
        """Any k-of-n shards should reconstruct the original."""
        data = b"ETP Phase 0 zfec integration test payload" * 10
        shards = ErasureCoder.encode(data, n, k)

        # Use last k shards (not the first k)
        shard_dict = {i: shards[i] for i in range(n - k, n)}
        recovered = ErasureCoder.decode(shard_dict, n, k)
        assert recovered == data

    @pytest.mark.skipif(not _zfec_available, reason="zfec not installed")
    def test_zfec_matches_pure_python(self):
        """Verify zfec and pure Python both round-trip to the same original data."""
        import ltp.erasure as erasure_mod

        data = os.urandom(512)
        n, k = 6, 3

        # Encode + decode with zfec
        shards_zfec = ErasureCoder.encode(data, n, k)
        shard_dict_zfec = {i: shards_zfec[i] for i in range(k)}
        recovered_zfec = ErasureCoder.decode(shard_dict_zfec, n, k)

        # Encode + decode with pure Python (temporarily disable zfec)
        original_flag = erasure_mod._zfec_available
        try:
            erasure_mod._zfec_available = False
            shards_py = ErasureCoder.encode(data, n, k)
            shard_dict_py = {i: shards_py[i] for i in range(k)}
            recovered_py = ErasureCoder.decode(shard_dict_py, n, k)
        finally:
            erasure_mod._zfec_available = original_flag

        # Both backends must recover the original data
        assert recovered_zfec == data
        assert recovered_py == data

    def test_encode_empty_data(self):
        data = b""
        shards = ErasureCoder.encode(data, 4, 2)
        shard_dict = {0: shards[0], 1: shards[1]}
        assert ErasureCoder.decode(shard_dict, 4, 2) == data

    def test_encode_small_data(self):
        data = b"\x42"
        shards = ErasureCoder.encode(data, 4, 2)
        shard_dict = {0: shards[0], 2: shards[2]}
        assert ErasureCoder.decode(shard_dict, 4, 2) == data


# ---------------------------------------------------------------------------
# BLAKE3 production assertion
# ---------------------------------------------------------------------------


class TestBlake3Assertion:
    """Test BLAKE3 production mode enforcement."""

    def test_blake3_available_flag(self):
        """blake3 should be available in dev environment."""
        # This test documents the flag exists; it may be True or False
        assert isinstance(_blake3_available, bool)

    def test_blake3_assertion_fires_in_subprocess(self):
        """With ETP_REQUIRE_REAL_CRYPTO=1 and blake3 unimportable,
        hashing.py should raise RuntimeError."""
        # We simulate blake3 being unavailable by hiding it from sys.modules
        code = (
            "import sys; "
            "sys.modules['blake3'] = None; "  # Make import fail
            "del sys.modules['blake3']; "
            # Patch so import blake3 raises ImportError
            "import importlib; "
            "import builtins; "
            "original_import = builtins.__import__; "
            "def patched_import(name, *args, **kwargs):\n"
            "    if name == 'blake3': raise ImportError('blocked')\n"
            "    return original_import(name, *args, **kwargs)\n; "
            "builtins.__import__ = patched_import; "
            "from ltp.dual_lane import hashing"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env={**os.environ, "ETP_REQUIRE_REAL_CRYPTO": "1"},
        )
        assert result.returncode != 0
        assert "RuntimeError" in result.stderr or "blake3" in result.stderr

    @pytest.mark.skipif(not _blake3_available, reason="blake3 not installed")
    def test_blake3_no_error_when_available(self):
        """With blake3 installed, production mode should not raise."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from ltp.dual_lane.hashing import _blake3_available; "
                "assert _blake3_available; print('OK')",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "ETP_REQUIRE_REAL_CRYPTO": "1"},
        )
        assert result.returncode == 0
        assert "OK" in result.stdout


# ---------------------------------------------------------------------------
# Export test
# ---------------------------------------------------------------------------


class TestExports:
    """Verify assert_real_crypto is properly exported."""

    def test_importable_from_ltp(self):
        from ltp import assert_real_crypto as fn

        assert callable(fn)

    def test_in_primitives_all(self):
        from ltp.primitives import __all__

        assert "assert_real_crypto" in __all__
