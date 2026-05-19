"""
Tests for the L2 deployment verification script.

Uses mock web3 to avoid network dependency.
"""

from __future__ import annotations

import sys
import types

import pytest


def _make_mock_web3(
    version: int = 5,
    admin: str = "0x" + "aB" * 20,
    paused: bool = False,
    chain_id: int = 84532,
    storage_bytes: bytes | None = None,
    connected: bool = True,
):
    """Create a mock web3 module that returns predetermined values."""
    mod = types.ModuleType("web3")

    class _Functions:
        def __init__(self):
            pass

        def version(self):
            return self

        def admin(self):
            return self

        def paused(self):
            return self

        def call(self):
            # This is set per-function below
            raise NotImplementedError

    class _Contract:
        def __init__(self, addr, abi):
            self.address = addr

            class _Funcs:
                def version(self_inner):
                    class _V:
                        def call(self_call):
                            return version

                    return _V()

                def admin(self_inner):
                    class _A:
                        def call(self_call):
                            return admin

                    return _A()

                def paused(self_inner):
                    class _P:
                        def call(self_call):
                            return paused

                    return _P()

            self.functions = _Funcs()

    if storage_bytes is None:
        # Default: admin address padded to 32 bytes
        storage_bytes = b"\x00" * 12 + bytes.fromhex(admin[2:])

    _chain_id = chain_id
    _storage_bytes = storage_bytes

    class _Eth:
        chain_id = _chain_id

        def get_storage_at(self, addr, slot):
            return _storage_bytes

        def contract(self, address, abi):
            return _Contract(address, abi)

    class _MockW3:
        class HTTPProvider:
            def __init__(self, url):
                self.url = url

        def __init__(self, provider):
            self.eth = _Eth()

        def is_connected(self):
            return connected

        @staticmethod
        def to_checksum_address(addr):
            return addr

    mod.Web3 = _MockW3  # type: ignore[attr-defined]
    return mod


class TestVerifyDeployment:
    def test_verify_happy_path(self, monkeypatch):
        admin_addr = "0x" + "aB" * 20
        mock = _make_mock_web3(version=5, admin=admin_addr, paused=False)
        monkeypatch.setitem(sys.modules, "web3", mock)

        # Force reimport
        if "scripts.verify_l2_deployment" in sys.modules:
            del sys.modules["scripts.verify_l2_deployment"]

        from scripts.verify_l2_deployment import verify_deployment

        result = verify_deployment(
            rpc_url="http://localhost:8545",
            proxy_address="0x" + "11" * 20,
            expected_admin=admin_addr,
        )

        assert result["checks_passed"] >= 4
        assert result["checks_failed"] == 0
        assert result["version"] == 5
        assert result["paused"] is False
        assert result["errors"] == []

    def test_verify_wrong_version(self, monkeypatch):
        mock = _make_mock_web3(version=0)
        monkeypatch.setitem(sys.modules, "web3", mock)

        if "scripts.verify_l2_deployment" in sys.modules:
            del sys.modules["scripts.verify_l2_deployment"]

        from scripts.verify_l2_deployment import verify_deployment

        result = verify_deployment(
            rpc_url="http://localhost:8545",
            proxy_address="0x" + "11" * 20,
        )

        assert result["checks_failed"] >= 1
        assert any("version" in e for e in result["errors"])

    def test_verify_wrong_admin(self, monkeypatch):
        actual_admin = "0x" + "aB" * 20
        expected_admin = "0x" + "CD" * 20
        mock = _make_mock_web3(admin=actual_admin)
        monkeypatch.setitem(sys.modules, "web3", mock)

        if "scripts.verify_l2_deployment" in sys.modules:
            del sys.modules["scripts.verify_l2_deployment"]

        from scripts.verify_l2_deployment import verify_deployment

        result = verify_deployment(
            rpc_url="http://localhost:8545",
            proxy_address="0x" + "11" * 20,
            expected_admin=expected_admin,
        )

        assert result["checks_failed"] >= 1
        assert any("admin" in e for e in result["errors"])

    def test_verify_wrong_impl(self, monkeypatch):
        actual_impl_bytes = b"\x00" * 12 + bytes.fromhex("aa" * 20)
        mock = _make_mock_web3(storage_bytes=actual_impl_bytes)
        monkeypatch.setitem(sys.modules, "web3", mock)

        if "scripts.verify_l2_deployment" in sys.modules:
            del sys.modules["scripts.verify_l2_deployment"]

        from scripts.verify_l2_deployment import verify_deployment

        result = verify_deployment(
            rpc_url="http://localhost:8545",
            proxy_address="0x" + "11" * 20,
            expected_impl="0x" + "BB" * 20,
        )

        assert result["checks_failed"] >= 1
        assert any("EIP-1967" in e for e in result["errors"])
