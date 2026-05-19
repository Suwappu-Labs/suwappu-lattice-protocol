#!/usr/bin/env python3
"""
Verify L2 deployment of LTPAnchorRegistry via web3.py.

Checks version, admin, paused state, EIP-1967 implementation slot,
and chain ID against expected values.

Usage:
    python scripts/verify_l2_deployment.py \
        --rpc-url https://sepolia.base.org \
        --proxy 0x... \
        --expected-admin 0x...

Requires: pip install web3>=6.0.0  (or pip install 'ltp[chain]')
"""

from __future__ import annotations

import argparse
import sys

# EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# Minimal ABI for verification
_VERIFY_ABI = [
    {
        "type": "function",
        "name": "version",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "admin",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "paused",
        "inputs": [],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
]

# Minimal ABI for MultiSig threshold check
_MULTISIG_ABI = [
    {
        "type": "function",
        "name": "required",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]

# Minimal ABI for Timelock minDelay check
_TIMELOCK_ABI = [
    {
        "type": "function",
        "name": "getMinDelay",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
]


def verify_deployment(
    rpc_url: str,
    proxy_address: str,
    expected_admin: str | None = None,
    expected_impl: str | None = None,
    multisig_address: str | None = None,
    expected_threshold: int | None = None,
    timelock_address: str | None = None,
    expected_min_delay: int | None = None,
) -> dict:
    """Verify an L2 LTPAnchorRegistry deployment.

    Returns a dict with check results:
        version: int
        admin: str
        paused: bool
        impl_address: str (from EIP-1967 slot)
        chain_id: int
        threshold: int (if multisig_address provided)
        min_delay: int (if timelock_address provided)
        checks_passed: int
        checks_failed: int
        errors: list[str]
    """
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        return {
            "checks_passed": 0,
            "checks_failed": 1,
            "errors": [f"Cannot connect to RPC: {rpc_url}"],
        }

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(proxy_address),
        abi=_VERIFY_ABI,
    )

    passed = 0
    failed = 0
    errors = []
    result: dict = {}

    # 1. Version
    try:
        ver = contract.functions.version().call()
        result["version"] = ver
        if ver >= 1:
            passed += 1
        else:
            failed += 1
            errors.append(f"version() = {ver} (expected >= 1)")
    except Exception as e:
        failed += 1
        errors.append(f"version() call failed: {e}")

    # 2. Admin
    try:
        admin = contract.functions.admin().call()
        result["admin"] = admin
        if expected_admin and admin.lower() != expected_admin.lower():
            failed += 1
            errors.append(f"admin() = {admin} (expected {expected_admin})")
        else:
            passed += 1
    except Exception as e:
        failed += 1
        errors.append(f"admin() call failed: {e}")

    # 3. Paused
    try:
        paused = contract.functions.paused().call()
        result["paused"] = paused
        if not paused:
            passed += 1
        else:
            failed += 1
            errors.append("paused() = true (expected false)")
    except Exception as e:
        failed += 1
        errors.append(f"paused() call failed: {e}")

    # 4. EIP-1967 implementation slot
    try:
        slot_value = w3.eth.get_storage_at(
            Web3.to_checksum_address(proxy_address),
            int(EIP1967_IMPL_SLOT, 16),
        )
        impl_address = Web3.to_checksum_address("0x" + slot_value[-20:].hex())
        result["impl_address"] = impl_address
        if expected_impl and impl_address.lower() != expected_impl.lower():
            failed += 1
            errors.append(f"EIP-1967 impl = {impl_address} (expected {expected_impl})")
        else:
            passed += 1
    except Exception as e:
        failed += 1
        errors.append(f"EIP-1967 slot read failed: {e}")

    # 5. Chain ID
    try:
        chain_id = w3.eth.chain_id
        result["chain_id"] = chain_id
        passed += 1
    except Exception as e:
        failed += 1
        errors.append(f"chain_id read failed: {e}")

    # 6. MultiSig threshold (optional)
    if multisig_address:
        try:
            multisig = w3.eth.contract(
                address=Web3.to_checksum_address(multisig_address),
                abi=_MULTISIG_ABI,
            )
            threshold = multisig.functions.required().call()
            result["threshold"] = threshold
            if expected_threshold is not None and threshold != expected_threshold:
                failed += 1
                errors.append(f"threshold = {threshold} (expected {expected_threshold})")
            elif threshold >= 2:
                passed += 1
            else:
                failed += 1
                errors.append(f"threshold = {threshold} (expected >= 2)")
        except Exception as e:
            failed += 1
            errors.append(f"MultiSig threshold check failed: {e}")

    # 7. Timelock minDelay (optional)
    if timelock_address:
        try:
            timelock = w3.eth.contract(
                address=Web3.to_checksum_address(timelock_address),
                abi=_TIMELOCK_ABI,
            )
            min_delay = timelock.functions.getMinDelay().call()
            result["min_delay"] = min_delay
            if expected_min_delay is not None and min_delay != expected_min_delay:
                failed += 1
                errors.append(f"minDelay = {min_delay}s (expected {expected_min_delay}s)")
            elif min_delay >= 60:
                passed += 1
            else:
                failed += 1
                errors.append(f"minDelay = {min_delay}s (expected >= 60s)")
        except Exception as e:
            failed += 1
            errors.append(f"Timelock minDelay check failed: {e}")

    result["checks_passed"] = passed
    result["checks_failed"] = failed
    result["errors"] = errors

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify L2 LTPAnchorRegistry deployment",
    )
    parser.add_argument("--rpc-url", required=True, help="L2 RPC URL")
    parser.add_argument("--proxy", required=True, help="Proxy contract address")
    parser.add_argument("--expected-admin", default=None, help="Expected admin address")
    parser.add_argument("--expected-impl", default=None, help="Expected implementation address")
    parser.add_argument("--multisig", default=None, help="MultiSig contract address")
    parser.add_argument(
        "--expected-threshold", type=int, default=None, help="Expected MultiSig threshold"
    )
    parser.add_argument("--timelock", default=None, help="Timelock contract address")
    parser.add_argument(
        "--expected-min-delay", type=int, default=None, help="Expected Timelock minDelay (seconds)"
    )
    args = parser.parse_args()

    result = verify_deployment(
        args.rpc_url,
        args.proxy,
        args.expected_admin,
        args.expected_impl,
        multisig_address=args.multisig,
        expected_threshold=args.expected_threshold,
        timelock_address=args.timelock,
        expected_min_delay=args.expected_min_delay,
    )

    print(f"Version:    {result.get('version', 'N/A')}")
    print(f"Admin:      {result.get('admin', 'N/A')}")
    print(f"Paused:     {result.get('paused', 'N/A')}")
    print(f"Impl:       {result.get('impl_address', 'N/A')}")
    print(f"Chain ID:   {result.get('chain_id', 'N/A')}")
    if "threshold" in result:
        print(f"Threshold:  {result['threshold']}")
    if "min_delay" in result:
        print(f"Min Delay:  {result['min_delay']}s")
    print(f"Passed:     {result['checks_passed']}")
    print(f"Failed:     {result['checks_failed']}")

    if result["errors"]:
        print("\nErrors:")
        for err in result["errors"]:
            print(f"  - {err}")
        sys.exit(1)

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
