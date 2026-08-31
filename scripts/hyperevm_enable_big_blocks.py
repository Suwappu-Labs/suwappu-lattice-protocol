#!/usr/bin/env python3
"""Enable (or disable) the HyperEVM big-block lane for a deployer address.

HyperEVM interleaves small blocks (measured 3,000,000 gas limit on testnet)
with big blocks (measured 30,000,000 gas limit). Contract-deployment
transactions in the LTP stack exceed the small-block limit when batched, so
the deployer must opt its address into the big-block lane before running
`scripts/deploy_hyperevm_testnet.sh`. This is a HyperCore action
(`evmUserModify`), signed with the deployer key via the official
Hyperliquid SDK — not an EVM transaction.

Usage:
  pip install hyperliquid-python-sdk
  DEPLOYER_PRIVATE_KEY=0x... python3 scripts/hyperevm_enable_big_blocks.py [--disable] [--mainnet]

Reads DEPLOYER_PRIVATE_KEY from the environment (same key the deploy script
uses). Defaults to testnet; pass --mainnet for HyperEVM mainnet (chain 999).
After a successful deploy you can switch back to small blocks with --disable
so steady-state anchor writes ride the faster ~1s lane.

This helper is intentionally standalone: it is not imported by the LTP
package and adds no runtime dependency. The Hyperliquid SDK is imported
lazily so the rest of the repo does not require it.
"""

from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Toggle the HyperEVM big-block lane")
    parser.add_argument(
        "--disable",
        action="store_true",
        help="disable big blocks (revert to the small-block lane)",
    )
    parser.add_argument(
        "--mainnet",
        action="store_true",
        help="target HyperEVM mainnet (default: testnet)",
    )
    args = parser.parse_args()

    key = os.environ.get("DEPLOYER_PRIVATE_KEY")
    if not key:
        print("ERROR: DEPLOYER_PRIVATE_KEY is required", file=sys.stderr)
        return 1

    try:
        from eth_account import Account
        from hyperliquid.exchange import Exchange
        from hyperliquid.utils import constants
    except ImportError:
        print(
            "ERROR: the Hyperliquid SDK is required for this helper.\n"
            "  pip install hyperliquid-python-sdk",
            file=sys.stderr,
        )
        return 1

    wallet = Account.from_key(key)
    base_url = constants.MAINNET_API_URL if args.mainnet else constants.TESTNET_API_URL
    net = "mainnet" if args.mainnet else "testnet"
    enable = not args.disable

    exchange = Exchange(wallet, base_url=base_url)
    print(
        f"{'Enabling' if enable else 'Disabling'} big blocks for "
        f"{wallet.address} on HyperEVM {net} ..."
    )
    result = exchange.use_big_blocks(enable)
    print(f"response: {result}")

    status = result.get("status") if isinstance(result, dict) else None
    if status != "ok":
        print("ERROR: big-block toggle was not acknowledged with status=ok", file=sys.stderr)
        return 1
    print(f"OK: {wallet.address} now uses {'BIG' if enable else 'small'} blocks on HyperEVM {net}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
