"""Gateway VM — CLI entry point.

Usage:
    python -m src.ltp.gateway_vm
    etp-gateway  (if installed via pyproject.toml scripts)

Requires: pip install -e ".[gateway,chain,crypto]"
"""

from __future__ import annotations

import os
import sys

from .boot import validate_config
from .config import GatewayVMConfig


def main() -> None:
    """Boot the gateway VM process.

    1. Load config from ETP_GATEWAY_VM_* env vars
    2. Validate required fields (fail-fast)
    3. Create real Web3/RPC callables for source and dest chains
    4. Create DevnetAnchorClient for on-chain anchoring
    5. Build GatewayVMService + GatewayTracker
    6. Create FastAPI app via create_app()
    7. Run uvicorn
    """
    config = GatewayVMConfig.from_env()

    # --- Fail-fast validation ---
    missing = validate_config(config)
    if missing:
        print(
            f"ERROR: Missing required env vars:\n  " + "\n  ".join(missing),
            file=sys.stderr,
        )
        sys.exit(1)

    operator_key = os.environ.get("ETP_GATEWAY_VM_OPERATOR_KEY", "")
    if not operator_key:
        print("ERROR: Missing ETP_GATEWAY_VM_OPERATOR_KEY", file=sys.stderr)
        sys.exit(1)

    # --- Late imports (web3 + crypto may not be installed) ---
    try:
        from web3 import Web3
    except ImportError:
        print(
            'ERROR: web3 not installed. Run: pip install -e ".[gateway,chain,crypto]"',
            file=sys.stderr,
        )
        sys.exit(1)

    from ..keypair import KeyPair
    from .anchor_client import DevnetAnchorClient
    from .app import create_app
    from .service import GatewayVMService
    from .tracker import GatewayTracker

    # --- Source chain RPC ---
    w3_source = Web3(Web3.HTTPProvider(config.source_rpc_url))
    _bridge_addr = Web3.to_checksum_address(config.source_bridge_contract)

    # BridgeEmitter ABI — only the BridgeTransfer event for log decoding.
    _BRIDGE_ABI = [
        {
            "anonymous": False,
            "type": "event",
            "name": "BridgeTransfer",
            "inputs": [
                {"name": "sender", "type": "address", "indexed": True},
                {"name": "recipient", "type": "address", "indexed": True},
                {"name": "payloadHash", "type": "string", "indexed": False},
                {"name": "amount", "type": "uint256", "indexed": False},
                {"name": "nonce", "type": "uint256", "indexed": False},
            ],
        }
    ]
    _bridge_contract = w3_source.eth.contract(
        address=_bridge_addr, abi=_BRIDGE_ABI
    )
    _bridge_transfer_event = _bridge_contract.events.BridgeTransfer()

    # Alchemy limits eth_getLogs to small block ranges.
    # Chunk large ranges to stay within provider limits.
    _LOG_CHUNK_SIZE = 5

    def fetch_logs(from_block: int, to_block: int) -> list[dict]:
        all_logs: list[dict] = []
        cursor = from_block
        while cursor <= to_block:
            chunk_end = min(cursor + _LOG_CHUNK_SIZE - 1, to_block)
            raw_logs = w3_source.eth.get_logs(
                {
                    "fromBlock": cursor,
                    "toBlock": chunk_end,
                    "address": _bridge_addr,
                }
            )
            for raw in raw_logs:
                try:
                    decoded = _bridge_transfer_event.process_log(raw)
                    all_logs.append(
                        {
                            "address": decoded["address"],
                            "transactionHash": decoded["transactionHash"].hex(),
                            "blockNumber": decoded["blockNumber"],
                            "logIndex": decoded["logIndex"],
                            "event": decoded["event"],
                            "args": dict(decoded["args"]),
                        }
                    )
                except Exception:
                    # Skip logs that don't match BridgeTransfer ABI
                    pass
            cursor = chunk_end + 1
        return all_logs

    def get_source_block_number() -> int:
        return w3_source.eth.block_number

    # --- Dest chain RPC ---
    w3_dest = Web3(Web3.HTTPProvider(config.dest_rpc_url))

    def get_dest_block_number() -> int:
        return w3_dest.eth.block_number

    # --- Anchor client ---
    anchor_client = DevnetAnchorClient.from_gateway_config(config, operator_key)

    # --- Operator keypair (ML-DSA-65 for attestation signing) ---
    # Load a pre-generated keypair if available (stable vkHash across restarts),
    # otherwise generate a fresh one (development/testing only).
    import json
    import base64

    keypair_path = os.environ.get("ETP_GATEWAY_VM_KEYPAIR_PATH", "")
    if keypair_path and os.path.exists(keypair_path):
        with open(keypair_path) as f:
            kp_data = json.load(f)
        keypair = KeyPair(
            ek=base64.b64decode(kp_data["ek"]),
            dk=base64.b64decode(kp_data["dk"]),
            vk=base64.b64decode(kp_data["vk"]),
            sk=base64.b64decode(kp_data["sk"]),
            label=kp_data.get("label", config.gateway_id),
        )
        print(f"  Keypair:     loaded from {keypair_path}")
    else:
        keypair = KeyPair.generate(config.gateway_id)
        print("  Keypair:     generated fresh (not persistent)")

    # --- Seed listener near chain tip (avoid scanning entire chain history) ---
    # Use a small window — Alchemy free-tier limits eth_getLogs to ~5 blocks.
    current_source_block = get_source_block_number()
    start_block = max(0, current_source_block - 5)

    # --- Build service ---
    tracker = GatewayTracker()
    service = GatewayVMService(
        config=config,
        operator_keypair=keypair,
        fetch_logs=fetch_logs,
        get_source_block_number=get_source_block_number,
        get_dest_block_number=get_dest_block_number,
        anchor_fn=anchor_client.as_anchor_fn(),
        is_signer_authorized=lambda: True,
        start_block=start_block,
    )

    # --- Create FastAPI app and run ---
    app = create_app(config, service, tracker)

    import uvicorn

    host = os.environ.get("ETP_GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("ETP_GATEWAY_PORT", "8000"))

    print(f"Starting ETP Gateway VM on {host}:{port}")
    print(f"  Gateway ID:   {config.gateway_id}")
    print(f"  Source chain:  {config.source_chain_id}")
    print(f"  Dest chain:    {config.dest_chain_id}")
    print(f"  Challenge:     {config.challenge_mode}")

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
