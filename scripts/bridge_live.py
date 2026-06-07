#!/usr/bin/env python3
"""
Live cross-chain bridge execution — SUWAPPU Testnet <-> Base Sepolia.

Runs LiveBridge.transfer() against both live RPCs in both directions,
capturing full TX hashes and writing results to JSON.

Usage:
    # Both directions
    python scripts/bridge_live.py --direction both --output bridge_results.json

    # Single direction
    python scripts/bridge_live.py --direction suwappu-to-base
    python scripts/bridge_live.py --direction base-to-suwappu

Requires:
    - contracts/.env with RPC URLs, operator keys, registry addresses
    - Signers registered on both chains
    - web3 installed (pip install web3)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.ltp.anchor.chain_config import ChainConfig, create_anchor_client
from src.ltp.bridge.challenge import ChallengeManager
from src.ltp.bridge.live import LiveBridge, LiveBridgeResult
from src.ltp.bridge.message import BridgeMessage
from src.ltp.bridge.zk_bridge import SimulatedZKBridgeProver
from src.ltp.commitment import CommitmentNetwork
from src.ltp.keypair import KeyPair, KeyRegistry
from src.ltp.protocol import LTPProtocol

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("bridge_live")


def load_env(env_path: str = "contracts/.env") -> dict[str, str]:
    """Load .env file handling Windows CRLF line endings."""
    env = {}
    path = PROJECT_ROOT / env_path
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Copy from template and configure.")
    with open(path, "r") as f:
        for line in f:
            line = line.strip().replace("\r", "")
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def inject_poa_middleware(client):
    """Inject ExtraDataToPOAMiddleware for PoA chains (SUWAPPU Testnet)."""
    try:
        from web3.middleware import ExtraDataToPOAMiddleware

        client._w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        logger.info("PoA middleware injected for %s", client._w3.provider.endpoint_uri)
    except (ImportError, AttributeError) as e:
        logger.warning("Could not inject PoA middleware: %s", e)


def create_protocol(keypair_path: str = "") -> tuple[LTPProtocol, KeyPair, KeyRegistry]:
    """Create a protocol instance with commitment network and keypair.

    If keypair_path is provided, loads the saved keypair (for registered signer).
    Otherwise generates a fresh one (for testing only).
    """
    if keypair_path:
        kp_file = PROJECT_ROOT / keypair_path
        if kp_file.exists():
            with open(kp_file) as f:
                kp_data = json.load(f)
            kp = KeyPair(
                ek=bytes.fromhex(kp_data["ek_hex"]),
                dk=bytes.fromhex(kp_data["dk_hex"]),
                vk=bytes.fromhex(kp_data["vk_hex"]),
                sk=bytes.fromhex(kp_data["sk_hex"]),
                label=kp_data.get("label", "bridge-operator"),
            )
            logger.info(
                "Loaded keypair from %s (VK hash: %s)", keypair_path, kp_data.get("vk_hash", "?")
            )
        else:
            raise FileNotFoundError(f"Keypair file not found: {kp_file}")
    else:
        kp = KeyPair.generate("bridge-operator")
        logger.info("Generated ephemeral keypair (not registered on-chain)")

    kr = KeyRegistry()
    kr.register(kp)

    network = CommitmentNetwork()
    # Register nodes for shard placement (need at least n=8 for default erasure coding)
    for i in range(8):
        network.register_node(f"bridge-node-{i}", f"region-{i}", stake=1000.0)

    protocol = LTPProtocol(network=network, key_registry=kr)
    return protocol, kp, kr


def build_chain_config(env: dict, prefix: str, chain_id: int, label: str) -> ChainConfig:
    """Build ChainConfig from env vars with a given prefix."""
    rpc_key = f"{prefix}_RPC_URL" if prefix != "BASE_SEPOLIA" else "BASE_SEPOLIA_RPC_URL"
    registry_key = f"{prefix}_ANCHOR_REGISTRY" if prefix == "SUWAPPU" else "L2_PROXY_ADDRESS"
    operator_key_var = f"{prefix}_OPERATOR_KEY" if prefix == "SUWAPPU" else "L2_DEPLOYER_KEY"

    rpc_url = env.get(rpc_key, "")
    registry = env.get(registry_key, "")
    op_key = env.get(operator_key_var, "")

    if not rpc_url or not registry or not op_key:
        raise ValueError(
            f"Missing env vars for {label}: {rpc_key}={bool(rpc_url)}, "
            f"{registry_key}={bool(registry)}, {operator_key_var}={bool(op_key)}"
        )

    return ChainConfig(
        chain_id=chain_id,
        label=label,
        rpc_url=rpc_url,
        registry_address=registry,
        operator_key=op_key,
        tx_timeout=180,
    )


def execute_bridge(
    direction: str,
    protocol: LTPProtocol,
    operator_kp: KeyPair,
    l1_config: ChainConfig,
    l2_config: ChainConfig,
    nonce: int = 1,
) -> dict:
    """Execute a single bridge transfer and return result dict."""
    logger.info("=" * 60)
    logger.info("BRIDGE: %s → %s (nonce=%d)", l1_config.label, l2_config.label, nonce)
    logger.info("=" * 60)

    # Create AnchorClients
    l1_client = create_anchor_client(l1_config)
    l2_client = create_anchor_client(l2_config)

    # Inject PoA middleware for SUWAPPU Testnet
    if l1_config.chain_id == 103115120:
        inject_poa_middleware(l1_client)
    if l2_config.chain_id == 103115120:
        inject_poa_middleware(l2_client)

    # Create challenge manager + ZK prover for full 7-phase bridge
    challenge_mgr = ChallengeManager(challenge_period=3600)
    zk_prover = SimulatedZKBridgeProver()

    # Create LiveBridge
    bridge = LiveBridge(
        protocol=protocol,
        l1_client=l1_client,
        operator_keypair=operator_kp,
        l2_verifier_keypair=operator_kp,  # Same keypair for testnet
        source_chain=l1_config.label,
        dest_chain=l2_config.label,
        l1_chain_id=l1_config.chain_id,
        l2_client=l2_client,
        l2_chain_id=l2_config.chain_id,
        dual_write=True,
        challenge_manager=challenge_mgr,
        zk_prover=zk_prover,
    )

    # Build bridge message
    message = BridgeMessage(
        msg_type="token_lock",
        source_chain=l1_config.label,
        dest_chain=l2_config.label,
        sender="0xcBFDDCb830eE902248F6d1b0A0C64f6e4E35b8E9",
        recipient="0xcBFDDCb830eE902248F6d1b0A0C64f6e4E35b8E9",
        payload={"token": "LTP", "amount": "1000000", "bridge_direction": direction},
        nonce=nonce,
    )

    # Execute
    t0 = time.time()
    result = bridge.transfer(message)
    elapsed = time.time() - t0

    if result is None:
        logger.error("Bridge transfer FAILED for %s", direction)
        return {"direction": direction, "success": False, "error": "materialization failed"}

    # Build result dict
    result_dict = {
        "direction": direction,
        "success": True,
        "entity_id": result.entity_id,
        "l1_chain_id": result.l1_chain_id,
        "l1_anchor_tx_hash": result.l1_anchor_tx_hash,
        "is_anchored_on_l1": result.is_anchored_on_l1,
        "l1_entity_state": result.l1_entity_state,
        "l1_block_height": result.l1_block_height,
        "sequence": result.sequence,
        "cross_chain": result.cross_chain,
        "elapsed_seconds": round(elapsed, 3),
    }

    if result.l2_anchor_tx_hash:
        result_dict["l2_chain_id"] = result.l2_chain_id
        result_dict["l2_anchor_tx_hash"] = result.l2_anchor_tx_hash
        result_dict["is_anchored_on_l2"] = result.is_anchored_on_l2
        result_dict["l2_entity_state"] = result.l2_entity_state
        result_dict["l2_block_height"] = result.l2_block_height

    if result.challenge_status:
        result_dict["challenge_status"] = result.challenge_status
        result_dict["challenge_deadline"] = result.challenge_deadline

    if result.zk_proof_id:
        result_dict["zk_proof_id"] = result.zk_proof_id
        result_dict["zk_finalized"] = result.zk_finalized

    logger.info("Bridge %s COMPLETE in %.1fs", direction, elapsed)
    logger.info("  L1 TX: %s", result.l1_anchor_tx_hash)
    if result.l2_anchor_tx_hash:
        logger.info("  L2 TX: %s", result.l2_anchor_tx_hash)
    logger.info("  Anchored L1: %s, L2: %s", result.is_anchored_on_l1, result.is_anchored_on_l2)
    logger.info("  Challenge: %s, ZK finalized: %s", result.challenge_status, result.zk_finalized)

    return result_dict


def main():
    parser = argparse.ArgumentParser(description="Live cross-chain bridge execution")
    parser.add_argument(
        "--direction",
        choices=["suwappu-to-base", "base-to-suwappu", "both"],
        default="both",
        help="Bridge direction (default: both)",
    )
    parser.add_argument(
        "--output",
        default="bridge_results.json",
        help="Output JSON file (default: bridge_results.json)",
    )
    parser.add_argument(
        "--env-file",
        default="contracts/.env",
        help="Path to .env file (default: contracts/.env)",
    )
    parser.add_argument(
        "--keypair",
        default="bridge_operator_keypair.json",
        help="Path to keypair JSON file (default: bridge_operator_keypair.json)",
    )
    args = parser.parse_args()

    # Load environment
    env = load_env(args.env_file)
    logger.info("Loaded %d env vars from %s", len(env), args.env_file)

    # Build chain configs
    suwappu_config = build_chain_config(env, "SUWAPPU", 103115120, "suwappu_testnet")
    base_config = build_chain_config(env, "BASE_SEPOLIA", 84532, "base_sepolia")

    logger.info("SUWAPPU Testnet: %s → %s", suwappu_config.rpc_url, suwappu_config.registry_address)
    logger.info("Base Sepolia: %s → %s", base_config.rpc_url, base_config.registry_address)

    # Create protocol with registered keypair
    protocol, operator_kp, kr = create_protocol(keypair_path=args.keypair)
    logger.info("Protocol created with 8 commitment nodes")

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "deployer": "0xcBFDDCb830eE902248F6d1b0A0C64f6e4E35b8E9",
        "suwappu_registry": suwappu_config.registry_address,
        "base_registry": base_config.registry_address,
        "transfers": [],
    }

    nonce = 1

    if args.direction in ("suwappu-to-base", "both"):
        r = execute_bridge("suwappu_to_base", protocol, operator_kp, suwappu_config, base_config, nonce)
        results["transfers"].append(r)
        nonce += 1

    if args.direction in ("base-to-suwappu", "both"):
        r = execute_bridge("base_to_suwappu", protocol, operator_kp, base_config, suwappu_config, nonce)
        results["transfers"].append(r)

    # Write results
    output_path = PROJECT_ROOT / args.output
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Results written to %s", output_path)

    # Summary
    success_count = sum(1 for t in results["transfers"] if t.get("success"))
    total = len(results["transfers"])
    logger.info("=" * 60)
    logger.info("SUMMARY: %d/%d transfers succeeded", success_count, total)
    for t in results["transfers"]:
        if t.get("success"):
            logger.info(
                "  %s: L1=%s L2=%s",
                t["direction"],
                t.get("l1_anchor_tx_hash", "N/A"),
                t.get("l2_anchor_tx_hash", "N/A"),
            )
        else:
            logger.info("  %s: FAILED — %s", t["direction"], t.get("error", "unknown"))
    logger.info("=" * 60)

    return 0 if success_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
