#!/usr/bin/env python3
"""Python-SDK round-trip against a deployed HyperEVM LTP registry.

Run after scripts/deploy_hyperevm_testnet.sh. Proves the corridor surface
end-to-end from the SDK side:

  1. Builds a ChainConfig from the built-in HYPEREVM_TESTNET chain profile
     (chain ID 998, HyperBFT depth-1 finality posture).
  2. Verifies live configuration (RPC reachable, chain ID matches, registry
     has code) via AnchorClient.verify_live_configuration().
  3. Anchors a fresh digest on-chain under the governance-registered
     bridge-signer vk hash, with the correct monotonic sequence.
  4. Reads the anchor back (isAnchored + entity state).
  5. Builds the LTP-corridor-v1 attestation payload for the
     hyperevm-testnet -> eth-sepolia withdrawal lane over the anchored
     root and checks the lane's depth-1 signing policy against the live
     chain head.

Environment:
  REGISTRY_ADDRESS           deployed registry proxy (ERC1967Proxy) address
  ANCHOR_SENDER_PRIVATE_KEY  funded EOA key that submits the anchor tx
  BRIDGE_OPERATOR_VK_HASH    governance-registered vk hash (0x + 64 hex)
  HYPEREVM_RPC_URL           default https://rpc.hyperliquid-testnet.xyz/evm

Works identically against the real chain-998 testnet and a local
`anvil --chain-id 998` rehearsal.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.ltp.anchor.chain_config import create_anchor_client
from src.ltp.anchor.chain_profiles import HYPEREVM_TESTNET
from src.ltp.anchor.state import EntityState
from src.ltp.anchor.submission import AnchorSubmission
from src.ltp.corridor.lanes import get_lane


def main() -> int:
    rpc_url = os.environ.get("HYPEREVM_RPC_URL", "https://rpc.hyperliquid-testnet.xyz/evm")
    registry = os.environ["REGISTRY_ADDRESS"]
    sender_key = os.environ["ANCHOR_SENDER_PRIVATE_KEY"]
    vk_hash_hex = os.environ["BRIDGE_OPERATOR_VK_HASH"]
    vk_hash = bytes.fromhex(vk_hash_hex.removeprefix("0x"))
    if len(vk_hash) != 32:
        raise SystemExit("BRIDGE_OPERATOR_VK_HASH must be 32 bytes of hex")

    # 1. Chain profile -> ChainConfig -> AnchorClient
    config = HYPEREVM_TESTNET.to_chain_config(
        rpc_url=rpc_url,
        registry_address=registry,
        operator_key=sender_key,
    )
    client = create_anchor_client(config)
    print(
        f"[1] profile={HYPEREVM_TESTNET.label} chain_id={config.chain_id} "
        f"confirmation_depth={config.confirmation_depth}"
    )

    # 2. Fail-fast live configuration check
    client.verify_live_configuration()
    print(f"[2] live config OK: {rpc_url} is chain {config.chain_id}, registry {registry} has code")

    # 3. Anchor a fresh digest under the registered signer
    digest = os.urandom(32)
    state_root = os.urandom(32)
    sequence = client.signer_sequence(vk_hash) + 1
    submission = AnchorSubmission(
        anchor_digest=digest,
        merkle_root=state_root,
        policy_hash=b"\x00" * 32,  # sentinel: no on-chain policy
        signer_vk_hash=vk_hash,
        sequence=sequence,
        valid_until=int(time.time()) + 3600,
        target_chain_id=11_155_111,  # withdrawal lane target: Sepolia
        receipt_type="COMMIT",
    )
    tx_hash = client.anchor(submission)
    print(f"[3] anchored digest 0x{digest.hex()} seq={sequence} tx=0x{tx_hash.lstrip('0x')}")

    # 4. Read it back
    if not client.is_anchored(digest):
        raise SystemExit("FAIL: digest not anchored after tx confirmation")
    state = client.entity_state(digest)
    if state != EntityState.ANCHORED:
        raise SystemExit(f"FAIL: unexpected entity state {state}")
    print(f"[4] read-back OK: isAnchored=True entity_state={state.name}")

    # 5. Corridor-lane payload over the anchored root
    lane = get_lane("hyperevm-testnet:eth-sepolia")
    height = client.get_block_number()
    payload = lane.payload(
        source_height=height,
        state_root=state_root,
        timestamp_round=int(time.time()),
    )
    attestable = lane.is_attestable(source_height=height, source_head=height)
    if not attestable:
        raise SystemExit("FAIL: depth-1 lane must be attestable at head")
    print(
        f"[5] lane={lane.name} height={height} "
        f"canonical_digest=0x{payload.canonical_digest().hex()} attestable={attestable}"
    )

    print("PASS: HyperEVM corridor deployment verified end-to-end")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
