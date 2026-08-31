#!/usr/bin/env bash
# deploy_hyperevm_testnet.sh — deploy the LTP registry + bridge stack to
# Hyperliquid HyperEVM testnet (chain ID 998) and register the bridge
# operator's ML-DSA-65 vk hash through the full governance path
# (MultiSig -> Timelock -> Registry).
#
# The same script drives a local rehearsal: start `anvil --chain-id 998`
# and run with LOCAL_REHEARSAL=1 (uses evm_increaseTime for the timelock
# delay instead of waiting wall-clock).
#
# Required environment:
#   DEPLOYER_PRIVATE_KEY     funded key on the target chain (gas is HYPE on 998)
#   OPERATOR_PRIVATE_KEY     second MultiSig owner key (funded for confirm txs)
#   BRIDGE_OPERATOR_VK_HASH  0x + 64 hex — ML-DSA-65 vk hash to authorize
#
# Optional environment:
#   HYPEREVM_RPC_URL         default https://rpc.hyperliquid-testnet.xyz/evm
#   EXPECTED_CHAIN_ID        default 998; the script refuses to touch any other chain
#   LOCAL_REHEARSAL=1        target is a local anvil: skip faucet/big-block guidance,
#                            fast-forward the timelock delay via evm_increaseTime
#
# HyperEVM gotchas this script accounts for:
#   - Gas token is HYPE, not ETH. Fund the deployer via the Hyperliquid
#     testnet faucet before running.
#   - HyperEVM interleaves small blocks (measured 3,000,000 gas limit on
#     testnet) with big blocks (measured 30,000,000 gas limit). The batched
#     stack deploy needs ~6.3M gas, so the deployer must ride the big-block
#     lane. This script measures the live small-block limit at preflight and,
#     unless BIG_BLOCKS_READY=1, runs scripts/hyperevm_enable_big_blocks.py
#     to opt the deployer in via the Hyperliquid SDK before deploying.
#     After the deploy, revert with:
#       DEPLOYER_PRIVATE_KEY=... python3 scripts/hyperevm_enable_big_blocks.py --disable
#
# Sequencing reference: docs/plans/2026-08-31-hyperliquid-ethereum-corridor.md

set -euo pipefail
cd "$(dirname "$0")/.."

RPC="${HYPEREVM_RPC_URL:-https://rpc.hyperliquid-testnet.xyz/evm}"
EXPECTED_CHAIN_ID="${EXPECTED_CHAIN_ID:-998}"
LOCAL_REHEARSAL="${LOCAL_REHEARSAL:-0}"

: "${DEPLOYER_PRIVATE_KEY:?DEPLOYER_PRIVATE_KEY is required (funded on the target chain)}"
: "${OPERATOR_PRIVATE_KEY:?OPERATOR_PRIVATE_KEY is required (second MultiSig owner)}"
: "${BRIDGE_OPERATOR_VK_HASH:?BRIDGE_OPERATOR_VK_HASH is required (0x + 64 hex ML-DSA-65 vk hash)}"

if ! [[ "$BRIDGE_OPERATOR_VK_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "ERROR: BRIDGE_OPERATOR_VK_HASH must be 0x followed by 64 hex chars" >&2
    exit 1
fi

for tool in forge cast python3; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not on PATH" >&2; exit 1; }
done

ZERO32=0x0000000000000000000000000000000000000000000000000000000000000000

step() { echo ""; echo "── $* ──────────────────────────────────────────"; }

# ---------------------------------------------------------------------------
step "Preflight"
# ---------------------------------------------------------------------------

CHAIN_ID=$(cast chain-id --rpc-url "$RPC")
if [ "$CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]; then
    echo "ERROR: RPC $RPC reports chain ID $CHAIN_ID, expected $EXPECTED_CHAIN_ID." >&2
    echo "Refusing to deploy to an unexpected chain." >&2
    exit 1
fi

DEPLOYER=$(cast wallet address "$DEPLOYER_PRIVATE_KEY")
OPERATOR=$(cast wallet address "$OPERATOR_PRIVATE_KEY")
if [ "$DEPLOYER" = "$OPERATOR" ]; then
    echo "ERROR: deployer and operator must be distinct (2-of-2 MultiSig owners)" >&2
    exit 1
fi

DEPLOYER_BALANCE=$(cast balance "$DEPLOYER" --rpc-url "$RPC")
OPERATOR_BALANCE=$(cast balance "$OPERATOR" --rpc-url "$RPC")
if [ "$DEPLOYER_BALANCE" = "0" ] || [ "$OPERATOR_BALANCE" = "0" ]; then
    echo "ERROR: deployer ($DEPLOYER: $DEPLOYER_BALANCE wei) and operator" >&2
    echo "($OPERATOR: $OPERATOR_BALANCE wei) both need gas on chain $CHAIN_ID." >&2
    if [ "$LOCAL_REHEARSAL" != "1" ]; then
        echo "Fund them with testnet HYPE via the Hyperliquid testnet faucet" >&2
        echo "(app.hyperliquid-testnet.xyz), then re-run." >&2
    fi
    exit 1
fi

echo "Chain ID:  $CHAIN_ID"
echo "Deployer:  $DEPLOYER"
echo "Operator:  $OPERATOR"

# Big-block lane: the batched stack deploy (~6.3M gas) exceeds HyperEVM's
# small-block limit. Measure the live limit and opt the deployer into big
# blocks unless we're on a local rehearsal or the caller asserts it's ready.
if [ "$LOCAL_REHEARSAL" != "1" ]; then
    BLOCK_GAS_LIMIT=$(cast rpc eth_getBlockByNumber latest false --rpc-url "$RPC" \
        | python3 -c "import json,sys;print(int(json.load(sys.stdin)['gasLimit'],16))" 2>/dev/null || echo 0)
    echo "Live block gas limit: $BLOCK_GAS_LIMIT (small-block lane if ~3,000,000)"
    if [ "${BIG_BLOCKS_READY:-0}" = "1" ]; then
        echo "BIG_BLOCKS_READY=1 — assuming the deployer is already on the big-block lane."
    elif [ "$BLOCK_GAS_LIMIT" -ge 30000000 ] 2>/dev/null; then
        echo "Block gas limit already >= 30M; big-block lane looks active."
    else
        echo "Enabling the big-block lane for the deployer via the Hyperliquid SDK..."
        BIG_ARGS=""
        [ "$EXPECTED_CHAIN_ID" = "999" ] && BIG_ARGS="--mainnet"
        if ! DEPLOYER_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY" \
             python3 "$(dirname "$0")/hyperevm_enable_big_blocks.py" $BIG_ARGS; then
            echo "ERROR: could not enable big blocks. Enable it manually, then re-run" >&2
            echo "with BIG_BLOCKS_READY=1:" >&2
            echo "  DEPLOYER_PRIVATE_KEY=... python3 scripts/hyperevm_enable_big_blocks.py${BIG_ARGS:+ $BIG_ARGS}" >&2
            exit 1
        fi
    fi
fi

# Extract "contractName -> address" pairs from a forge broadcast artifact.
addr_from_broadcast() {
    local script_name=$1 contract_name=$2
    python3 - "$script_name" "$CHAIN_ID" "$contract_name" <<'EOF'
import json, sys
script, chain_id, wanted = sys.argv[1], sys.argv[2], sys.argv[3]
path = f"contracts/broadcast/{script}/{chain_id}/run-latest.json"
with open(path) as f:
    run = json.load(f)
for tx in run["transactions"]:
    if tx.get("transactionType") == "CREATE" and tx.get("contractName") == wanted:
        print(tx["contractAddress"])
        break
else:
    sys.exit(f"{wanted} not found in {path}")
EOF
}

# ---------------------------------------------------------------------------
step "Phase 1: registry stack (LTPAnchorRegistry + MultiSig + Timelock)"
# ---------------------------------------------------------------------------

SUWAPPU_OPERATOR_ADDRESS="$OPERATOR" forge script contracts/script/DeployTestnet.s.sol \
    --root contracts --rpc-url "$RPC" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast

REGISTRY_IMPL=$(addr_from_broadcast DeployTestnet.s.sol LTPAnchorRegistry)
REGISTRY_PROXY=$(addr_from_broadcast DeployTestnet.s.sol ERC1967Proxy)
MULTISIG=$(addr_from_broadcast DeployTestnet.s.sol LTPMultiSig)
TIMELOCK=$(addr_from_broadcast DeployTestnet.s.sol TimelockController)

echo "Registry impl:    $REGISTRY_IMPL"
echo "Registry (proxy): $REGISTRY_PROXY"
echo "MultiSig:         $MULTISIG"
echo "Timelock:         $TIMELOCK"

# ---------------------------------------------------------------------------
step "Phase 2: bridge stack (OptimisticBridgeChallenge + ZKBridgeVerifier)"
# ---------------------------------------------------------------------------

BRIDGE_TIMELOCK_ADMIN="$TIMELOCK" forge script contracts/script/DeployBridge.s.sol \
    --root contracts --rpc-url "$RPC" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast

CHALLENGE=$(addr_from_broadcast DeployBridge.s.sol OptimisticBridgeChallenge)
ZK_VERIFIER=$(addr_from_broadcast DeployBridge.s.sol ZKBridgeVerifier)

echo "OptimisticBridgeChallenge: $CHALLENGE"
echo "ZKBridgeVerifier:          $ZK_VERIFIER"

# ---------------------------------------------------------------------------
step "Phase 3: governance registration of the bridge signer vk hash"
# ---------------------------------------------------------------------------
# Full path per docs/DEPLOYED_CONTRACTS.md: every admin call goes
# MultiSig(submit -> confirm -> execute) -> Timelock(schedule, then after
# the delay a second MultiSig round for Timelock.execute) -> Registry.

SALT=$(cast keccak "ltp-hyperevm-bridge-signer-v1")
DELAY=$(cast call "$TIMELOCK" "getMinDelay()(uint256)" --rpc-url "$RPC")
REG_CALL=$(cast calldata "registerSigner(bytes32)" "$BRIDGE_OPERATOR_VK_HASH")

# One MultiSig round: deployer submits (auto-confirms), operator confirms,
# deployer executes. $1 = target, $2 = calldata.
multisig_round() {
    local target=$1 data=$2
    local tx_id
    tx_id=$(cast call "$MULTISIG" "getTransactionCount()(uint256)" --rpc-url "$RPC")
    cast send "$MULTISIG" "submitTransaction(address,uint256,bytes)" \
        "$target" 0 "$data" \
        --rpc-url "$RPC" --private-key "$DEPLOYER_PRIVATE_KEY" >/dev/null
    cast send "$MULTISIG" "confirmTransaction(uint256)" "$tx_id" \
        --rpc-url "$RPC" --private-key "$OPERATOR_PRIVATE_KEY" >/dev/null
    cast send "$MULTISIG" "executeTransaction(uint256)" "$tx_id" \
        --rpc-url "$RPC" --private-key "$DEPLOYER_PRIVATE_KEY" >/dev/null
    echo "$tx_id"
}

SCHEDULE_CALL=$(cast calldata "schedule(address,uint256,bytes,bytes32,bytes32,uint256)" \
    "$REGISTRY_PROXY" 0 "$REG_CALL" "$ZERO32" "$SALT" "$DELAY")
TX1=$(multisig_round "$TIMELOCK" "$SCHEDULE_CALL")
echo "Timelock.schedule executed via MultiSig tx #$TX1 (delay: ${DELAY}s)"

if [ "$LOCAL_REHEARSAL" = "1" ]; then
    cast rpc evm_increaseTime "$((DELAY + 1))" --rpc-url "$RPC" >/dev/null
    cast rpc evm_mine --rpc-url "$RPC" >/dev/null
    echo "Local rehearsal: fast-forwarded $((DELAY + 1))s"
else
    echo "Waiting ${DELAY}s for the timelock delay..."
    sleep "$((DELAY + 5))"
fi

EXECUTE_CALL=$(cast calldata "execute(address,uint256,bytes,bytes32,bytes32)" \
    "$REGISTRY_PROXY" 0 "$REG_CALL" "$ZERO32" "$SALT")
TX2=$(multisig_round "$TIMELOCK" "$EXECUTE_CALL")
echo "Timelock.execute executed via MultiSig tx #$TX2 (registerSigner ran)"

# ---------------------------------------------------------------------------
step "Phase 4: on-chain verification"
# ---------------------------------------------------------------------------

REGISTERED=$(cast call "$REGISTRY_PROXY" "authorizedSigners(bytes32)(bool)" \
    "$BRIDGE_OPERATOR_VK_HASH" --rpc-url "$RPC")
REGISTRY_ADMIN=$(cast call "$REGISTRY_PROXY" "admin()(address)" --rpc-url "$RPC")

echo "Signer $BRIDGE_OPERATOR_VK_HASH registered: $REGISTERED"
echo "Registry admin (must be the Timelock):      $REGISTRY_ADMIN"

if [ "$REGISTERED" != "true" ]; then
    echo "ERROR: signer registration did not take effect" >&2
    exit 1
fi
if [ "$(echo "$REGISTRY_ADMIN" | tr '[:upper:]' '[:lower:]')" != "$(echo "$TIMELOCK" | tr '[:upper:]' '[:lower:]')" ]; then
    echo "ERROR: registry admin is not the Timelock" >&2
    exit 1
fi

step "DONE — record these in docs/DEPLOYED_CONTRACTS.md (real testnet only)"
cat <<SUMMARY
Chain ID:                  $CHAIN_ID
LTPAnchorRegistry (impl):  $REGISTRY_IMPL
ERC1967Proxy (registry):   $REGISTRY_PROXY
LTPMultiSig (2-of-2):      $MULTISIG
TimelockController:        $TIMELOCK
OptimisticBridgeChallenge: $CHALLENGE
ZKBridgeVerifier:          $ZK_VERIFIER
Bridge signer vk hash:     $BRIDGE_OPERATOR_VK_HASH

Next: scripts/verify_corridor_deployment.py runs the Python-SDK anchor
round-trip against this deployment (see its header for usage).
SUMMARY
