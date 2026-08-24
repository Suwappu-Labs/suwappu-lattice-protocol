#!/usr/bin/env bash
# Register an ML-DSA-65 signer vkHash on a freshly deployed leg's LTPAnchorRegistry,
# via the full governance path:
#
#   MultiSig.submit (deployer, auto-confirms)
#     -> MultiSig.confirm (operator)
#     -> MultiSig.execute        (calls Timelock.schedule)
#     -> wait timelock delay
#     -> Timelock.execute        (calls Registry.registerSigner)
#
# Usage:
#   scripts/register_signer_leg.sh config/deploy/<chain>.env [deployments/<label>.json]
#
# Reads MULTISIG / TIMELOCK / REGISTRY addresses from the deployments JSON written
# by scripts/deploy_testnet_leg.sh, and SIGNER_VK_HASH / keys from the env file.
# Equivalent to contracts/script/RegisterGatewaySigner.s.sol but parameterized per
# chain, so no per-leg Solidity edits are needed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }

ENV_FILE="${1:-}"
[ -n "$ENV_FILE" ] || die "usage: $0 config/deploy/<chain>.env [deployments/<label>.json]"
[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

DEPLOY_JSON="${2:-$REPO_ROOT/deployments/$CHAIN_LABEL.json}"
[ -f "$DEPLOY_JSON" ] || die "deployments file not found: $DEPLOY_JSON (run deploy_testnet_leg.sh first)"

for v in RPC_URL DEPLOYER_PRIVATE_KEY OPERATOR_PRIVATE_KEY SIGNER_VK_HASH; do
    [ -n "${!v:-}" ] || die "$v is not set in $ENV_FILE"
    case "${!v}" in *FILL_ME*) die "$v still has the placeholder value in $ENV_FILE";; esac
done
command -v cast >/dev/null || die "cast not found — install foundry"
command -v jq   >/dev/null || die "jq not found"

MULTISIG="$(jq -r '.contracts.LTPMultiSig' "$DEPLOY_JSON")"
TIMELOCK="$(jq -r '.contracts.TimelockController' "$DEPLOY_JSON")"
REGISTRY="$(jq -r '.contracts.ERC1967Proxy' "$DEPLOY_JSON")"
for v in MULTISIG TIMELOCK REGISTRY; do
    [ -n "${!v}" ] && [ "${!v}" != "null" ] || die "missing $v in $DEPLOY_JSON"
done

ZERO32=0x0000000000000000000000000000000000000000000000000000000000000000
SALT="$(cast keccak "ltp-signer-registration-$CHAIN_LABEL-$SIGNER_VK_HASH")"

echo "== Registering signer on $CHAIN_LABEL =="
echo "Registry: $REGISTRY"
echo "vkHash:   $SIGNER_VK_HASH"

REGISTRY_CALL="$(cast calldata "registerSigner(bytes32)" "$SIGNER_VK_HASH")"
DELAY="$(cast call "$TIMELOCK" "getMinDelay()(uint256)" --rpc-url "$RPC_URL")"
DELAY="${DELAY%% *}"
TIMELOCK_CALL="$(cast calldata "schedule(address,uint256,bytes,bytes32,bytes32,uint256)" \
    "$REGISTRY" 0 "$REGISTRY_CALL" "$ZERO32" "$SALT" "$DELAY")"

# Idempotency: skip submit/confirm/execute when the timelock op already exists
# (lets the script be re-run after an interrupted wait without re-proposing).
OP_ID="$(cast call "$TIMELOCK" \
    "hashOperation(address,uint256,bytes,bytes32,bytes32)(bytes32)" \
    "$REGISTRY" 0 "$REGISTRY_CALL" "$ZERO32" "$SALT" --rpc-url "$RPC_URL")"
if [ "$(cast call "$TIMELOCK" "isOperationDone(bytes32)(bool)" "$OP_ID" --rpc-url "$RPC_URL")" = "true" ]; then
    echo "Operation already executed — nothing to do."
    exit 0
fi
ALREADY_SCHEDULED="$(cast call "$TIMELOCK" "isOperation(bytes32)(bool)" "$OP_ID" --rpc-url "$RPC_URL")"

if [ "$ALREADY_SCHEDULED" != "true" ]; then
# Step 1: deployer submits (auto-confirm #1)
echo "-- Step 1: MultiSig.submit (deployer)"
cast send "$MULTISIG" "submitTransaction(address,uint256,bytes)" "$TIMELOCK" 0 "$TIMELOCK_CALL" \
    --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" >/dev/null
TX_COUNT="$(cast call "$MULTISIG" "getTransactionCount()(uint256)" --rpc-url "$RPC_URL")"
TX_ID=$(( ${TX_COUNT%% *} - 1 ))
echo "   MultiSig TX ID: $TX_ID"

# Step 2: operator confirms (#2 of 2)
echo "-- Step 2: MultiSig.confirm (operator)"
cast send "$MULTISIG" "confirmTransaction(uint256)" "$TX_ID" \
    --rpc-url "$RPC_URL" --private-key "$OPERATOR_PRIVATE_KEY" >/dev/null

# Step 3: execute multisig tx -> Timelock.schedule
echo "-- Step 3: MultiSig.execute (schedules timelock op)"
cast send "$MULTISIG" "executeTransaction(uint256)" "$TX_ID" \
    --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" >/dev/null
else
    echo "Timelock operation already scheduled — skipping multisig steps."
fi

# Step 4: wait out the delay, then execute the timelock op
echo "-- Step 4: waiting ${DELAY}s timelock delay (op $OP_ID)"
sleep $(( DELAY + 5 ))

for attempt in 1 2 3 4 5; do
    READY="$(cast call "$TIMELOCK" "isOperationReady(bytes32)(bool)" "$OP_ID" --rpc-url "$RPC_URL")"
    [ "$READY" = "true" ] && break
    echo "   not ready yet (attempt $attempt), sleeping 15s"
    sleep 15
done
[ "$READY" = "true" ] || die "timelock operation never became ready — re-run later with the same env"

# The timelock's only executor is the multisig, so Timelock.execute goes through
# a second multisig round (this is why the original legs took 6 registration txs).
echo "-- Step 5: Timelock.execute via second MultiSig round (registers signer)"
EXEC_CALL="$(cast calldata "execute(address,uint256,bytes,bytes32,bytes32)" \
    "$REGISTRY" 0 "$REGISTRY_CALL" "$ZERO32" "$SALT")"
cast send "$MULTISIG" "submitTransaction(address,uint256,bytes)" "$TIMELOCK" 0 "$EXEC_CALL" \
    --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" >/dev/null
TX_COUNT="$(cast call "$MULTISIG" "getTransactionCount()(uint256)" --rpc-url "$RPC_URL")"
EXEC_TX_ID=$(( ${TX_COUNT%% *} - 1 ))
cast send "$MULTISIG" "confirmTransaction(uint256)" "$EXEC_TX_ID" \
    --rpc-url "$RPC_URL" --private-key "$OPERATOR_PRIVATE_KEY" >/dev/null
cast send "$MULTISIG" "executeTransaction(uint256)" "$EXEC_TX_ID" \
    --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" >/dev/null

REGISTERED="$(cast call "$REGISTRY" "authorizedSigners(bytes32)(bool)" "$SIGNER_VK_HASH" \
    --rpc-url "$RPC_URL" 2>/dev/null || echo "unknown")"
echo
echo "== DONE — signer registered on $CHAIN_LABEL (authorizedSigners: $REGISTERED) =="
