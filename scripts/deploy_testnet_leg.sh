#!/usr/bin/env bash
# Deploy a full LTP leg — registry + governance + bridge pair — to one EVM testnet.
#
# Usage:
#   scripts/deploy_testnet_leg.sh config/deploy/<chain>.env
#
# Runs, in order:
#   1. contracts/script/DeployTestnet.s.sol   (LTPAnchorRegistry impl + ERC1967 proxy,
#                                              LTPMultiSig 2-of-2, TimelockController 60s,
#                                              admin handed to the timelock)
#   2. contracts/script/DeployBridge.s.sol    (OptimisticBridgeChallenge + ZKBridgeVerifier,
#                                              wired together, admin handed to the timelock)
#
# Then writes deployments/<CHAIN_LABEL>.json and prints the markdown snippet
# for docs/DEPLOYED_CONTRACTS.md. Signer registration is a separate step:
# scripts/register_signer_leg.sh (the multisig -> timelock governance path).
#
# Requires: forge + cast (foundry), jq. The contracts/lib submodule deps must be
# installed (forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$REPO_ROOT/contracts"

die() { echo "ERROR: $*" >&2; exit 1; }

ENV_FILE="${1:-}"
[ -n "$ENV_FILE" ] || die "usage: $0 config/deploy/<chain>.env"
[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

for v in CHAIN_LABEL CHAIN_ID RPC_URL DEPLOYER_PRIVATE_KEY SUWAPPU_OPERATOR_ADDRESS; do
    [ -n "${!v:-}" ] || die "$v is not set in $ENV_FILE"
    case "${!v}" in *FILL_ME*) die "$v still has the placeholder value in $ENV_FILE";; esac
done

command -v forge >/dev/null || die "forge not found — install foundry"
command -v cast  >/dev/null || die "cast not found — install foundry"
command -v jq    >/dev/null || die "jq not found"

# ---- Preflight ----
echo "== Preflight ($CHAIN_LABEL) =="
ACTUAL_CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL")"
[ "$ACTUAL_CHAIN_ID" = "$CHAIN_ID" ] || \
    die "RPC $RPC_URL reports chain ID $ACTUAL_CHAIN_ID, expected $CHAIN_ID"

DEPLOYER_ADDRESS="$(cast wallet address --private-key "$DEPLOYER_PRIVATE_KEY")"
BALANCE_WEI="$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL")"
echo "Deployer: $DEPLOYER_ADDRESS"
echo "Balance:  $(cast from-wei "$BALANCE_WEI") ETH"

MIN_WEI=5000000000000000   # 0.005 ETH
if [ "$(python3 -c "print(1 if int('$BALANCE_WEI') < $MIN_WEI else 0)")" = "1" ] \
    && [ "${FORCE_DEPLOY:-}" != "true" ]; then
    die "deployer balance below 0.005 ETH — fund it or set FORCE_DEPLOY=true"
fi

[ "$DEPLOYER_ADDRESS" != "$SUWAPPU_OPERATOR_ADDRESS" ] || \
    die "SUWAPPU_OPERATOR_ADDRESS must differ from the deployer (2-of-2 multisig needs two owners)"

# ---- 1. Registry + governance ----
echo
echo "== Deploying registry + governance =="
(
    cd "$CONTRACTS_DIR"
    SUWAPPU_OPERATOR_ADDRESS="$SUWAPPU_OPERATOR_ADDRESS" \
    forge script script/DeployTestnet.s.sol:DeployTestnet \
        --rpc-url "$RPC_URL" \
        --private-key "$DEPLOYER_PRIVATE_KEY" \
        --broadcast -vv
)

REG_BROADCAST="$CONTRACTS_DIR/broadcast/DeployTestnet.s.sol/$CHAIN_ID/run-latest.json"
[ -f "$REG_BROADCAST" ] || die "broadcast file missing: $REG_BROADCAST"

addr_of() { # addr_of <broadcast.json> <contractName>
    jq -r --arg n "$2" \
        '[.transactions[] | select(.transactionType=="CREATE" and .contractName==$n)][0].contractAddress // empty' \
        "$1"
}

IMPLEMENTATION="$(addr_of "$REG_BROADCAST" LTPAnchorRegistry)"
PROXY="$(addr_of "$REG_BROADCAST" ERC1967Proxy)"
MULTISIG="$(addr_of "$REG_BROADCAST" LTPMultiSig)"
TIMELOCK="$(addr_of "$REG_BROADCAST" TimelockController)"
for v in IMPLEMENTATION PROXY MULTISIG TIMELOCK; do
    [ -n "${!v}" ] || die "could not extract $v from $REG_BROADCAST"
done

REGISTRY_BLOCK="$(python3 -c "import json,sys; r=json.load(open('$REG_BROADCAST'))['receipts']; print(min(int(x['blockNumber'],16) for x in r) if r else '')")"

# ---- 2. Bridge pair ----
echo
echo "== Deploying bridge pair =="
(
    cd "$CONTRACTS_DIR"
    BRIDGE_TIMELOCK_ADMIN="$TIMELOCK" \
    BRIDGE_CHALLENGE_PERIOD="${BRIDGE_CHALLENGE_PERIOD:-3600}" \
    BRIDGE_MIN_OPERATOR_BOND="${BRIDGE_MIN_OPERATOR_BOND:-0}" \
    BRIDGE_MIN_CHALLENGER_BOND="${BRIDGE_MIN_CHALLENGER_BOND:-0}" \
    BRIDGE_ZK_MODE="${BRIDGE_ZK_MODE:-0}" \
    forge script script/DeployBridge.s.sol:DeployBridge \
        --rpc-url "$RPC_URL" \
        --private-key "$DEPLOYER_PRIVATE_KEY" \
        --broadcast -vv
)

BRIDGE_BROADCAST="$CONTRACTS_DIR/broadcast/DeployBridge.s.sol/$CHAIN_ID/run-latest.json"
[ -f "$BRIDGE_BROADCAST" ] || die "broadcast file missing: $BRIDGE_BROADCAST"

CHALLENGE="$(addr_of "$BRIDGE_BROADCAST" OptimisticBridgeChallenge)"
ZK_VERIFIER="$(addr_of "$BRIDGE_BROADCAST" ZKBridgeVerifier)"
for v in CHALLENGE ZK_VERIFIER; do
    [ -n "${!v}" ] || die "could not extract $v from $BRIDGE_BROADCAST"
done
BRIDGE_BLOCK="$(python3 -c "import json,sys; r=json.load(open('$BRIDGE_BROADCAST'))['receipts']; print(min(int(x['blockNumber'],16) for x in r) if r else '')")"

# ---- 3. Post-deploy verification ----
echo
echo "== Verifying =="
VERSION="$(cast call "$PROXY" "version()(uint256)" --rpc-url "$RPC_URL")"
ADMIN="$(cast call "$PROXY" "admin()(address)" --rpc-url "$RPC_URL")"
echo "registry.version() = $VERSION"
echo "registry.admin()   = $ADMIN (expected timelock $TIMELOCK)"
[ "$(echo "$ADMIN" | tr '[:upper:]' '[:lower:]')" = "$(echo "$TIMELOCK" | tr '[:upper:]' '[:lower:]')" ] || \
    die "registry admin is not the timelock — investigate before using this leg"

# ---- 4. Record ----
mkdir -p "$REPO_ROOT/deployments"
OUT="$REPO_ROOT/deployments/$CHAIN_LABEL.json"
jq -n \
    --arg chain_label "$CHAIN_LABEL" \
    --argjson chain_id "$CHAIN_ID" \
    --arg rpc_url "$RPC_URL" \
    --arg explorer_url "${EXPLORER_URL:-}" \
    --arg deployer "$DEPLOYER_ADDRESS" \
    --arg operator "$SUWAPPU_OPERATOR_ADDRESS" \
    --arg implementation "$IMPLEMENTATION" \
    --arg proxy "$PROXY" \
    --arg multisig "$MULTISIG" \
    --arg timelock "$TIMELOCK" \
    --arg challenge "$CHALLENGE" \
    --arg zk_verifier "$ZK_VERIFIER" \
    --arg registry_block "$REGISTRY_BLOCK" \
    --arg bridge_block "$BRIDGE_BLOCK" \
    --arg deployed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        chain_label: $chain_label,
        chain_id: $chain_id,
        rpc_url: $rpc_url,
        explorer_url: $explorer_url,
        deployer: $deployer,
        multisig_operator: $operator,
        contracts: {
            LTPAnchorRegistry_implementation: $implementation,
            ERC1967Proxy: $proxy,
            LTPMultiSig: $multisig,
            TimelockController: $timelock,
            OptimisticBridgeChallenge: $challenge,
            ZKBridgeVerifier: $zk_verifier
        },
        blocks: {registry: $registry_block, bridge: $bridge_block},
        deployed_at: $deployed_at
    }' > "$OUT"
echo "Wrote $OUT"

# ---- 5. Summary ----
cat <<EOF

== Deployment complete: $CHAIN_LABEL (chain ID $CHAIN_ID) ==

Markdown for docs/DEPLOYED_CONTRACTS.md (adding a leg needs a plan under docs/plans/ —
see docs/plans/2026-08-24-testnet-cross-chain-relegging.md):

## $CHAIN_LABEL — Chain ID \`$CHAIN_ID\`

### Registry (deployed block ${REGISTRY_BLOCK:-?})

| Contract | Address |
|---|---|
| LTPAnchorRegistry (Implementation) | \`$IMPLEMENTATION\` |
| ERC1967Proxy | \`$PROXY\` |
| LTPMultiSig (2-of-2) | \`$MULTISIG\` |
| TimelockController (60s delay) | \`$TIMELOCK\` |

### Bridge (deployed block ${BRIDGE_BLOCK:-?})

| Contract | Address |
|---|---|
| OptimisticBridgeChallenge | \`$CHALLENGE\` |
| ZKBridgeVerifier | \`$ZK_VERIFIER\` |

Next steps:
  1. Register the bridge-operator signer:  scripts/register_signer_leg.sh $ENV_FILE
  2. Smoke-test a transfer:                scripts/bridge_live.py (see --l1-prefix/--l2-prefix)
EOF
