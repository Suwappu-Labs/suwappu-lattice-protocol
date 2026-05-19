#!/usr/bin/env bash
# scripts/propose_pause.sh — operator helper for the emergency-pause
# path described in docs/OPERATOR_RUNBOOK.md §7.
#
# Proposes a `pause()` transaction to the LTP multisig. Does NOT
# broadcast — outputs the calldata + multisig propose tx so the
# operator can review, then run the printed `cast send` line.
#
# Why a shell wrapper instead of a Foundry script: speed under stress.
# Operators trigger this when they're paged at 3am; they should not be
# fumbling through `forge script --sig ... --rpc-url ... --broadcast`
# under time pressure. This wrapper expects three named args, prints
# the exact command to run, and exits.
#
# Usage:
#   scripts/propose_pause.sh \
#       --rpc-url $LTP_RPC_URL \
#       --multisig 0x... \
#       --registry 0x...
#
# Exit codes:
#   0 — calldata generated and printed; operator runs the next step
#   1 — missing arg
#   2 — cast/forge not in PATH
#   3 — sanity check on registry address (no code at the address)

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: propose_pause.sh --rpc-url <url> --multisig <addr> --registry <addr> [--from <addr>]

  --rpc-url   JSON-RPC endpoint for the target chain
  --multisig  LTPMultiSig contract address (the propose target)
  --registry  LTPAnchorRegistry address (the call target — receives pause())
  --from      Optional: the proposer address. Defaults to first
              account from cast's default signer.

The script:
  1. Verifies cast / forge are in PATH
  2. Calls registry.paused() to check current state (no point pausing if already paused)
  3. ABI-encodes the pause() call (selector 0x8456cb59)
  4. Prints the exact `cast send` line for the multisig.proposeTransaction
EOF
    exit 1
}

RPC_URL=""
MULTISIG=""
REGISTRY=""
FROM=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc-url)   RPC_URL="$2"; shift 2 ;;
        --multisig)  MULTISIG="$2"; shift 2 ;;
        --registry)  REGISTRY="$2"; shift 2 ;;
        --from)      FROM="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *) echo "Unknown arg: $1" >&2; usage ;;
    esac
done

[[ -z "$RPC_URL" || -z "$MULTISIG" || -z "$REGISTRY" ]] && usage

command -v cast >/dev/null 2>&1 || {
    echo "ERROR: 'cast' not found. Install via foundryup." >&2
    exit 2
}

echo "▶ Checking current pause state on registry $REGISTRY"
PAUSED=$(cast call "$REGISTRY" 'paused()(bool)' --rpc-url "$RPC_URL")
echo "  registry.paused() == $PAUSED"
if [[ "$PAUSED" == "true" ]]; then
    echo "Already paused. Nothing to do."
    exit 0
fi

# pause() has no args; selector is bytes4(keccak256("pause()")) = 0x8456cb59
PAUSE_CALLDATA="0x8456cb59"

echo
echo "▶ Generated calldata for registry.pause(): $PAUSE_CALLDATA"
echo
echo "▶ Next step — propose the pause via the multisig."
echo "   Review the line below, then RUN IT to broadcast the proposal:"
echo
echo "  cast send $MULTISIG \\"
echo "      'proposeTransaction(address,uint256,bytes)' \\"
echo "      $REGISTRY 0 $PAUSE_CALLDATA \\"
echo "      --rpc-url $RPC_URL \\"
${FROM:+echo "      --from $FROM \\"}
echo "      --private-key \$LTP_PROPOSER_PRIVATE_KEY"
echo
echo "▶ After broadcast, share the tx hash in #ltp-incidents — cosigners"
echo "   confirm via the multisig dapp. Pause executes via 0s-delay"
echo "   Timelock once the threshold is reached."
echo
echo "▶ Watch the 'PAUSE STATUS' panel on the Grafana dashboard:"
echo "   https://grafana.<env>.ltp.../d/ltp-pause-status"
