#!/usr/bin/env bash
# scripts/propose_pause.sh — operator helper for the emergency-pause
# path described in docs/OPERATOR_RUNBOOK.md §7 and the v7 testnet
# rehearsal in docs/runbooks/v7-upgrade-testnet.md.
#
# Generates the multisig calldata for pausing the registry through
# the Timelock governance path. Does NOT broadcast — outputs the
# exact `cast send` lines the operator runs in sequence:
#
#   (a) multisig.submitTransaction(timelock, 0, timelock.schedule(...))
#   (b) cosigner: multisig.confirmTransaction(<scheduleTxId>)
#   (c) any owner: multisig.executeTransaction(<scheduleTxId>)
#       → timelock starts its delay countdown
#   (d) wait $TIMELOCK_DELAY seconds
#   (e) multisig.submitTransaction(timelock, 0, timelock.execute(...))
#   (f) cosigner: multisig.confirmTransaction(<executeTxId>)
#   (g) any owner: multisig.executeTransaction(<executeTxId>)
#       → timelock.execute → registry.pause() lands; paused == true
#
# Why a shell wrapper instead of a Foundry script: speed under stress.
# Operators trigger this when they're paged at 3am; they should not be
# fumbling through `forge script --sig ... --rpc-url ... --broadcast`
# under time pressure. This wrapper expects four named args, prints
# the full sequence of commands to run, and exits.
#
# Why the timelock detour: `LTPAnchorRegistry.pause()` is `onlyAdmin`
# (contracts/src/LTPAnchorRegistry.sol) and the registry admin in the
# deployed governance model is the TimelockController, not the
# multisig. A direct multisig → registry.pause() reverts NotAdmin.
#
# Usage:
#   scripts/propose_pause.sh \
#       --rpc-url   $LTP_RPC_URL \
#       --multisig  0x... \
#       --registry  0x... \
#       --timelock  0x...
#
# Exit codes:
#   0 — calldata generated and printed; operator runs the next step
#   1 — missing arg
#   2 — cast/forge not in PATH
#   3 — registry already paused (drill is a no-op)

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: propose_pause.sh --rpc-url <url> --multisig <addr> --registry <addr> --timelock <addr> [--from <addr>]

  --rpc-url   JSON-RPC endpoint for the target chain
  --multisig  LTPMultiSig contract address (the propose target)
  --registry  LTPAnchorRegistry address (final call target — receives pause())
  --timelock  TimelockController address (the registry's admin)
  --from      Optional: the proposer address. Defaults to first
              account from cast's default signer.

The script:
  1. Verifies cast is in PATH
  2. Calls registry.paused() to check current state (no point pausing if already paused)
  3. Queries the timelock's min delay
  4. ABI-encodes the pause() calldata (selector 0x8456cb59)
  5. Wraps it in timelock.schedule(...) and timelock.execute(...) calldata
  6. Prints the two `cast send` lines (schedule submit + execute submit)
     and the cosigner/execute steps in between.

Operator env vars the printed commands use:
  LTP_PROPOSER_PRIVATE_KEY  — proposer key for the multisig.submit* calls
EOF
    exit 1
}

RPC_URL=""
MULTISIG=""
REGISTRY=""
TIMELOCK=""
FROM=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpc-url)   RPC_URL="$2"; shift 2 ;;
        --multisig)  MULTISIG="$2"; shift 2 ;;
        --registry)  REGISTRY="$2"; shift 2 ;;
        --timelock)  TIMELOCK="$2"; shift 2 ;;
        --from)      FROM="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *) echo "Unknown arg: $1" >&2; usage ;;
    esac
done

[[ -z "$RPC_URL" || -z "$MULTISIG" || -z "$REGISTRY" || -z "$TIMELOCK" ]] && usage

command -v cast >/dev/null 2>&1 || {
    echo "ERROR: 'cast' not found. Install via foundryup." >&2
    exit 2
}

echo "▶ Checking current pause state on registry $REGISTRY"
PAUSED=$(cast call "$REGISTRY" 'paused()(bool)' --rpc-url "$RPC_URL")
echo "  registry.paused() == $PAUSED"
if [[ "$PAUSED" == "true" ]]; then
    echo "Already paused. Nothing to do."
    exit 3
fi

echo "▶ Querying timelock min delay on $TIMELOCK"
TIMELOCK_DELAY=$(cast call "$TIMELOCK" 'getMinDelay()(uint256)' --rpc-url "$RPC_URL")
# cast prints decimals with possible scientific notation; normalize.
TIMELOCK_DELAY="${TIMELOCK_DELAY%% *}"
echo "  timelock.getMinDelay() == $TIMELOCK_DELAY seconds"

# pause() selector is bytes4(keccak256("pause()")) = 0x8456cb59
PAUSE_CALLDATA="0x8456cb59"

# Build timelock.schedule(target, value, payload, predecessor, salt, delay)
# and timelock.execute(target, value, payload, predecessor, salt).
# predecessor = bytes32(0), salt = bytes32(0) per UpgradeV7.s.sol convention.
SCHEDULE_CALLDATA=$(cast calldata \
    'schedule(address,uint256,bytes,bytes32,bytes32,uint256)' \
    "$REGISTRY" 0 "$PAUSE_CALLDATA" \
    0x0000000000000000000000000000000000000000000000000000000000000000 \
    0x0000000000000000000000000000000000000000000000000000000000000000 \
    "$TIMELOCK_DELAY")

EXECUTE_CALLDATA=$(cast calldata \
    'execute(address,uint256,bytes,bytes32,bytes32)' \
    "$REGISTRY" 0 "$PAUSE_CALLDATA" \
    0x0000000000000000000000000000000000000000000000000000000000000000 \
    0x0000000000000000000000000000000000000000000000000000000000000000)

echo
echo "▶ Generated calldata for registry.pause() (via timelock):"
echo "  pause() selector:    $PAUSE_CALLDATA"
echo "  schedule calldata:   $SCHEDULE_CALLDATA"
echo "  execute calldata:    $EXECUTE_CALLDATA"
echo
echo "==================================================================="
echo "STEP A — Proposer submits the timelock-schedule tx to the multisig."
echo "         (Captures schedule txId; submitter auto-confirms.)"
echo "==================================================================="
echo
echo "  cast send $MULTISIG \\"
echo "      'submitTransaction(address,uint256,bytes)' \\"
echo "      $TIMELOCK 0 $SCHEDULE_CALLDATA \\"
echo "      --rpc-url $RPC_URL \\"
${FROM:+echo "      --from $FROM \\"}
echo "      --private-key \$LTP_PROPOSER_PRIVATE_KEY"
echo
echo "==================================================================="
echo "STEP B — Cosigner confirms <scheduleTxId> (from STEP A receipt)."
echo "==================================================================="
echo
echo "  cast send $MULTISIG \\"
echo "      'confirmTransaction(uint256)' <scheduleTxId> \\"
echo "      --rpc-url $RPC_URL --private-key \$LTP_COSIGNER_PRIVATE_KEY"
echo
echo "==================================================================="
echo "STEP C — Any owner executes <scheduleTxId> (fires timelock.schedule)."
echo "==================================================================="
echo
echo "  cast send $MULTISIG \\"
echo "      'executeTransaction(uint256)' <scheduleTxId> \\"
echo "      --rpc-url $RPC_URL --private-key \$LTP_OWNER_PRIVATE_KEY"
echo
echo "==================================================================="
echo "STEP D — Wait $TIMELOCK_DELAY seconds for the timelock delay."
echo "==================================================================="
echo
echo "  sleep $TIMELOCK_DELAY"
echo
echo "==================================================================="
echo "STEP E — Proposer submits the timelock-execute tx to the multisig."
echo "==================================================================="
echo
echo "  cast send $MULTISIG \\"
echo "      'submitTransaction(address,uint256,bytes)' \\"
echo "      $TIMELOCK 0 $EXECUTE_CALLDATA \\"
echo "      --rpc-url $RPC_URL \\"
${FROM:+echo "      --from $FROM \\"}
echo "      --private-key \$LTP_PROPOSER_PRIVATE_KEY"
echo
echo "==================================================================="
echo "STEP F — Cosigner confirms <executeTxId> (from STEP E receipt)."
echo "==================================================================="
echo
echo "  cast send $MULTISIG \\"
echo "      'confirmTransaction(uint256)' <executeTxId> \\"
echo "      --rpc-url $RPC_URL --private-key \$LTP_COSIGNER_PRIVATE_KEY"
echo
echo "==================================================================="
echo "STEP G — Any owner executes <executeTxId>"
echo "         → timelock.execute → registry.pause() lands."
echo "==================================================================="
echo
echo "  cast send $MULTISIG \\"
echo "      'executeTransaction(uint256)' <executeTxId> \\"
echo "      --rpc-url $RPC_URL --private-key \$LTP_OWNER_PRIVATE_KEY"
echo
echo "==================================================================="
echo "VERIFY — Confirm paused == true."
echo "==================================================================="
echo
echo "  cast call $REGISTRY 'paused()(bool)' --rpc-url $RPC_URL"
echo
echo "▶ After broadcast, share the tx hash in #ltp-incidents — cosigners"
echo "   confirm via the multisig dapp or by re-running STEP B/STEP F."
echo
echo "▶ Watch the 'PAUSE STATUS' panel on the Grafana dashboard:"
echo "   https://grafana.<env>.ltp.../d/ltp-pause-status"
