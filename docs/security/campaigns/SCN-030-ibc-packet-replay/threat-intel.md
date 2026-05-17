# SCN-030 — Threat intelligence sources

This scenario covers a **theoretical class** documented in the
Cosmos IBC specification and shared with many real bridge
incidents.

## Primary references

- **Cosmos IBC specification** — ICS-04 (channel & packet
  semantics) covers the sequence-number plus commitment
  design that rejects packet replay.
- **IBC research blogs** — multiple posts on the original IBC
  design discuss the replay-rejection invariant.

## Related real-world incidents

- **Wormhole (Feb 2022)** — broader signature-skip class, with
  a sub-element of cross-chain replay (SCN-001).
- **Several smaller bridges** that lacked per-message ID
  tracking; specifics often disputed in public sources.
- **Polygon Plasma Bridge** had a documented "exit replay"
  bug class in its design phase that was patched before
  exploitation.

## Primary technical analyses

- **Trail of Bits** — surveys of bridge replay-rejection
  designs (cited across multiple audit retrospectives).
- **OpenZeppelin** — guidance on chain-binding in EIP-712
  domain separators.

## Root primitive

A cross-chain message handler that doesn't:
- track per-message IDs and reject duplicates,
- bind the message to a specific destination chain, AND
- enforce sequence monotonicity per sender

…is vulnerable to replay across chains, across time, or across
both. The defense triad is the minimum bar.

## Mapping to LTP

LTP's `_anchor()` implements all three:
- `_anchors[anchorDigest].anchoredAt` for per-message
  rejection
- `targetChainId = block.chainid` for chain binding
- `signerSequences[vk]` for monotonicity

All three are pinned in `SCN_001_Wormhole_AnchorRegistry.t.sol`
(D3, D5, D8) and `SCN_001_Wormhole_AnchorRegistry.invariant.t.sol`
(I2, I3). SCN-030 is the cross-reference document.

## Date of last verification

2026-05-17 — SCN-030 added under R-4.
