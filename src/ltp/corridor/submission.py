"""Bridge a `CorridorAttestation` into a suwappu-db `StateAnchor`.

The 7-of-9 corridor attestation produces a quorum signature over an
`(source_chain, source_height, state_root, …)` payload. The suwappu-db anchor
registry consumes a different but overlapping struct keyed to a single
target chain. This module gives LTP a one-call helper that:

1. Extracts the `(chain_id, height, state_root, parent)` tuple from a
   corridor attestation that targets a specific chain.
2. Computes the appropriate MAC (`BLAKE3-keyed` Rust canonical, or
   `Keccak256` Solidity phase-1 placeholder).
3. Returns a `StateAnchor` ready to submit to either the Rust
   `suwappudb-bridge` dispatcher or the Solidity `LTPAnchorRegistry.acceptAnchor`.

The corridor signature itself does not live inside the `StateAnchor` —
the Solidity contract takes a separate signature blob recovered through
ECDSA (or, post-S11, the hybrid ECDSA + ML-DSA-65 scheme). Signature
production is owned by the chain-key custody surface, not by this helper.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import CorridorAttestation
from .state_anchor import (
    GENESIS_PARENT,
    AuthScheme,
    StateAnchor,
    compute_mac_blake3,
    compute_mac_keccak256,
    hash_anchor_blake3,
    hash_anchor_keccak256,
)


class CorridorAnchorError(ValueError):
    """Raised when an attestation cannot be projected onto a state anchor."""


@dataclass(frozen=True)
class CorridorAnchorBuild:
    """Result of building a state anchor from a corridor attestation."""

    anchor: StateAnchor
    canonical_hash: bytes  # Use this as `parent` for the next anchor.


def build_state_anchor_blake3(
    attestation: CorridorAttestation,
    chain_key: bytes,
    parent: bytes = GENESIS_PARENT,
    auth_scheme: AuthScheme = AuthScheme.BLAKE3_MAC,
) -> CorridorAnchorBuild:
    """Project a corridor attestation onto a suwappu-db `StateAnchor` using the
    Rust-canonical BLAKE3-keyed MAC.

    `chain_key` is the 32-byte per-chain authentication key registered with
    the anchor registry (`setChainKey` on the Solidity side). The
    `target_chain` field of the attestation payload is used as the
    `chain_id` of the resulting anchor.
    """
    payload = attestation.payload
    if payload.target_chain >= (1 << 32):
        raise CorridorAnchorError(
            f"target_chain {payload.target_chain} exceeds u32; "
            f"the suwappu-db anchor registry keys chains by u32"
        )
    chain_id = payload.target_chain
    mac = compute_mac_blake3(
        chain_id=chain_id,
        height=payload.source_height,
        state_root=payload.state_root,
        parent=parent,
        key=chain_key,
    )
    anchor = StateAnchor(
        chain_id=chain_id,
        height=payload.source_height,
        state_root=payload.state_root,
        parent=parent,
        mac=mac,
        auth_scheme=auth_scheme,
    )
    return CorridorAnchorBuild(
        anchor=anchor,
        canonical_hash=hash_anchor_blake3(anchor),
    )


def build_state_anchor_keccak256(
    attestation: CorridorAttestation,
    chain_key: bytes,
    parent: bytes = GENESIS_PARENT,
    auth_scheme: AuthScheme = AuthScheme.BLAKE3_MAC,
) -> CorridorAnchorBuild:
    """Same as `build_state_anchor_blake3`, but using the Solidity phase-1
    Keccak256 placeholder MAC. Use this when the on-chain `LTPAnchorRegistry`
    has not yet swapped in the BLAKE3 precompile (pre-suwappu-db sprint S11).
    """
    payload = attestation.payload
    if payload.target_chain >= (1 << 32):
        raise CorridorAnchorError(f"target_chain {payload.target_chain} exceeds u32")
    chain_id = payload.target_chain
    mac = compute_mac_keccak256(
        chain_id=chain_id,
        height=payload.source_height,
        state_root=payload.state_root,
        parent=parent,
        key=chain_key,
    )
    anchor = StateAnchor(
        chain_id=chain_id,
        height=payload.source_height,
        state_root=payload.state_root,
        parent=parent,
        mac=mac,
        auth_scheme=auth_scheme,
    )
    return CorridorAnchorBuild(
        anchor=anchor,
        canonical_hash=hash_anchor_keccak256(anchor),
    )
