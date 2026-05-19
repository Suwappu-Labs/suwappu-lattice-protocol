"""Per-chain state anchor — mirror of `gsx-db/crates/gsxdb-bridge/src/anchor/types.rs`
and the Solidity surface `gsx-db/contracts/src/LTPAnchorRegistry.sol`.

The gsx-db anchor is distinct from `gsx-lattice-protocol/contracts/src/LTPAnchorRegistry.sol`:

| Surface | Schema | Scope |
|---|---|---|
| `gsx-db` LTPAnchorRegistry | `(chainId, height, stateRoot, parent, mac)` | per-chain state-root anchor |
| `gsx-lattice-protocol` LTPAnchorRegistry | per-entity commitment anchor (`anchorDigest`, `entityIdHash`, ...) | LTP commitment log |

This module gives LTP a Python implementation of the **gsx-db** anchor so an
LTP corridor witness can construct, hash, and verify the same anchor bytes
that gsx-db's Rust crate and the Solidity contract operate on.

Two MAC backends are provided:

- `compute_mac_blake3` — Rust-canonical, BLAKE3-keyed (matches
  `gsxdb-bridge::compute_mac`).
- `compute_mac_keccak256` — Solidity phase-1 placeholder (matches the
  `computeMac` function in `gsx-db/contracts/src/LTPAnchorRegistry.sol`).
  Replaced by a BLAKE3 precompile in gsx-db sprint S11.

Likewise `hash_anchor_blake3` mirrors the Rust hash, `hash_anchor_keccak256`
mirrors the Solidity hash. The Rust hash also folds in `auth_scheme`; the
Solidity hash does not. Use the Rust variant for cross-Rust parity and the
Solidity variant when checking on-chain calls today.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum

try:  # pragma: no cover — optional dependency
    import blake3 as _blake3

    _blake3_available = True
except ImportError:
    _blake3 = None
    _blake3_available = False


GENESIS_PARENT: bytes = bytes(32)


class AuthScheme(IntEnum):
    """Authentication mode carried by an anchor.

    Wire encoding via the underlying `u8` discriminant — values are pinned
    to match `gsx-db/crates/gsxdb-bridge/src/anchor/types.rs::AuthScheme`.
    """

    BLAKE3_MAC = 0
    SP1_ZK_PROOF = 1
    ECDSA_SECP256K1 = 2
    ML_DSA_65_HYBRID = 3


@dataclass(frozen=True)
class StateAnchor:
    """Per-chain anchor: `(chain_id, height, state_root, parent, mac, auth_scheme)`."""

    chain_id: int  # u32
    height: int  # u64
    state_root: bytes  # 32 bytes
    parent: bytes  # 32 bytes
    mac: bytes  # 32 bytes
    auth_scheme: AuthScheme = AuthScheme.BLAKE3_MAC

    def __post_init__(self) -> None:
        if not 0 <= self.chain_id < (1 << 32):
            raise ValueError("chain_id must fit in u32")
        if not 0 <= self.height < (1 << 64):
            raise ValueError("height must fit in u64")
        for name in ("state_root", "parent", "mac"):
            if len(getattr(self, name)) != 32:
                raise ValueError(f"{name} must be 32 bytes")


def _require_blake3() -> None:
    if not _blake3_available:
        raise RuntimeError(
            "blake3 library not installed; install with `pip install blake3` "
            "to use the Rust-canonical anchor surface"
        )


def compute_mac_blake3(
    chain_id: int,
    height: int,
    state_root: bytes,
    parent: bytes,
    key: bytes,
) -> bytes:
    """BLAKE3-keyed MAC matching `gsxdb-bridge::compute_mac`."""
    if len(key) != 32:
        raise ValueError("MAC key must be 32 bytes")
    if len(state_root) != 32 or len(parent) != 32:
        raise ValueError("state_root and parent must be 32 bytes")
    _require_blake3()
    h = _blake3.blake3(key=key)
    h.update(b"GSXDB-ANCHOR/MAC")
    h.update(chain_id.to_bytes(4, "big"))
    h.update(height.to_bytes(8, "big"))
    h.update(state_root)
    h.update(parent)
    return h.digest()


def compute_mac_keccak256(
    chain_id: int,
    height: int,
    state_root: bytes,
    parent: bytes,
    key: bytes,
) -> bytes:
    """Keccak256 placeholder MAC matching the Solidity contract.

    Mirrors `LTPAnchorRegistry.computeMac` byte-for-byte:
    `keccak256("GSXDB-ANCHOR/MAC" || key || chainId || height || stateRoot || parent)`
    """
    if len(key) != 32:
        raise ValueError("MAC key must be 32 bytes")
    if len(state_root) != 32 or len(parent) != 32:
        raise ValueError("state_root and parent must be 32 bytes")
    blob = (
        b"GSXDB-ANCHOR/MAC"
        + key
        + chain_id.to_bytes(4, "big")
        + height.to_bytes(8, "big")
        + state_root
        + parent
    )
    return _keccak256(blob)


def hash_anchor_blake3(anchor: StateAnchor) -> bytes:
    """Rust-canonical anchor hash — `gsxdb-bridge::Anchor::hash`."""
    _require_blake3()
    h = _blake3.blake3()
    h.update(b"GSXDB-ANCHOR/HASH")
    h.update(anchor.chain_id.to_bytes(4, "big"))
    h.update(anchor.height.to_bytes(8, "big"))
    h.update(anchor.state_root)
    h.update(anchor.parent)
    h.update(anchor.mac)
    h.update(bytes([int(anchor.auth_scheme)]))
    return h.digest()


def hash_anchor_keccak256(anchor: StateAnchor) -> bytes:
    """Solidity phase-1 anchor hash — `LTPAnchorRegistry.hashAnchor`.

    Note: the Solidity version does NOT fold in `auth_scheme`, so anchors
    that differ only in `auth_scheme` will hash to the same value here.
    The Rust variant disambiguates them; the gsx-db S11 cross-parity sprint
    will reconcile the two encodings.
    """
    blob = (
        b"GSXDB-ANCHOR/HASH"
        + anchor.chain_id.to_bytes(4, "big")
        + anchor.height.to_bytes(8, "big")
        + anchor.state_root
        + anchor.parent
        + anchor.mac
    )
    return _keccak256(blob)


def _keccak256(data: bytes) -> bytes:
    # hashlib has built-in keccak via the `_sha3` extension under the name
    # "sha3_256"; the actual Keccak-256 used by Ethereum is exposed by
    # `pysha3`/`pycryptodome`. Prefer eth_utils' `keccak` if available.
    try:
        from eth_utils import keccak  # type: ignore

        return keccak(data)
    except ImportError:
        pass
    try:
        from Crypto.Hash import keccak as _keccak_mod  # type: ignore

        k = _keccak_mod.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        pass
    # Fallback: SHA3-256 (FIPS 202) is NOT Keccak-256 — these differ in
    # padding. Raise so callers don't get silently-wrong digests.
    raise RuntimeError("Keccak-256 backend not available; install `eth-utils` or `pycryptodome`")
