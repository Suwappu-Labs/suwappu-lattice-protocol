#!/usr/bin/env python3
"""Tempo payment memo <-> LTP anchor attestation (prototype).

WHAT THIS IS
------------
A Tempo payment carries an optional 32-byte memo. In Tempo's own SDK a human
memo is written as `pad(stringToHex(memo), { size: 32 })` — right-zero-padded
ASCII in a `bytes32` field.

An LTP EntityID is a SHA3-256 digest: exactly 32 bytes. It therefore fits a
Tempo memo *exactly*, with no truncation and no encoding overhead.

That gives a payment a verifiable evidence pointer. The payment settles on
Tempo at Tempo's speed and cost; the supporting document set (invoice, KYC
bundle, contract, delivery proof) is committed to LTP and never touches either
chain. Anyone holding the payment can resolve the memo to an on-chain anchor
and confirm the documents existed, are retrievable, and have not changed.

WHY THE MEMO IS THE RAW HASH, NOT A TAGGED STRUCT
-------------------------------------------------
The obvious alternative is a 4-byte magic prefix plus 28 bytes of digest so a
parser can recognise "this is an LTP memo" without a network call. That trade
is bad: it spends 32 bits of the hash to buy a guess. Collision resistance
drops from 2^128 to 2^112 (birthday bound) — weakening the exact binding the
memo exists to provide.

So the full 32 bytes are used, and discrimination is done by *lookup* rather
than by parsing: ask the registry. `getEntityState(memo) != UNKNOWN` means the
memo is an LTP attestation. A human memo like "INV-2026-0042" is
`0x494e562d...0000` and will simply not resolve. The registry is the oracle;
a magic byte would only be a hint, and a lossy one.

STATUS
------
Prototype. The LTP half is real and runs against a live registry. The Tempo
half is *not* transacted here: Tempo's testnet faucet is passkey-gated, so no
Tempo payment is sent by this script. What it demonstrates is the binding and
the verification path, both of which are chain-agnostic — the memo is a
`bytes32` either way.

See `docs/design-decisions/TEMPO_INTEGRATION.md` for the measured facts about
Tempo, including two RPC behaviours that break naive deploy tooling.

USAGE
-----
    # Derive a memo from a document set (no network)
    python examples/tempo_memo_attestation.py derive --file invoice.json

    # Resolve a memo against a live LTP registry
    python examples/tempo_memo_attestation.py verify \\
        --memo 0x<32-byte-hex> \\
        --rpc https://ethereum-sepolia-rpc.publicnode.com \\
        --registry 0xfd66b836cbe118001156c006e05cfe4432733cd3

Zero third-party dependencies for `verify` (raw JSON-RPC over urllib), so an
integrator can run it without installing the LTP SDK. `derive` needs the SDK.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# --- Registry ABI selectors -------------------------------------------------
# keccak256(signature)[:4]. Hardcoded so `verify` needs no third-party keccak
# (hashlib ships NIST SHA3, which is NOT Ethereum's keccak256 and would yield
# the wrong selector — a subtle way to get a silently empty eth_call result).
#
# Reproduce with Foundry:
#     cast sig 'getEntityState(bytes32)'   ->  0xe490c513
#     cast sig 'entitySigners(bytes32)'    ->  0xc5db24b8
SEL_GET_ENTITY_STATE = "0xe490c513"
SEL_ENTITY_SIGNERS = "0xc5db24b8"

# LTPAnchorRegistry.sol:19-24
ENTITY_STATES = {
    0: "UNKNOWN",
    1: "COMMITTED",
    2: "ANCHORED",
    3: "MATERIALIZED",
    4: "DISPUTED",
    5: "DELETED",
}

MEMO_BYTES = 32


def normalize_memo(memo: str) -> bytes:
    """Accept 0x-prefixed or bare hex; require exactly 32 bytes."""
    raw = memo[2:] if memo.startswith(("0x", "0X")) else memo
    try:
        b = bytes.fromhex(raw)
    except ValueError as exc:
        raise SystemExit(f"memo is not valid hex: {exc}")
    if len(b) != MEMO_BYTES:
        raise SystemExit(
            f"memo must be exactly {MEMO_BYTES} bytes (Tempo bytes32); got {len(b)}"
        )
    return b


def looks_like_text_memo(memo: bytes) -> bool:
    """Heuristic only, used for explaining a miss — never for trust decisions.

    Tempo human memos are right-zero-padded ASCII. A digest effectively never
    is. This is a diagnostic, not a validity check: the registry decides.
    """
    stripped = memo.rstrip(b"\x00")
    if not stripped or stripped == memo:
        return False
    return all(0x20 <= c < 0x7F for c in stripped)


def _rpc(rpc_url: str, method: str, params: list) -> dict:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            # Several public RPC providers reject urllib's default
            # "Python-urllib/3.x" agent with a bare 403. Identify properly.
            "User-Agent": "ltp-tempo-memo-attestation/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"RPC {rpc_url} returned HTTP {exc.code} ({exc.reason}). "
            "Public endpoints rate-limit and sometimes block unknown clients; "
            "try another endpoint."
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"could not reach RPC {rpc_url}: {exc.reason}") from exc


def _eth_call(rpc_url: str, to: str, data: str) -> str:
    out = _rpc(rpc_url, "eth_call", [{"to": to, "data": data}, "latest"])
    if "error" in out:
        raise SystemExit(f"eth_call failed: {out['error']}")
    return out["result"]


def verify_memo(memo_hex: str, rpc_url: str, registry: str) -> dict:
    """Resolve a Tempo memo against an LTP registry.

    Returns a dict describing what the chain says. Never raises on a memo that
    simply is not an LTP attestation — that is a legitimate answer.
    """
    memo = normalize_memo(memo_hex)
    arg = memo.hex()

    sel_state = SEL_GET_ENTITY_STATE
    sel_signer = SEL_ENTITY_SIGNERS

    state_raw = _eth_call(rpc_url, registry, sel_state + arg)
    state = int(state_raw, 16) if state_raw not in ("0x", "") else 0

    result = {
        "memo": "0x" + arg,
        "registry": registry,
        "entity_state_code": state,
        "entity_state": ENTITY_STATES.get(state, f"UNRECOGNISED({state})"),
        "is_ltp_attestation": state != 0,
    }

    if state == 0:
        result["explanation"] = (
            "This memo does not resolve to an entity in this registry. It is "
            "either a plain payment memo, an attestation anchored on a "
            "different leg, or not an LTP memo at all."
        )
        if looks_like_text_memo(memo):
            text = memo.rstrip(b"\x00").decode("ascii", "replace")
            result["looks_like_text_memo"] = text
            result["explanation"] += (
                f" It decodes as the ASCII text {text!r}, which is the shape of "
                "a human Tempo memo."
            )
        return result

    signer_raw = _eth_call(rpc_url, registry, sel_signer + arg)
    signer = "0x" + signer_raw[2:].rjust(64, "0")[-64:]
    result["signer_vk_hash"] = signer
    result["explanation"] = (
        f"Anchored in this registry under signer {signer}. The payment's "
        "supporting documents are committed to LTP and retrievable from the "
        "commitment network; this proves the commitment exists on-chain and "
        "binds it to a registered signer."
    )
    return result


def derive_memo(content: bytes, shape: str) -> dict:
    """Commit a document set locally and return the Tempo memo for it.

    Uses the real SDK identity function (Entity.compute_id, whitepaper 1.2):
    EntityID = SHA3-256(content || shape || timestamp || sender_vk).
    """
    sys.path.insert(0, str(PROJECT_ROOT))
    from src.ltp.dual_lane.hashing import spec_hash_bytes  # noqa: E402
    from src.ltp.entity import Entity  # noqa: E402
    from src.ltp.keypair import KeyPair  # noqa: E402

    kp = KeyPair.generate("tempo-memo-demo")
    entity = Entity(content=content, shape=shape)
    ts = time.time()

    # EntityID is an algorithm-prefixed string, e.g.
    #   "sha3-256:2d15816987ce0eb1..."
    # The on-chain bytes32 is NOT the digest after that prefix. It is
    # SHA3-256 over the EntityID *string*, prefix included — the convention
    # set by src/ltp/bridge/live.py:247:
    #     entity_id_hash = spec_hash_bytes(commitment.entity_id.encode())
    # Matching it exactly is what makes the memo resolve on-chain; deriving
    # the "obvious" raw digest instead produces a memo that silently never
    # resolves against any registry.
    entity_id = entity.compute_id(kp.vk, ts)
    memo = spec_hash_bytes(entity_id.encode())

    if len(memo) != MEMO_BYTES:
        raise SystemExit(
            f"entity_id_hash is {len(memo)} bytes; a Tempo memo is {MEMO_BYTES}. "
            "The fit is exact by construction — this indicates a hash change."
        )
    return {
        "entity_id": entity_id,
        "entity_id_hash": "0x" + memo.hex(),
        "tempo_memo": "0x" + memo.hex(),
        "shape": shape,
        "content_bytes": len(content),
        "timestamp": ts,
        "note": (
            "Pass tempo_memo as the `memo` argument of a TIP-20 transfer. It is "
            "already bytes32; do NOT run it through stringToHex/pad, which is "
            "for human text memos and would double-encode it."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("derive", help="commit a document set, print its Tempo memo")
    d.add_argument("--file", type=Path, help="document to commit")
    d.add_argument("--text", help="inline content instead of --file")
    d.add_argument("--shape", default="application/json", help="LTP shape")

    v = sub.add_parser("verify", help="resolve a memo against a live registry")
    v.add_argument("--memo", required=True, help="32-byte memo, 0x-prefixed")
    v.add_argument("--rpc", required=True, help="JSON-RPC endpoint")
    v.add_argument("--registry", required=True, help="LTPAnchorRegistry proxy")

    args = ap.parse_args()

    if args.cmd == "derive":
        if args.file:
            content = args.file.read_bytes()
        elif args.text:
            content = args.text.encode()
        else:
            raise SystemExit("provide --file or --text")
        print(json.dumps(derive_memo(content, args.shape), indent=2))
    else:
        print(json.dumps(verify_memo(args.memo, args.rpc, args.registry), indent=2))


if __name__ == "__main__":
    main()
