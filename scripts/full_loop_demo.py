#!/usr/bin/env python3
"""
Full native-PQ bridge loop demo.

Connects a live gsx-dag devnet (ML-DSA-65 attestations) to the suwappu-node
EVM via the GsxDagQuorumHeaderOracle + GsxDagValidatorRegistry contracts,
proving a real validator-quorum header attestation finalizes on the EVM.

Legs:
  1. Verify all 4 devnet validators are responding.
  2. Start suwappu-node (fresh process, port 8545).
  3. Deploy registry (nonce 0) + oracle (nonce 1) so oracle lands at
     0xe7f1725e7734ce288f8367e1bb143e90bb3f0512.
  4. bootstrapEpoch0 with the 4 genesis ML-DSA pubkeys.
  5. Poll validators until >= 3 attest the SAME (block_number, state_root).
  6. submitHeader via the relayer.
  7. Assert receipt status == 1 and oracle.headerStateRoot readback matches.
"""

from __future__ import annotations

import logging
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = Path("/Users/toma/gsx")
REVM_ROOT = REPO_ROOT / "gsx-revm"
FIXTURES = REVM_ROOT / "crates/suwappu-revm/tests/fixtures"
SUWAPPU_NODE_BIN = REVM_ROOT / "target/release/suwappu-node"
GENESIS_TOML = REPO_ROOT / "gsx-dag/target/devnet-real/genesis.toml"

# ── Constants ────────────────────────────────────────────────────────────────

VALIDATOR_URLS = [
    "http://127.0.0.1:9092",
    "http://127.0.0.1:9192",
    "http://127.0.0.1:9292",
    "http://127.0.0.1:9392",
]

NODE_PORT = 8545
NODE_URL = f"http://127.0.0.1:{NODE_PORT}"
CHAIN_ID = 31337

# Standard Anvil account 0 — prefunded in suwappu-node with u128::MAX wei.
ACCOUNT_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ACCOUNT_0_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# networkId the devnet validators sign over (from genesis.toml / RPC oracle field).
NETWORK_ID_HEX = "0xff431b3851ff00be6b5a4bd9b67e7d4118300693937865dfe75847dfd7cdd78a"
NETWORK_ID = int(NETWORK_ID_HEX, 16)

# The oracle address validators signed over — must match after deploy.
EXPECTED_ORACLE = "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512"

GAS_LIMIT = 25_000_000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("full_loop_demo")


# ── Genesis pubkey loader ─────────────────────────────────────────────────────


def load_genesis_pubkeys() -> list[bytes]:
    """Load ML-DSA-65 pubkeys from devnet genesis.toml."""
    text = GENESIS_TOML.read_text()
    pubkeys_hex = re.findall(r'mldsa_public_key_hex\s*=\s*"([0-9a-f]+)"', text)
    assert len(pubkeys_hex) == 4, f"Expected 4 pubkeys in genesis.toml, got {len(pubkeys_hex)}"
    pubkeys = [bytes.fromhex(h) for h in pubkeys_hex]
    for i, pk in enumerate(pubkeys):
        assert len(pk) == 1952, (  # ML-DSA-65 pubkey = 1952 bytes
            f"Validator[{i}] pubkey has wrong length: {len(pk)} bytes (expected 1952)"
        )
    logger.info("Loaded %d genesis pubkeys from %s", len(pubkeys), GENESIS_TOML)
    return pubkeys


# ── ABI encoders ─────────────────────────────────────────────────────────────


def abi_encode_address_uint256(addr: str, value: int) -> bytes:
    """ABI-encode (address, uint256) constructor args."""
    from eth_abi import encode

    return encode(["address", "uint256"], [addr, value])


def abi_encode_bootstrap(pk_hashes: list[bytes], stakes: list[int]) -> bytes:
    """ABI-encode bootstrapEpoch0(bytes32[], uint256[]) calldata."""
    from eth_abi import encode

    # keccak256("bootstrapEpoch0(bytes32[],uint256[])") = 23f68c1c
    selector = bytes.fromhex("23f68c1c")
    return selector + encode(["bytes32[]", "uint256[]"], [pk_hashes, stakes])


def abi_encode_submit_header(
    block_number: int,
    state_root: bytes,
    epoch: int,
    pubkeys: list[bytes],
    sigs: list[bytes],
) -> bytes:
    """ABI-encode submitHeader(uint256,bytes32,uint256,bytes[],bytes[]) calldata."""
    from eth_abi import encode

    # keccak256("submitHeader(uint256,bytes32,uint256,bytes[],bytes[])") = ebd9380d
    selector = bytes.fromhex("ebd9380d")
    state_root32 = state_root.rjust(32, b"\x00")
    return selector + encode(
        ["uint256", "bytes32", "uint256", "bytes[]", "bytes[]"],
        [block_number, state_root32, epoch, pubkeys, sigs],
    )


def abi_encode_header_state_root(chain_id: int, block_number: int) -> bytes:
    """ABI-encode headerStateRoot(uint256,uint256) view call."""
    from eth_abi import encode

    # keccak256("headerStateRoot(uint256,uint256)") = 016d9f11
    selector = bytes.fromhex("016d9f11")
    return selector + encode(["uint256", "uint256"], [chain_id, block_number])


def abi_encode_current_epoch() -> bytes:
    """ABI-encode currentEpoch() view call."""
    # keccak256("currentEpoch()") = 76671808
    return bytes.fromhex("76671808")


# ── Selector verification ─────────────────────────────────────────────────────


def _verify_selectors() -> None:
    """Verify all hard-coded 4-byte selectors against keccak256."""
    from eth_hash.auto import keccak

    checks = {
        "bootstrapEpoch0(bytes32[],uint256[])": "23f68c1c",
        "submitHeader(uint256,bytes32,uint256,bytes[],bytes[])": "ebd9380d",
        "headerStateRoot(uint256,uint256)": "016d9f11",
        "currentEpoch()": "76671808",
    }
    for sig, expected in checks.items():
        got = keccak(sig.encode()).hex()[:8]
        if got != expected:
            raise AssertionError(f"selector mismatch for {sig}: got {got}, expected {expected}")
    logger.info("All ABI selectors verified.")


# ── Node management ──────────────────────────────────────────────────────────


def kill_existing_node() -> None:
    """Kill any process already listening on NODE_PORT."""
    result = subprocess.run(
        ["lsof", "-ti", f"tcp:{NODE_PORT}"],
        capture_output=True,
        text=True,
    )
    pids = result.stdout.strip().split("\n")
    for pid in pids:
        pid = pid.strip()
        if pid:
            logger.info("Killing existing process on port %d (pid=%s)", NODE_PORT, pid)
            subprocess.run(["kill", "-9", pid], capture_output=True)
    time.sleep(0.5)


def start_suwappu_node() -> "subprocess.Popen[bytes]":
    """Start suwappu-node on NODE_PORT with CHAIN_ID."""
    kill_existing_node()
    proc = subprocess.Popen(
        [
            str(SUWAPPU_NODE_BIN),
            "--port",
            str(NODE_PORT),
            "--chain-id",
            str(CHAIN_ID),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait until the node is accepting connections.
    deadline = time.time() + 15.0
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                NODE_URL,
                data=b'{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}',
                headers={"content-type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
            logger.info("suwappu-node ready on port %d", NODE_PORT)
            return proc
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("suwappu-node did not start within 15s")


# ── Web3 helpers ─────────────────────────────────────────────────────────────


def make_web3() -> "Web3":  # type: ignore[name-defined]
    from eth_account import Account
    from web3 import Web3
    from web3.middleware import SignAndSendRawMiddlewareBuilder

    w3 = Web3(Web3.HTTPProvider(NODE_URL))
    acct = Account.from_key(ACCOUNT_0_KEY)
    w3.eth.default_account = acct.address
    w3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(acct))
    return w3


def eth_call_raw(w3: "Web3", to: str, data: bytes) -> bytes:  # type: ignore[name-defined]
    result = w3.eth.call({"to": to, "data": "0x" + data.hex()})
    return bytes(result)


# ── Deploy helpers ────────────────────────────────────────────────────────────


def deploy_contract(
    w3: "Web3",  # type: ignore[name-defined]
    creation_hex: str,
    ctor_args: bytes,
    label: str,
) -> str:
    """Deploy a contract and return its checksummed address."""
    from web3 import Web3

    code = bytes.fromhex(creation_hex.strip().lstrip("0x"))
    tx_data = code + ctor_args

    tx_hash = w3.eth.send_transaction(
        {
            "from": ACCOUNT_0,
            "data": "0x" + tx_data.hex(),
            "gas": GAS_LIMIT,
        }
    )
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1, f"{label} deploy failed (status=0)"
    addr = Web3.to_checksum_address(receipt["contractAddress"])
    logger.info("%s deployed at %s (tx=%s)", label, addr, tx_hash.hex())
    return addr


def send_tx_data(w3: "Web3", to: str, data: bytes, label: str) -> dict:  # type: ignore[name-defined]
    """Send a transaction and return the receipt."""
    tx_hash = w3.eth.send_transaction(
        {
            "from": ACCOUNT_0,
            "to": to,
            "data": "0x" + data.hex(),
            "gas": GAS_LIMIT,
        }
    )
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logger.info("%s tx=%s status=%d", label, tx_hash.hex(), receipt.get("status", -1))
    return receipt


# ── Relayer quorum accumulator ────────────────────────────────────────────────


def run_relayer_until_quorum(
    relayer: "HeaderRelayer",  # type: ignore[name-defined]
    validator_urls: list[str],
    min_quorum: int = 3,
    max_rounds: int = 100,
    sleep_s: float = 0.4,
) -> tuple["AggregatedHeader", int]:  # type: ignore[name-defined]
    """
    Drive the shipped HeaderRelayer until it aggregates >= min_quorum signers.

    Uses relayer.poll() + relayer.aggregate() accumulating across rounds so
    that validators whose block counters diverge by a round still converge.
    Returns (AggregatedHeader, rounds_taken).
    """
    flat = []
    for round_num in range(1, max_rounds + 1):
        flat += relayer.poll(validator_urls)
        agg = relayer.aggregate(flat)
        if agg is not None and agg.signer_count >= min_quorum:
            logger.info(
                "HeaderRelayer quorum: block=%d signers=%d (round=%d)",
                agg.block_number,
                agg.signer_count,
                round_num,
            )
            return agg, round_num
        time.sleep(sleep_s)
    raise RuntimeError(f"No quorum of >= {min_quorum} after {max_rounds} relayer poll rounds")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:  # noqa: C901
    print("=" * 70)
    print("SUWAPPU FULL NATIVE-PQ BRIDGE LOOP DEMO")
    print("=" * 70)

    # Verify selectors before any network calls.
    _verify_selectors()

    # ── Step 1: verify devnet is up ──────────────────────────────────────────
    import requests

    print("\n[1] Checking devnet validators...")
    responding = []
    for url in VALIDATOR_URLS:
        try:
            resp = requests.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "gsx_getHeaderAttestation",
                    "params": [],
                },
                timeout=5,
                headers={"content-type": "application/json"},
            )
            view = resp.json().get("result")
            if view:
                bn = view["block_number"]
                print(f"  {url}: block={bn} oracle={view['oracle']}")
                responding.append(url)
            else:
                print(f"  {url}: null response")
        except Exception as exc:
            print(f"  {url}: ERROR {exc}")

    if len(responding) < 3:
        print(f"FATAL: only {len(responding)} validators responding, need >= 3")
        return 1
    print(f"  {len(responding)}/4 validators responding — OK")

    # ── Step 2: start suwappu-node ───────────────────────────────────────────
    print("\n[2] Starting suwappu-node (fresh)...")
    node_proc = start_suwappu_node()

    _node_proc_ref: Optional[subprocess.Popen] = node_proc  # type: ignore[type-arg]

    def _cleanup(signum: Optional[int] = None, frame: Optional[object] = None) -> None:
        if _node_proc_ref is not None:
            _node_proc_ref.terminate()

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        from web3 import Web3

        w3 = make_web3()
        chain_id = w3.eth.chain_id
        acct_balance = w3.eth.get_balance(ACCOUNT_0)
        print(f"  chain_id={chain_id} account_0_balance={acct_balance}")
        assert chain_id == CHAIN_ID, f"chain_id mismatch: {chain_id} != {CHAIN_ID}"

        # ── Step 3: deploy registry (nonce 0) + oracle (nonce 1) ─────────────
        print("\n[3] Deploying contracts...")
        registry_hex = (FIXTURES / "GsxDagValidatorRegistry.creation.hex").read_text().strip()
        oracle_hex = (FIXTURES / "GsxDagQuorumHeaderOracle.creation.hex").read_text().strip()

        # Registry constructor: (address admin, uint256 networkId)
        reg_args = abi_encode_address_uint256(ACCOUNT_0, NETWORK_ID)
        registry_addr = deploy_contract(w3, registry_hex, reg_args, "GsxDagValidatorRegistry")

        # Oracle constructor: (address registry, uint256 gsxDagChainId)
        oracle_args = abi_encode_address_uint256(registry_addr, NETWORK_ID)
        oracle_addr = deploy_contract(w3, oracle_hex, oracle_args, "GsxDagQuorumHeaderOracle")

        # ── GATE: oracle address must match what validators signed over ───────
        print("\n[3a] Oracle address assertion:")
        print(f"  deployed:  {oracle_addr.lower()}")
        print(f"  expected:  {EXPECTED_ORACLE}")
        assert oracle_addr.lower() == EXPECTED_ORACLE.lower(), (
            f"ORACLE ADDRESS MISMATCH — nonce order wrong or wrong account!\n"
            f"  got:      {oracle_addr}\n"
            f"  expected: {EXPECTED_ORACLE}\n"
            "  Nothing will verify. Abort."
        )
        print("  MATCH — oracle address confirmed.")

        # ── Step 4: bootstrapEpoch0 ───────────────────────────────────────────
        print("\n[4] Bootstrapping epoch 0 with genesis pubkeys...")
        from eth_hash.auto import keccak

        genesis_pubkeys = load_genesis_pubkeys()
        pk_hashes: list[bytes] = []
        for pk in genesis_pubkeys:
            pk_hashes.append(keccak(pk))

        # Sort by hash value ascending (contract requirement)
        pk_hashes.sort()
        stakes = [150000] * len(pk_hashes)

        bootstrap_data = abi_encode_bootstrap(pk_hashes, stakes)
        receipt_bootstrap = send_tx_data(w3, registry_addr, bootstrap_data, "bootstrapEpoch0")
        assert receipt_bootstrap["status"] == 1, "bootstrapEpoch0 failed"
        print(f"  bootstrapEpoch0 success (status={receipt_bootstrap['status']})")

        # currentEpoch is read on-chain by relayer.submit() — no need to pass it here.

        # ── Step 5: drive the shipped HeaderRelayer until quorum ─────────────
        print("\n[5] Running HeaderRelayer.poll() + aggregate() until >= 3 signers...")
        from ltp.bridge.header_relayer import HeaderRelayer

        relayer = HeaderRelayer()
        agg, poll_rounds = run_relayer_until_quorum(
            relayer, VALIDATOR_URLS, min_quorum=3, max_rounds=100, sleep_s=0.4
        )
        block_number = agg.block_number
        state_root = agg.state_root
        print(f"  Quorum found in {poll_rounds} poll round(s)")
        print(f"  block_number = {block_number}")
        print(f"  state_root   = 0x{state_root.hex()}")
        print(f"  signers      = {agg.signer_count}")

        # ── Step 6: submit via HeaderRelayer.submit() ─────────────────────────
        print("\n[6] HeaderRelayer.submit() -> oracle.submitHeader()...")
        # relayer.submit() reads epoch on-chain via registry() + currentEpoch()
        # and calls oracle.submitHeader() via fn.transact() — requires default_account
        # + signing middleware (both set in make_web3()).
        receipt_submit = relayer.submit(w3, oracle_addr, agg)
        receipt_status = receipt_submit.get("status")
        print(f"  submitHeader tx status = {receipt_status}")

        # ── Step 7: assert finalization ───────────────────────────────────────
        print("\n[7] Reading back headerStateRoot...")
        readback_raw = eth_call_raw(
            w3, oracle_addr, abi_encode_header_state_root(NETWORK_ID, block_number)
        )
        readback_bytes = readback_raw[:32] if len(readback_raw) >= 32 else b"\x00" * 32

        print(
            f"  oracle.headerStateRoot(networkId=0x...{hex(NETWORK_ID)[-8:]}, block={block_number})"
        )
        print(f"  = 0x{readback_bytes.hex()}")
        print(f"  state_root from devnet = 0x{state_root.hex()}")

        state_root32 = state_root.rjust(32, b"\x00")
        finalized = receipt_status == 1 and readback_bytes == state_root32

        if finalized:
            print("\n" + "=" * 70)
            print("RESULT: YES — REAL devnet quorum attestation FINALIZED on suwappu-node")
            print("=" * 70)
            print(f"  Oracle address:           {oracle_addr}")
            print(f"  Finalized block_number:   {block_number}")
            print(f"  Finalized state_root:     0x{state_root.hex()}")
            print(f"  headerStateRoot readback: 0x{readback_bytes.hex()}")
            print(f"  Poll rounds to quorum:    {poll_rounds}")
            print(f"  Signers:                  {agg.signer_count}")
            print(f"  submitHeader tx status:   {receipt_status}")
            print()
            print("HONEST SCOPE NOTE:")
            print(
                "  This proves source->relay->destination native-PQ finalization. NOT a fund-safe"
            )
            print(
                "  lock->mint: state_root is an opaque BLAKE3 L1 anchor;"
                " storage-proof corridor unsupplied."
            )
            return 0

        if receipt_status != 1:
            print("\n" + "=" * 70)
            print("RESULT: NO — submitHeader REVERTED (status=0)")
            print("=" * 70)
            print(f"  Receipt: {receipt_submit}")
            return 1

        print("\n" + "=" * 70)
        print("RESULT: NO — submitHeader succeeded but readback mismatch")
        print("=" * 70)
        print(f"  expected: 0x{state_root.hex()}")
        print(f"  got:      0x{readback_bytes.hex()}")
        return 1

    finally:
        node_proc.terminate()
        node_proc.wait(timeout=5)
        logger.info("suwappu-node stopped.")


if __name__ == "__main__":
    sys.exit(main())
