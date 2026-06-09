"""
Integration test: HeaderRelayer aggregate -> REAL GsxDagQuorumHeaderOracle.

Follows the anvil/web3 + forge-artifact conventions of
``tests/test_contract_integration.py`` and ``tests/test_governance_onchain.py``
byte-for-byte (module skip guard, ANVIL_* constants, ``_send_tx`` helper,
``out/<File>.sol/<Contract>.json`` artifact loading).

What is REAL vs mocked:
  - The ``GsxDagValidatorRegistry`` + ``GsxDagQuorumHeaderOracle`` are the REAL
    deployed contracts. ``submitHeader`` re-verifies sigs, the strict
    keccak(pubkey) dedup, and the >2/3 stake quorum on-chain. We do NOT mock
    the oracle.
  - Only the ML-DSA (0x0101) and BLAKE3 (0x0102) PRIMITIVES are mocked, etched
    via ``anvil_setCode`` from the compiled ``MockMldsa`` / ``MockBlake3``
    runtime bytecode (real ML-DSA-on-chain is covered separately by
    suwappu-revm 0x0101).

This proves the relayer is LIVENESS-trusted but CANNOT forge: the REAL oracle
ACCEPTS the aggregated quorum (finalized stateRoot read back on-chain) and
REJECTS a sub-quorum set (tx reverts).
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

try:
    from web3 import Web3

    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False


def _anvil_running() -> bool:
    if not HAS_WEB3:
        return False
    try:
        w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
        return w3.is_connected()
    except Exception:
        return False


# The relayer module itself imports `src.ltp` which asserts PQ backends; if that
# environment is absent we must skip rather than error at collection.
try:
    import src.ltp.bridge.header_relayer as _hr  # noqa: F401

    HAS_RELAYER = True
except Exception:
    HAS_RELAYER = False


pytestmark = pytest.mark.skipif(
    not HAS_WEB3 or not _anvil_running() or not HAS_RELAYER,
    reason="Requires web3, the PQ-backed ltp env, and anvil on localhost:8545",
)

ANVIL_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ANVIL_RPC = "http://localhost:8545"
ANVIL_CHAIN_ID = 31337

NETWORK_ID = 7777
GSXDAG_CHAIN_ID = 909090
BLOCK_NUMBER = 100
STATE_ROOT = bytes([0xAB]) * 32

BLAKE3_ADDR = "0x0000000000000000000000000000000000000102"
MLDSA_ADDR = "0x0000000000000000000000000000000000000101"

HEADER_DOMAIN = Web3.keccak(text="SUWAPPU_GSXDAG_HEADER_V1") if HAS_WEB3 else b""


# --------------------------------------------------------------------------- helpers
def _contracts_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "contracts")


def _artifact(file_sol: str, contract: str) -> dict:
    path = os.path.join(_contracts_dir(), "out", file_sol, contract + ".json")
    if not os.path.exists(path):
        subprocess.run(["forge", "build"], cwd=_contracts_dir(), check=True)
    with open(path) as f:
        return json.load(f)


def _send_tx(w3, account, fn, gas=2_000_000):
    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": ANVIL_CHAIN_ID,
            "gas": gas,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def _deploy(w3, account, artifact, *ctor_args):
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"]["object"])
    receipt = _send_tx(w3, account, contract.constructor(*ctor_args), gas=4_000_000)
    assert receipt["status"] == 1, "deployment failed"
    return receipt["contractAddress"]


def _mock_pubkey(i: int) -> bytes:
    # Mirrors GsxDagQuorumHeader.t.sol: keccak(abi.encodePacked("validator", i)).
    return Web3.solidity_keccak(["string", "uint256"], ["validator", i])


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def w3():
    return Web3(Web3.HTTPProvider(ANVIL_RPC))


@pytest.fixture(scope="module")
def account(w3):
    return w3.eth.account.from_key(ANVIL_PRIVATE_KEY)


@pytest.fixture(scope="module")
def precompiles(w3):
    """Etch MockBlake3@0x0102 and MockMldsa@0x0101 via anvil_setCode (runtime code)."""
    blake3 = _artifact("GsxDagQuorumHeader.t.sol", "MockBlake3")
    mldsa = _artifact("GsxDagQuorumHeader.t.sol", "MockMldsa")
    b3_code = "0x" + blake3["deployedBytecode"]["object"].removeprefix("0x")
    md_code = "0x" + mldsa["deployedBytecode"]["object"].removeprefix("0x")
    r1 = w3.provider.make_request("anvil_setCode", [BLAKE3_ADDR, b3_code])
    r2 = w3.provider.make_request("anvil_setCode", [MLDSA_ADDR, md_code])
    assert "error" not in r1, r1
    assert "error" not in r2, r2
    # Sanity: code is now present at the precompile addresses.
    assert w3.eth.get_code(Web3.to_checksum_address(BLAKE3_ADDR)) != b""
    assert w3.eth.get_code(Web3.to_checksum_address(MLDSA_ADDR)) != b""
    return True


@pytest.fixture(scope="module")
def deployment(w3, account, precompiles):
    """Deploy real registry + oracle and bootstrap 4 validators @ 25 stake (total 100)."""
    reg_art = _artifact("GsxDagValidatorRegistry.sol", "GsxDagValidatorRegistry")
    orc_art = _artifact("GsxDagQuorumHeaderOracle.sol", "GsxDagQuorumHeaderOracle")

    registry_addr = _deploy(w3, account, reg_art, account.address, NETWORK_ID)
    oracle_addr = _deploy(w3, account, orc_art, registry_addr, GSXDAG_CHAIN_ID)

    registry = w3.eth.contract(address=registry_addr, abi=reg_art["abi"])
    oracle = w3.eth.contract(address=oracle_addr, abi=orc_art["abi"])

    # 4 validators; pkHashes must be strictly increasing keccak(pubkey).
    pubkeys = [_mock_pubkey(i) for i in range(4)]
    pubkeys_sorted = sorted(pubkeys, key=Web3.keccak)
    pkhashes = [Web3.keccak(pk) for pk in pubkeys_sorted]
    stakes = [25, 25, 25, 25]  # total 100 -> quorum = 100*2//3 + 1 = 67
    receipt = _send_tx(w3, account, registry.functions.bootstrapEpoch0(pkhashes, stakes))
    assert receipt["status"] == 1, "bootstrap failed"

    return {
        "registry": registry,
        "oracle": oracle,
        "registry_addr": registry_addr,
        "oracle_addr": oracle_addr,
        "pubkeys_sorted": pubkeys_sorted,
    }


def _header_digest(oracle_addr: str) -> bytes:
    """Off-chain header digest == on-chain (mock BLAKE3 == keccak)."""
    return Web3.solidity_keccak(
        ["bytes32", "uint256", "address", "uint256", "bytes32"],
        [
            HEADER_DOMAIN,
            NETWORK_ID,
            Web3.to_checksum_address(oracle_addr),
            BLOCK_NUMBER,
            STATE_ROOT,
        ],
    )


def _mock_sign(pubkey: bytes, digest: bytes) -> bytes:
    """Mock ML-DSA sig: keccak256("MOCK_MLDSA" || bytes32(pubkey) || digest)."""
    return Web3.solidity_keccak(["string", "bytes32", "bytes32"], ["MOCK_MLDSA", pubkey, digest])


def _make_attestations(deployment, signer_pubkeys):
    """Build mock-form HeaderAttestation objects for the given signers."""
    from src.ltp.bridge.header_relayer import HeaderAttestation

    oracle_addr = deployment["oracle_addr"]
    digest = _header_digest(oracle_addr)
    atts = []
    for i, pk in enumerate(signer_pubkeys):
        atts.append(
            HeaderAttestation(
                block_number=BLOCK_NUMBER,
                state_root=STATE_ROOT,
                authority_id=i,
                pubkey=pk,
                signature=_mock_sign(pk, digest),
                network_id=NETWORK_ID.to_bytes(32, "big"),
                oracle=oracle_addr.lower(),
            )
        )
    return atts


def _w3_with_default_account(account):
    """A web3 instance whose default account is the anvil deployer (for fn.transact())."""
    from web3.middleware import SignAndSendRawMiddlewareBuilder

    w3 = Web3(Web3.HTTPProvider(ANVIL_RPC))
    w3.middleware_onion.inject(SignAndSendRawMiddlewareBuilder.build(account), layer=0)
    w3.eth.default_account = account.address
    return w3


# --------------------------------------------------------------------------- tests
def test_relayer_quorum_accepted_by_real_oracle(deployment, account):
    """Relayer aggregates 3-of-4 (75 >= 67) and the REAL oracle FINALIZES it."""
    from src.ltp.bridge.header_relayer import HeaderRelayer

    pubkeys = deployment["pubkeys_sorted"]
    # 3 signers -> 75 stake, clears quorum of 67.
    atts = _make_attestations(deployment, pubkeys[:3])

    relayer = HeaderRelayer()
    agg = relayer.aggregate(atts)
    assert agg is not None
    assert agg.signer_count == 3
    # Relayer ordered them strictly increasing by keccak(pubkey).
    hashes = [Web3.keccak(pk) for pk in agg.pubkeys]
    assert hashes == sorted(hashes)

    w3s = _w3_with_default_account(account)
    receipt = relayer.submit(w3s, deployment["oracle_addr"], agg)
    assert receipt["status"] == 1, "REAL oracle rejected a valid quorum"

    # On-chain finalized stateRoot, read via the oracle's gsxDagChainId (NOT networkId).
    oracle = deployment["oracle"]
    finalized = oracle.functions.headerStateRoot(GSXDAG_CHAIN_ID, BLOCK_NUMBER).call()
    assert finalized == STATE_ROOT, "finalized root mismatch"
    # Wrong chain id returns zero (domain separation sanity).
    assert oracle.functions.headerStateRoot(NETWORK_ID, BLOCK_NUMBER).call() == b"\x00" * 32


def test_relayer_subquorum_rejected_by_real_oracle(deployment, account, w3):
    """A 1-of-4 (25 < 67) aggregate is REJECTED by the REAL oracle (revert)."""
    from src.ltp.bridge.header_relayer import HeaderRelayer

    pubkeys = deployment["pubkeys_sorted"]
    # Use a DISTINCT, un-finalized block so this can't no-op on an existing root.
    sub_block = BLOCK_NUMBER + 1

    digest = Web3.solidity_keccak(
        ["bytes32", "uint256", "address", "uint256", "bytes32"],
        [
            HEADER_DOMAIN,
            NETWORK_ID,
            Web3.to_checksum_address(deployment["oracle_addr"]),
            sub_block,
            STATE_ROOT,
        ],
    )
    pk = pubkeys[0]
    sig = Web3.solidity_keccak(["string", "bytes32", "bytes32"], ["MOCK_MLDSA", pk, digest])

    oracle = deployment["oracle"]
    # Send with fixed gas so a revert surfaces as status==0 (not an estimateGas throw),
    # mirroring the test_contract_integration.py:388 revert idiom.
    receipt = _send_tx(
        w3,
        account,
        oracle.functions.submitHeader(sub_block, STATE_ROOT, 0, [pk], [sig]),
        gas=2_000_000,
    )
    assert receipt["status"] == 0, "sub-quorum submission MUST revert (BelowQuorum)"
    # And nothing was finalized for that block.
    assert oracle.functions.headerStateRoot(GSXDAG_CHAIN_ID, sub_block).call() == b"\x00" * 32

    # Sanity: the relayer would faithfully produce exactly this 1-signer aggregate.
    relayer = HeaderRelayer()
    sub_atts = _make_attestations(deployment, [pk])
    sub_agg = relayer.aggregate(sub_atts)
    assert sub_agg is not None and sub_agg.signer_count == 1
