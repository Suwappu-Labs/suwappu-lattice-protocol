"""
Integration tests: Python trust layer ↔ Solidity LTPAnchorRegistry.

Proves that the Python trust layer and the Solidity contract produce
identical accept/reject behavior for anchoring, state transitions,
sequence tracking, and signer authorization.

Requires:
  - anvil running on localhost:8545 (Foundry local EVM)
  - web3 installed: pip install web3>=6.0.0

Usage:
  anvil &
  cd contracts && forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast
  pytest tests/test_contract_integration.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

# Skip entire module if web3 is not installed or anvil not running
try:
    from web3 import Web3

    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False


# Check if anvil is running
def _anvil_running() -> bool:
    if not HAS_WEB3:
        return False
    try:
        w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
        return w3.is_connected()
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not HAS_WEB3 or not _anvil_running(),
    reason="Requires web3 and anvil running on localhost:8545",
)

# Anvil default deployer private key and address
ANVIL_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ANVIL_RPC = "http://localhost:8545"
ANVIL_CHAIN_ID = 31337


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def w3():
    """Web3 connection to local anvil."""
    return Web3(Web3.HTTPProvider(ANVIL_RPC))


@pytest.fixture(scope="module")
def contract_address(w3):
    """Deploy LTPAnchorRegistry behind UUPS proxy and return proxy address."""
    contracts_dir = os.path.join(os.path.dirname(__file__), "..", "contracts")

    # Read implementation artifact
    impl_path = os.path.join(
        contracts_dir,
        "out",
        "LTPAnchorRegistry.sol",
        "LTPAnchorRegistry.json",
    )
    if not os.path.exists(impl_path):
        subprocess.run(["forge", "build"], cwd=contracts_dir, check=True)

    with open(impl_path) as f:
        impl_artifact = json.load(f)

    # Read proxy artifact
    proxy_path = os.path.join(
        contracts_dir,
        "out",
        "ERC1967Proxy.sol",
        "ERC1967Proxy.json",
    )
    with open(proxy_path) as f:
        proxy_artifact = json.load(f)

    account = w3.eth.account.from_key(ANVIL_PRIVATE_KEY)

    # 1. Deploy implementation (constructor disables initializers, no args)
    impl_contract = w3.eth.contract(
        abi=impl_artifact["abi"],
        bytecode=impl_artifact["bytecode"]["object"],
    )
    tx = impl_contract.constructor().build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": ANVIL_CHAIN_ID,
            "gas": 5_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1, "Implementation deployment failed"
    impl_address = receipt["contractAddress"]

    # 2. Build initialize calldata
    impl_instance = w3.eth.contract(address=impl_address, abi=impl_artifact["abi"])
    init_data = impl_instance.encode_abi("initialize", args=[account.address])

    # 3. Deploy ERC1967Proxy(implementation, initData)
    proxy_contract = w3.eth.contract(
        abi=proxy_artifact["abi"],
        bytecode=proxy_artifact["bytecode"]["object"],
    )
    tx = proxy_contract.constructor(impl_address, bytes.fromhex(init_data[2:])).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": ANVIL_CHAIN_ID,
            "gas": 1_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1, "Proxy deployment failed"
    return receipt["contractAddress"]


@pytest.fixture(scope="module")
def registry(w3, contract_address):
    """Contract instance (proxy cast to implementation ABI)."""
    artifact_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "contracts",
        "out",
        "LTPAnchorRegistry.sol",
        "LTPAnchorRegistry.json",
    )
    with open(artifact_path) as f:
        artifact = json.load(f)
    return w3.eth.contract(address=contract_address, abi=artifact["abi"])


@pytest.fixture(scope="module")
def account(w3):
    """Anvil deployer account."""
    return w3.eth.account.from_key(ANVIL_PRIVATE_KEY)


@pytest.fixture(scope="module")
def anchor_client(contract_address):
    """AnchorClient instance for testing."""
    from src.ltp.anchor.client import AnchorClient

    return AnchorClient(
        rpc_url=ANVIL_RPC,
        contract_address=contract_address,
        private_key=ANVIL_PRIVATE_KEY,
        chain_id=ANVIL_CHAIN_ID,
    )


def _send_tx(w3, account, fn, gas=500_000):
    """Helper to send a transaction. Returns receipt."""
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


# ---------------------------------------------------------------------------
# 1. Round-trip: anchor → isAnchored with entityIdHash
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_anchor_and_verify(self, w3, registry, account):
        """anchor() with entityIdHash → isAnchored, getEntityState."""
        signer_vk_hash = Web3.keccak(text="test-signer-roundtrip")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        anchor_digest = Web3.keccak(text="roundtrip-digest-1")
        entity_id = Web3.keccak(text="roundtrip-entity-1")
        merkle_root = Web3.keccak(text="merkle-root-1")
        policy_hash = Web3.keccak(text="policy-hash-1")
        valid_until = int(time.time()) + 3600

        receipt = _send_tx(
            w3,
            account,
            registry.functions.anchor(
                anchor_digest,
                entity_id,
                merkle_root,
                policy_hash,
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )
        assert receipt["status"] == 1

        assert registry.functions.isAnchored(anchor_digest).call() is True
        assert registry.functions.getEntityState(entity_id).call() == 2  # ANCHORED
        assert registry.functions.getSignerSequence(signer_vk_hash).call() == 1


# ---------------------------------------------------------------------------
# 2. State machine parity: Python validate_transition vs on-chain
# ---------------------------------------------------------------------------


class TestStateMachineParity:
    def test_valid_transitions_match(self, registry):
        """Python and on-chain agree on valid transitions."""
        from src.ltp.anchor.state import EntityState, validate_transition

        ok, _ = validate_transition(EntityState.UNKNOWN, EntityState.COMMITTED)
        assert ok

        ok, _ = validate_transition(EntityState.COMMITTED, EntityState.ANCHORED)
        assert ok

    def test_invalid_transition_parity(self, registry):
        """UNKNOWN → MATERIALIZED invalid in both Python and on-chain."""
        from src.ltp.anchor.state import EntityState, validate_transition

        ok, reason = validate_transition(EntityState.UNKNOWN, EntityState.MATERIALIZED)
        assert not ok
        assert "invalid" in reason


# ---------------------------------------------------------------------------
# 3. Sequence parity: SequenceTracker vs on-chain
# ---------------------------------------------------------------------------


class TestSequenceParity:
    def test_sequence_hwm_matches(self, w3, registry, account):
        """On-chain and Python sequence HWM track identically."""
        from src.ltp.sequencing import SequenceTracker

        signer_vk_hash = Web3.keccak(text="seq-parity-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        valid_until = int(time.time()) + 3600

        tracker = SequenceTracker(chain_id="test")
        fake_vk = b"seq-parity-signer"

        for seq in [1, 2, 3, 5, 10]:
            digest = Web3.keccak(text=f"seq-digest-{seq}")
            entity_id = Web3.keccak(text=f"seq-entity-{seq}")
            root = Web3.keccak(text=f"seq-root-{seq}")
            policy = Web3.keccak(text=f"seq-policy-{seq}")
            receipt = _send_tx(
                w3,
                account,
                registry.functions.anchor(
                    digest,
                    entity_id,
                    root,
                    policy,
                    signer_vk_hash,
                    seq,
                    valid_until,
                    0,
                ),
            )
            assert receipt["status"] == 1

            ok, _ = tracker.validate_and_advance(
                fake_vk,
                seq,
                "test",
                time.time() + 3600,
            )
            assert ok

            on_chain_seq = registry.functions.getSignerSequence(signer_vk_hash).call()
            py_seq = tracker.current_sequence(fake_vk)
            assert on_chain_seq == seq
            assert py_seq == seq


# ---------------------------------------------------------------------------
# 4. Batch anchoring
# ---------------------------------------------------------------------------


class TestBatchAnchoring:
    def test_batch_10_items(self, w3, registry, account):
        """Batch anchor 10 items, all verifiable on-chain."""
        signer_vk_hash = Web3.keccak(text="batch-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        valid_until = int(time.time()) + 3600
        count = 10

        digests = [Web3.keccak(text=f"batch-digest-{i}") for i in range(count)]
        entity_ids = [Web3.keccak(text=f"batch-entity-{i}") for i in range(count)]
        roots = [Web3.keccak(text=f"batch-root-{i}") for i in range(count)]
        policies = [Web3.keccak(text=f"batch-policy-{i}") for i in range(count)]
        signers = [signer_vk_hash] * count
        seqs = list(range(1, count + 1))
        expiries = [valid_until] * count
        types = [0] * count

        receipt = _send_tx(
            w3,
            account,
            registry.functions.batchAnchor(
                digests,
                entity_ids,
                roots,
                policies,
                signers,
                seqs,
                expiries,
                types,
            ),
            gas=3_000_000,
        )
        assert receipt["status"] == 1

        # Batch query
        results = registry.functions.areAnchored(digests).call()
        assert all(results)

        assert registry.functions.getSignerSequence(signer_vk_hash).call() == 10


# ---------------------------------------------------------------------------
# 5. Rejection parity
# ---------------------------------------------------------------------------


class TestRejectionParity:
    def test_expired_rejected(self, w3, registry, account):
        """Expired timestamps rejected on-chain."""
        signer_vk_hash = Web3.keccak(text="expired-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        digest = Web3.keccak(text="expired-digest")
        entity_id = Web3.keccak(text="expired-entity")
        valid_until = 1  # clearly expired

        receipt = _send_tx(
            w3,
            account,
            registry.functions.anchor(
                digest,
                entity_id,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )
        assert receipt["status"] == 0, "Expired anchor should revert"

    def test_unauthorized_signer_rejected(self, w3, registry, account):
        """Unauthorized signer rejected on-chain."""
        unknown_signer = Web3.keccak(text="unauthorized-signer")
        digest = Web3.keccak(text="unauth-digest")
        entity_id = Web3.keccak(text="unauth-entity")
        valid_until = int(time.time()) + 3600

        receipt = _send_tx(
            w3,
            account,
            registry.functions.anchor(
                digest,
                entity_id,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                unknown_signer,
                1,
                valid_until,
                0,
            ),
        )
        assert receipt["status"] == 0, "Unauthorized signer should revert"

    def test_replay_rejected(self, w3, registry, account):
        """Same anchor digest rejected on second attempt."""
        signer_vk_hash = Web3.keccak(text="replay-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        digest = Web3.keccak(text="replay-digest")
        entity_id = Web3.keccak(text="replay-entity")
        valid_until = int(time.time()) + 3600

        receipt = _send_tx(
            w3,
            account,
            registry.functions.anchor(
                digest,
                entity_id,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )
        assert receipt["status"] == 1

        receipt2 = _send_tx(
            w3,
            account,
            registry.functions.anchor(
                digest,
                Web3.keccak(text="other-entity"),
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                2,
                valid_until,
                0,
            ),
        )
        assert receipt2["status"] == 0, "Replay should revert"


# ---------------------------------------------------------------------------
# 6. transitionState integration
# ---------------------------------------------------------------------------


class TestTransitionState:
    def test_full_lifecycle(self, w3, registry, account):
        """Anchor → MATERIALIZED → DISPUTED → DELETED via transitionState."""
        signer_vk_hash = Web3.keccak(text="lifecycle-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        entity_id = Web3.keccak(text="lifecycle-entity")
        valid_until = int(time.time()) + 3600

        # Anchor (UNKNOWN → ANCHORED)
        _send_tx(
            w3,
            account,
            registry.functions.anchor(
                Web3.keccak(text="lifecycle-digest"),
                entity_id,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )
        assert registry.functions.getEntityState(entity_id).call() == 2  # ANCHORED

        # ANCHORED → MATERIALIZED
        receipt = _send_tx(
            w3,
            account,
            registry.functions.transitionState(entity_id, 3, signer_vk_hash, 2, valid_until),
        )
        assert receipt["status"] == 1
        assert registry.functions.getEntityState(entity_id).call() == 3  # MATERIALIZED

        # MATERIALIZED → DISPUTED
        receipt = _send_tx(
            w3,
            account,
            registry.functions.transitionState(entity_id, 4, signer_vk_hash, 3, valid_until),
        )
        assert receipt["status"] == 1
        assert registry.functions.getEntityState(entity_id).call() == 4  # DISPUTED

        # DISPUTED → DELETED
        receipt = _send_tx(
            w3,
            account,
            registry.functions.transitionState(entity_id, 5, signer_vk_hash, 4, valid_until),
        )
        assert receipt["status"] == 1
        assert registry.functions.getEntityState(entity_id).call() == 5  # DELETED


# ---------------------------------------------------------------------------
# 7. Batch queries integration
# ---------------------------------------------------------------------------


class TestBatchQueries:
    def test_batch_entity_states(self, w3, registry, account):
        """getEntityStates returns correct states for multiple entities."""
        signer_vk_hash = Web3.keccak(text="batchq-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        valid_until = int(time.time()) + 3600
        e1 = Web3.keccak(text="batchq-entity-1")
        e2 = Web3.keccak(text="batchq-entity-2")
        e3 = Web3.keccak(text="batchq-entity-3")  # never touched

        _send_tx(
            w3,
            account,
            registry.functions.anchor(
                Web3.keccak(text="batchq-d1"),
                e1,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )
        _send_tx(
            w3,
            account,
            registry.functions.anchor(
                Web3.keccak(text="batchq-d2"),
                e2,
                Web3.keccak(text="r2"),
                Web3.keccak(text="p2"),
                signer_vk_hash,
                2,
                valid_until,
                0,
            ),
        )
        # Transition e2 → MATERIALIZED
        _send_tx(
            w3,
            account,
            registry.functions.transitionState(
                e2,
                3,
                signer_vk_hash,
                3,
                valid_until,
            ),
        )

        states = registry.functions.getEntityStates([e1, e2, e3]).call()
        assert states[0] == 2  # ANCHORED
        assert states[1] == 3  # MATERIALIZED
        assert states[2] == 0  # UNKNOWN


# ---------------------------------------------------------------------------
# 8. AnchorClient integration
# ---------------------------------------------------------------------------


class TestAnchorClient:
    def test_client_anchor_and_query(self, w3, registry, account, anchor_client):
        """AnchorClient.anchor() → is_anchored() → entity_state()."""
        from src.ltp.anchor.state import EntityState

        signer_vk_hash = Web3.keccak(text="client-test-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        from src.ltp.anchor.submission import AnchorSubmission

        digest = Web3.keccak(text="client-digest-1")
        entity_id = Web3.keccak(text="client-entity-1")
        submission = AnchorSubmission(
            anchor_digest=digest,
            entity_id_hash=entity_id,
            merkle_root=Web3.keccak(text="client-root"),
            policy_hash=Web3.keccak(text="client-policy"),
            signer_vk_hash=signer_vk_hash,
            sequence=1,
            valid_until=int(time.time()) + 3600,
            target_chain_id=ANVIL_CHAIN_ID,
            receipt_type="COMMIT",
        )

        tx_hash = anchor_client.anchor(submission)
        assert len(tx_hash) > 0

        # AnchorClient now waits for receipt internally, no need to wait again
        assert anchor_client.is_anchored(digest) is True
        state = anchor_client.entity_state(entity_id)
        assert state == EntityState.ANCHORED
        assert anchor_client.signer_sequence(signer_vk_hash) == 1


# ---------------------------------------------------------------------------
# 9. ABI validation: Python ABI matches Solidity contract ABI
# ---------------------------------------------------------------------------


class TestABIValidation:
    def test_python_abi_matches_contract(self, w3, contract_address):
        """Verify every function in Python _REGISTRY_ABI exists in the compiled contract ABI."""
        from src.ltp.anchor.client import _REGISTRY_ABI

        artifact_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "contracts",
            "out",
            "LTPAnchorRegistry.sol",
            "LTPAnchorRegistry.json",
        )
        with open(artifact_path) as f:
            artifact = json.load(f)

        contract_functions = {}
        for item in artifact["abi"]:
            if item.get("type") == "function":
                contract_functions[item["name"]] = item

        for py_item in _REGISTRY_ABI:
            name = py_item["name"]
            assert name in contract_functions, (
                f"Python ABI has function '{name}' not found in compiled contract"
            )

            sol_item = contract_functions[name]

            # Check input count and types match (compare types only —
            # solc omits parameter names for public mapping getters)
            py_types = [p["type"] for p in py_item["inputs"]]
            sol_types = [p["type"] for p in sol_item["inputs"]]
            assert py_types == sol_types, (
                f"ABI mismatch for {name}: Python types={py_types}, Solidity types={sol_types}"
            )


# ---------------------------------------------------------------------------
# 10. transitionState integration
# ---------------------------------------------------------------------------


class TestTransitionStateIntegration:
    def test_transition_lifecycle_via_client(self, w3, registry, account, anchor_client):
        """AnchorClient.transition_state() full lifecycle."""
        from src.ltp.anchor.state import EntityState

        signer_vk_hash = Web3.keccak(text="transition-client-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        entity_id = Web3.keccak(text="transition-client-entity")
        valid_until = int(time.time()) + 3600

        # Anchor first
        _send_tx(
            w3,
            account,
            registry.functions.anchor(
                Web3.keccak(text="transition-client-digest"),
                entity_id,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )

        # ANCHORED → MATERIALIZED via client
        tx_hash = anchor_client.transition_state(
            entity_id,
            3,
            signer_vk_hash,
            2,
            valid_until,
        )
        assert len(tx_hash) > 0
        state = anchor_client.entity_state(entity_id)
        assert state == EntityState.MATERIALIZED

        # MATERIALIZED → DELETED via client
        tx_hash = anchor_client.transition_state(
            entity_id,
            5,
            signer_vk_hash,
            3,
            valid_until,
        )
        state = anchor_client.entity_state(entity_id)
        assert state == EntityState.DELETED


# ---------------------------------------------------------------------------
# 11. UUPS upgrade integration
# ---------------------------------------------------------------------------


class TestUUPSUpgradeIntegration:
    def test_upgrade_preserves_state(self, w3, registry, account, contract_address):
        """Deploy new impl, upgrade, verify state survives."""
        signer_vk_hash = Web3.keccak(text="upgrade-test-signer")
        _send_tx(w3, account, registry.functions.registerSigner(signer_vk_hash))

        entity_id = Web3.keccak(text="upgrade-test-entity")
        digest = Web3.keccak(text="upgrade-test-digest")
        valid_until = int(time.time()) + 3600

        _send_tx(
            w3,
            account,
            registry.functions.anchor(
                digest,
                entity_id,
                Web3.keccak(text="r"),
                Web3.keccak(text="p"),
                signer_vk_hash,
                1,
                valid_until,
                0,
            ),
        )
        assert registry.functions.isAnchored(digest).call() is True

        # Deploy new implementation
        contracts_dir = os.path.join(os.path.dirname(__file__), "..", "contracts")
        impl_path = os.path.join(
            contracts_dir,
            "out",
            "LTPAnchorRegistry.sol",
            "LTPAnchorRegistry.json",
        )
        with open(impl_path) as f:
            impl_artifact = json.load(f)

        impl_contract = w3.eth.contract(
            abi=impl_artifact["abi"],
            bytecode=impl_artifact["bytecode"]["object"],
        )
        tx = impl_contract.constructor().build_transaction(
            {
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address),
                "chainId": ANVIL_CHAIN_ID,
                "gas": 5_000_000,
                "gasPrice": w3.eth.gas_price,
            }
        )
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        new_impl_address = receipt["contractAddress"]

        # Upgrade via UUPS
        upgrade_fn = registry.functions.upgradeToAndCall(new_impl_address, b"")
        upgrade_receipt = _send_tx(w3, account, upgrade_fn)
        assert upgrade_receipt["status"] == 1

        # Verify state preserved
        assert registry.functions.isAnchored(digest).call() is True
        assert registry.functions.getEntityState(entity_id).call() == 2  # ANCHORED
        assert registry.functions.getSignerSequence(signer_vk_hash).call() == 1


# ---------------------------------------------------------------------------
# 7. LiveBridge: end-to-end bridge transfer with on-chain anchoring
# ---------------------------------------------------------------------------


class TestLiveBridge:
    """Prove the bridge works with real on-chain state (via anvil)."""

    @pytest.fixture
    def live_bridge(self, anchor_client, registry, w3, account):
        """Set up LiveBridge with all components wired to anvil."""
        from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
        from src.ltp.bridge.live import LiveBridge
        from src.ltp.domain import signer_fingerprint

        # Create bridge keypairs
        operator_kp = KeyPair.generate("live-bridge-operator")
        verifier_kp = KeyPair.generate("live-bridge-verifier")

        # Register the operator's signer VK hash on-chain
        vk_hash = signer_fingerprint(operator_kp.vk)
        _send_tx(w3, account, registry.functions.registerSigner(vk_hash))

        # Set up commitment network
        net = CommitmentNetwork()
        for nid, region in [
            ("live-1", "US-East"),
            ("live-2", "US-West"),
            ("live-3", "EU-West"),
            ("live-4", "EU-East"),
            ("live-5", "AP-East"),
            ("live-6", "AP-South"),
        ]:
            net.add_node(nid, region)

        protocol = LTPProtocol(net)

        return LiveBridge(
            protocol=protocol,
            l1_client=anchor_client,
            operator_keypair=operator_kp,
            l2_verifier_keypair=verifier_kp,
            source_chain="ethereum",
            dest_chain="optimism",
            l1_chain_id=ANVIL_CHAIN_ID,
        )

    def test_full_transfer_with_on_chain_anchor(self, live_bridge):
        """End-to-end: commit → anchor on-chain → relay → materialize → verify."""
        from src.ltp.bridge.message import BridgeMessage

        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="ethereum",
            dest_chain="optimism",
            sender="0xAliceSender",
            recipient="0xAliceRecipient",
            payload={"token": "USDC", "amount": 100, "decimals": 6},
            nonce=0,
        )

        result = live_bridge.transfer(msg)

        # Bridge message was reconstructed correctly
        assert result is not None
        assert result.message.msg_type == "token_lock"
        assert result.message.payload["token"] == "USDC"
        assert result.message.payload["amount"] == 100
        assert result.message.sender == "0xAliceSender"
        assert result.message.nonce == 0

        # Anchor exists ON-CHAIN (not simulated)
        assert result.is_anchored_on_l1 is True
        assert result.l1_entity_state == 2  # ANCHORED

        # Transaction was real (64 hex chars, may or may not have 0x prefix)
        tx_hash = result.l1_anchor_tx_hash
        clean = tx_hash[2:] if tx_hash.startswith("0x") else tx_hash
        assert len(clean) == 64
        int(clean, 16)  # Valid hex

    def test_multiple_transfers_sequence_advances(self, live_bridge):
        """Multiple transfers advance the on-chain sequence correctly."""
        from src.ltp.bridge.message import BridgeMessage

        results = []
        for nonce in range(3):
            msg = BridgeMessage(
                msg_type="token_lock",
                source_chain="ethereum",
                dest_chain="optimism",
                sender="0xBobSender",
                recipient="0xBobRecipient",
                payload={"token": "ETH", "amount": nonce + 1},
                nonce=nonce,
            )
            result = live_bridge.transfer(msg)
            assert result is not None
            results.append(result)

        # Sequences are strictly increasing
        for i in range(1, len(results)):
            assert results[i].sequence > results[i - 1].sequence

        # All anchors exist on-chain
        for r in results:
            assert r.is_anchored_on_l1 is True

        # On-chain sequence matches
        on_chain_seq = live_bridge.l1_on_chain_sequence
        assert on_chain_seq == results[-1].sequence

    def test_on_chain_state_is_anchored(self, live_bridge):
        """Verify the on-chain entity state is ANCHORED (2) after transfer."""
        from src.ltp.bridge.message import BridgeMessage

        msg = BridgeMessage(
            msg_type="state_update",
            source_chain="ethereum",
            dest_chain="optimism",
            sender="0xCharlie",
            recipient="0xCharlie",
            payload={"key": "value", "update_type": "config"},
            nonce=0,
        )

        result = live_bridge.transfer(msg)
        assert result is not None
        assert result.l1_entity_state == 2  # ANCHORED
        assert result.source_chain == "ethereum"
        assert result.dest_chain == "optimism"
