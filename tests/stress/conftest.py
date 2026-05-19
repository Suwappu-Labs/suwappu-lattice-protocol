"""Shared fixtures for gateway stress tests."""

from unittest.mock import MagicMock

import pytest

from src.ltp.keypair import KeyPair


@pytest.fixture(scope="module")
def stress_kp():
    return KeyPair.generate("stress-test-gateway")


def make_raw_log(
    tx_hash="0xabc",
    block_number=100,
    log_index=0,
    contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
    sender="0xdeadbeef",
    recipient="0xcafebabe",
    payload_hash="sha3-256:abcd1234",
    amount=100_000_000,
    nonce=1,
):
    """Create a raw EVM log dict."""
    return {
        "transactionHash": tx_hash,
        "blockNumber": block_number,
        "logIndex": log_index,
        "address": contract,
        "event": "AnchorCreated",
        "args": {
            "sender": sender,
            "recipient": recipient,
            "payloadHash": payload_hash,
            "amount": amount,
            "nonce": nonce,
        },
    }


def make_service(
    kp,
    *,
    raw_logs=None,
    current_block=200,
    anchor_fn=None,
    signer_authorized=True,
    finality_depth=12,
    max_retries=5,
    challenge_mode="disabled",
    replay_db_path=":memory:",
):
    """Create a GatewayVMService with injectable dependencies."""
    from src.ltp.gateway_vm.config import GatewayVMConfig
    from src.ltp.gateway_vm.service import GatewayVMService

    config = GatewayVMConfig(
        enabled=True,
        source_chain_id=84532,
        source_bridge_contract="0x5083194d9e8EB54Fc397E69A518Be9503C767Dd0",
        finality_depth=finality_depth,
        dest_chain_id=103115120,
        replay_db_path=replay_db_path,
        max_retries=max_retries,
        challenge_mode=challenge_mode,
    )

    if raw_logs is None:
        raw_logs = []

    if anchor_fn is None:
        anchor_fn = MagicMock(return_value="0xtxhash")

    return GatewayVMService(
        config=config,
        operator_keypair=kp,
        fetch_logs=lambda fb, tb: raw_logs,
        get_source_block_number=lambda: current_block,
        get_dest_block_number=lambda: 999,
        anchor_fn=anchor_fn,
        is_signer_authorized=lambda: signer_authorized,
    )
