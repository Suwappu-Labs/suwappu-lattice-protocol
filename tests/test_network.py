"""
Tests for gRPC networking layer.

Starts actual gRPC servers on localhost and verifies shard operations
work over the network.
"""

import os
import time

import pytest

from src.ltp.commitment import CommitmentNetwork, CommitmentNode
from src.ltp.network.client import NodeClient
from src.ltp.network.remote import RemoteNode
from src.ltp.network.server import NodeServer
from src.ltp.primitives import canonical_hash

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def node():
    return CommitmentNode("test-node", "US-East")


@pytest.fixture
def server_and_client(node):
    """Start a gRPC server on a random port and return (server, client).

    Uses gRPC's native port=0 binding — add_insecure_port returns the
    actual port, which NodeServer captures in self._port. No socket
    workaround needed.
    """
    server = NodeServer(node, port=0, host="localhost")
    server.start()
    time.sleep(0.1)  # brief wait for server to start accepting

    client = NodeClient(f"localhost:{server.port}", timeout=5.0)
    yield server, client, node

    client.close()
    server.stop(grace=0.5)


# ---------------------------------------------------------------------------
# Client-Server round-trip tests
# ---------------------------------------------------------------------------


class TestClientServer:
    def test_store_and_fetch(self, server_and_client):
        server, client, node = server_and_client
        data = os.urandom(256)

        assert client.store_shard("entity-1", 0, data)
        fetched = client.fetch_shard("entity-1", 0)
        assert fetched == data

    def test_fetch_missing(self, server_and_client):
        _, client, _ = server_and_client
        assert client.fetch_shard("nonexistent", 0) is None

    def test_audit_challenge(self, server_and_client):
        _, client, _ = server_and_client
        data = b"shard-content-for-audit"
        client.store_shard("audit-entity", 3, data)

        nonce = os.urandom(16)
        proof = client.audit_challenge("audit-entity", 3, nonce)
        assert proof is not None
        # Verify proof matches expected: H(ciphertext || nonce)
        expected = canonical_hash(data + nonce)
        assert proof == expected

    def test_audit_missing_shard(self, server_and_client):
        _, client, _ = server_and_client
        proof = client.audit_challenge("missing", 0, os.urandom(16))
        assert proof is None

    def test_remove_shard(self, server_and_client):
        _, client, _ = server_and_client
        client.store_shard("rm-entity", 0, b"data")
        assert client.remove_shard("rm-entity", 0)
        assert client.fetch_shard("rm-entity", 0) is None

    def test_remove_missing(self, server_and_client):
        _, client, _ = server_and_client
        assert not client.remove_shard("nope", 0)

    def test_node_info(self, server_and_client):
        _, client, _ = server_and_client
        client.store_shard("e1", 0, b"a")
        client.store_shard("e1", 1, b"b")

        info = client.get_node_info()
        assert info["node_id"] == "test-node"
        assert info["region"] == "US-East"
        assert info["shard_count"] == 2
        assert info["evicted"] is False

    def test_fetch_batch(self, server_and_client):
        _, client, _ = server_and_client
        client.store_shard("batch", 0, b"zero")
        client.store_shard("batch", 1, b"one")
        client.store_shard("batch", 2, b"two")

        results = client.fetch_shards_batch(
            [
                ("batch", 0),
                ("batch", 1),
                ("batch", 2),
                ("batch", 99),
            ]
        )
        assert results[0] == b"zero"
        assert results[1] == b"one"
        assert results[2] == b"two"
        assert results[3] is None

    def test_large_shard_over_network(self, server_and_client):
        _, client, _ = server_and_client
        big = os.urandom(500_000)  # 500KB
        assert client.store_shard("big", 0, big)
        assert client.fetch_shard("big", 0) == big

    def test_multiple_entities(self, server_and_client):
        _, client, _ = server_and_client
        for i in range(10):
            for j in range(4):
                client.store_shard(f"entity-{i}", j, f"data-{i}-{j}".encode())

        info = client.get_node_info()
        assert info["shard_count"] == 40

        assert client.fetch_shard("entity-5", 2) == b"data-5-2"


# ---------------------------------------------------------------------------
# RemoteNode integration
# ---------------------------------------------------------------------------


class TestRemoteNode:
    def test_remote_node_store_fetch(self, server_and_client):
        server, _, local_node = server_and_client
        remote = RemoteNode("test-node", "US-East", server.address)

        remote.store_shard("remote-entity", 0, b"remote-data")
        assert remote.fetch_shard("remote-entity", 0) == b"remote-data"
        # Verify it actually went to the local node via gRPC
        assert local_node.fetch_shard("remote-entity", 0) == b"remote-data"
        remote.close()

    def test_remote_node_audit(self, server_and_client):
        server, _, _ = server_and_client
        remote = RemoteNode("test-node", "US-East", server.address)

        remote.store_shard("audit-r", 0, b"audit-payload")
        nonce = os.urandom(16)
        proof = remote.respond_to_audit("audit-r", 0, nonce)
        assert proof is not None
        expected = canonical_hash(b"audit-payload" + nonce)
        assert proof == expected
        remote.close()

    def test_remote_node_shards_proxy(self, server_and_client):
        server, _, _ = server_and_client
        remote = RemoteNode("test-node", "US-East", server.address)

        # Dict-like access through proxy
        remote.shards[("proxy-e", 0)] = b"proxy-data"
        assert remote.shards[("proxy-e", 0)] == b"proxy-data"
        assert ("proxy-e", 0) in remote.shards
        assert remote.shards.get(("missing", 0)) is None

        del remote.shards[("proxy-e", 0)]
        assert ("proxy-e", 0) not in remote.shards
        remote.close()

    def test_remote_node_in_network(self, server_and_client):
        """RemoteNode can be added to a CommitmentNetwork."""
        server, _, _ = server_and_client
        remote = RemoteNode("test-node", "US-East", server.address)

        net = CommitmentNetwork()
        # Add some local nodes + the remote node
        net.add_node("local-0", "US-West")
        net.add_node("local-1", "EU-West")
        net.add_existing_node(remote)

        assert len(net.nodes) == 3
        assert any(n.node_id == "test-node" for n in net.nodes)
        remote.close()
