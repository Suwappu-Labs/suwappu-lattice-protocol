"""
Docker-based node runner for real-process LTP simulation.

Provides DockerNode and DockerNodeManager for spinning up actual Docker
containers that simulate real-world LTP commitment nodes. Each container
runs a lightweight HTTP server that stores/fetches encrypted shards,
responds to audits, and communicates over real TCP/IP with configurable
network constraints (via Docker network options or tc/netem).

Requirements:
  - Docker Engine running on the host
  - Python 'docker' package (pip install docker)

This module is optional — the in-process simulation (SimNode) works
without Docker. DockerNodeManager is for large-scale, high-fidelity
simulations where real network I/O matters.
"""

from __future__ import annotations

import json
import os
import textwrap
import time
from dataclasses import dataclass, field
from typing import Optional

# Docker SDK import is deferred to avoid hard dependency
_docker_available = False
try:
    import docker

    _docker_available = True
except ImportError:
    docker = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONTAINER_IMAGE = "python:3.12-slim"
CONTAINER_PORT = 8321
NODE_SERVER_SCRIPT = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"Minimal LTP shard storage node — runs inside Docker container.\"\"\"

    import hashlib
    import json
    import os
    from http.server import HTTPServer, BaseHTTPRequestHandler

    SHARDS = {}  # (entity_id, shard_index) → bytes (hex-encoded for JSON)
    PORT = int(os.environ.get("LTP_NODE_PORT", "8321"))
    NODE_ID = os.environ.get("LTP_NODE_ID", "docker-node")
    REGION = os.environ.get("LTP_NODE_REGION", "unknown")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # suppress request logs

        def _respond(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def do_GET(self):
            if self.path == "/health":
                self._respond(200, {"status": "ok", "node_id": NODE_ID, "region": REGION,
                                     "shard_count": len(SHARDS)})
                return

            if self.path.startswith("/shard/"):
                parts = self.path.split("/")
                if len(parts) >= 4:
                    entity_id = parts[2]
                    shard_index = int(parts[3])
                    key = (entity_id, shard_index)
                    if key in SHARDS:
                        self._respond(200, {"data": SHARDS[key]})
                        return
                self._respond(404, {"error": "shard not found"})
                return

            self._respond(404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/shard":
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length))
                entity_id = body["entity_id"]
                shard_index = body["shard_index"]
                data_hex = body["data"]
                SHARDS[(entity_id, shard_index)] = data_hex
                self._respond(200, {"stored": True})
                return

            if self.path == "/audit":
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length))
                entity_id = body["entity_id"]
                shard_index = body["shard_index"]
                nonce_hex = body["nonce"]
                key = (entity_id, shard_index)
                if key not in SHARDS:
                    self._respond(404, {"error": "shard not found"})
                    return
                ct = bytes.fromhex(SHARDS[key])
                nonce = bytes.fromhex(nonce_hex)
                digest = hashlib.blake2b(ct + nonce, digest_size=32).hexdigest()
                self._respond(200, {"proof": "blake2b:" + digest})
                return

            self._respond(404, {"error": "not found"})

    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
""")


@dataclass
class DockerNode:
    """
    Represents a Docker container running an LTP shard storage node.
    """

    node_id: str
    region: str
    container_id: str = ""
    host: str = "127.0.0.1"
    port: int = CONTAINER_PORT
    network_name: str = ""
    _running: bool = False

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def running(self) -> bool:
        return self._running

    def health_check(self) -> dict | None:
        """Check if the container node is healthy."""
        try:
            import urllib.request

            url = f"{self.base_url}/health"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    def store_shard(self, entity_id: str, shard_index: int, data: bytes) -> bool:
        """Store a shard on the Docker node via HTTP."""
        try:
            import urllib.request

            payload = json.dumps(
                {
                    "entity_id": entity_id,
                    "shard_index": shard_index,
                    "data": data.hex(),
                }
            ).encode()
            req = urllib.request.Request(
                f"{self.base_url}/shard",
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                return result.get("stored", False)
        except Exception:
            return False

    def fetch_shard(self, entity_id: str, shard_index: int) -> bytes | None:
        """Fetch a shard from the Docker node via HTTP."""
        try:
            import urllib.request

            url = f"{self.base_url}/shard/{entity_id}/{shard_index}"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                return bytes.fromhex(result["data"])
        except Exception:
            return None

    def audit(self, entity_id: str, shard_index: int, nonce: bytes) -> str | None:
        """Send an audit challenge to the Docker node."""
        try:
            import urllib.request

            payload = json.dumps(
                {
                    "entity_id": entity_id,
                    "shard_index": shard_index,
                    "nonce": nonce.hex(),
                }
            ).encode()
            req = urllib.request.Request(
                f"{self.base_url}/audit",
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                return result.get("proof")
        except Exception:
            return None


class DockerNodeManager:
    """
    Manages Docker containers for large-scale LTP simulations.

    Creates isolated Docker networks per region and applies network
    constraints (latency, bandwidth, packet loss) using tc/netem
    when available.
    """

    def __init__(self, network_prefix: str = "ltp-sim") -> None:
        if not _docker_available:
            raise ImportError("Docker SDK not installed. Install with: pip install docker")
        self._client = docker.from_env()
        self._network_prefix = network_prefix
        self._nodes: dict[str, DockerNode] = {}
        self._containers: dict[str, object] = {}  # container_id → Container
        self._networks: dict[str, object] = {}  # region → Network
        self._next_port = CONTAINER_PORT

    def _get_or_create_network(self, region: str) -> object:
        """Get or create a Docker network for a region."""
        if region in self._networks:
            return self._networks[region]
        net_name = f"{self._network_prefix}-{region}"
        network = self._client.networks.create(
            net_name,
            driver="bridge",
            labels={"ltp-sim-region": region},
        )
        self._networks[region] = network
        return network

    def create_node(self, node_id: str, region: str) -> DockerNode:
        """
        Spin up a Docker container running an LTP shard storage node.

        Returns a DockerNode handle for interacting with the container.
        """
        network = self._get_or_create_network(region)
        port = self._next_port
        self._next_port += 1

        container = self._client.containers.run(
            CONTAINER_IMAGE,
            command=["python3", "-c", NODE_SERVER_SCRIPT],
            detach=True,
            ports={f"{CONTAINER_PORT}/tcp": port},
            environment={
                "LTP_NODE_ID": node_id,
                "LTP_NODE_REGION": region,
                "LTP_NODE_PORT": str(CONTAINER_PORT),
            },
            labels={
                "ltp-sim-node": node_id,
                "ltp-sim-region": region,
            },
            name=f"{self._network_prefix}-{node_id}",
            remove=True,
        )

        # Attach to region network
        network.connect(container)

        docker_node = DockerNode(
            node_id=node_id,
            region=region,
            container_id=container.id,
            host="127.0.0.1",
            port=port,
            network_name=network.name,
        )
        docker_node._running = True
        self._nodes[node_id] = docker_node
        self._containers[container.id] = container

        return docker_node

    def wait_for_healthy(self, node_id: str, timeout_s: float = 30.0) -> bool:
        """Wait until a Docker node passes health check."""
        node = self._nodes.get(node_id)
        if not node:
            return False
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            health = node.health_check()
            if health and health.get("status") == "ok":
                return True
            time.sleep(0.5)
        return False

    def stop_node(self, node_id: str) -> None:
        """Stop and remove a Docker container node."""
        node = self._nodes.get(node_id)
        if not node:
            return
        container = self._containers.get(node.container_id)
        if container:
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            del self._containers[node.container_id]
        node._running = False

    def stop_all(self) -> None:
        """Stop all Docker container nodes and remove networks."""
        for node_id in list(self._nodes.keys()):
            self.stop_node(node_id)

        for network in self._networks.values():
            try:
                network.remove()
            except Exception:
                pass
        self._networks.clear()
        self._nodes.clear()

    def apply_network_delay(self, node_id: str, delay_ms: int, jitter_ms: int = 0) -> bool:
        """
        Apply network delay to a container using tc/netem.

        Requires the container to have NET_ADMIN capability.
        """
        node = self._nodes.get(node_id)
        if not node:
            return False
        container = self._containers.get(node.container_id)
        if not container:
            return False
        try:
            cmd = f"tc qdisc add dev eth0 root netem delay {delay_ms}ms"
            if jitter_ms > 0:
                cmd += f" {jitter_ms}ms"
            container.exec_run(cmd)
            return True
        except Exception:
            return False

    @property
    def nodes(self) -> dict[str, DockerNode]:
        return dict(self._nodes)

    @property
    def running_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.running)
