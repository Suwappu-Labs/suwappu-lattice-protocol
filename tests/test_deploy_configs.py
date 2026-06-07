"""
Deployment configuration validation tests.

Validates that Dockerfile, Helm values, and K8s manifests are
structurally correct and parseable.
"""

from __future__ import annotations

import os

import pytest
import yaml

DEPLOY_DIR = os.path.join(os.path.dirname(__file__), "..", "deploy")


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


class TestDockerfile:
    def test_dockerfile_exists(self):
        path = os.path.join(DEPLOY_DIR, "Dockerfile")
        assert os.path.isfile(path)

    def test_dockerfile_has_multi_stage(self):
        path = os.path.join(DEPLOY_DIR, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "AS builder" in content
        assert "AS runtime" in content

    def test_dockerfile_has_healthcheck(self):
        path = os.path.join(DEPLOY_DIR, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "HEALTHCHECK" in content

    def test_dockerfile_runs_as_non_root(self):
        path = os.path.join(DEPLOY_DIR, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "USER etp" in content


# ---------------------------------------------------------------------------
# Helm Values
# ---------------------------------------------------------------------------


class TestHelmValues:
    def test_values_yaml_parseable(self):
        path = os.path.join(DEPLOY_DIR, "helm", "values.yaml")
        with open(path) as f:
            values = yaml.safe_load(f)
        assert isinstance(values, dict)

    def test_values_has_required_services(self):
        path = os.path.join(DEPLOY_DIR, "helm", "values.yaml")
        with open(path) as f:
            values = yaml.safe_load(f)
        assert "apiGateway" in values
        assert "protocolService" in values
        assert "logService" in values
        assert "shardNode" in values

    def test_values_has_anchor_config(self):
        path = os.path.join(DEPLOY_DIR, "helm", "values.yaml")
        with open(path) as f:
            values = yaml.safe_load(f)
        assert "anchor" in values
        assert values["anchor"]["enabled"] is True
        chains = values["anchor"]["chains"]
        chain_ids = {c["chainId"] for c in chains}
        assert 103115120 in chain_ids  # SUWAPPU Testnet
        assert 84532 in chain_ids  # Base Sepolia


# ---------------------------------------------------------------------------
# K8s Manifests
# ---------------------------------------------------------------------------


class TestK8sManifests:
    def test_namespace_yaml_valid(self):
        path = os.path.join(DEPLOY_DIR, "k8s", "namespace.yaml")
        with open(path) as f:
            doc = yaml.safe_load(f)
        assert doc["kind"] == "Namespace"
        assert doc["metadata"]["name"] == "etp"

    def test_log_service_is_statefulset(self):
        path = os.path.join(DEPLOY_DIR, "k8s", "log-service.yaml")
        with open(path) as f:
            doc = yaml.safe_load(f)
        assert doc["kind"] == "StatefulSet"
        assert doc["metadata"]["namespace"] == "etp"
        assert doc["spec"]["replicas"] == 1

    def test_api_gateway_is_deployment(self):
        path = os.path.join(DEPLOY_DIR, "k8s", "api-gateway.yaml")
        with open(path) as f:
            docs = list(yaml.safe_load_all(f))
        deployment = docs[0]
        assert deployment["kind"] == "Deployment"
        assert deployment["spec"]["replicas"] == 3
