"""FedRAMP High readiness evidence and deployment-profile gates."""

from __future__ import annotations

import json
from pathlib import Path

from deploy import preflight_gateway as preflight
from src.ltp.compliance import (
    AuditEvent,
    AuditEventType,
    ComplianceConfig,
    ComplianceFramework,
    CryptoProviderMode,
    HSMConfig,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _clear_preflight_env(monkeypatch) -> None:
    names = {
        "ETP_DEPLOYMENT_PROFILE",
        "ETP_REQUIRE_REAL_CRYPTO",
        "ETP_GATEWAY_VM_SOURCE_CHAIN_ID",
        "ETP_GATEWAY_VM_SOURCE_RPC_URL",
        "ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT",
        "ETP_GATEWAY_VM_DEST_CHAIN_ID",
        "ETP_GATEWAY_VM_DEST_RPC_URL",
        "ETP_GATEWAY_VM_DEST_REGISTRY",
        "ETP_GATEWAY_VM_OPERATOR_KEY",
        "ETP_GATEWAY_VM_OPERATOR_KMS_KEY_ID",
        "ETP_ANCHOR_OPERATOR_KEY",
        "ETP_ANCHOR_OPERATOR_KMS_KEY_ID",
        "OPERATOR_KEY",
        "ETP_KMS_BACKEND",
        "ETP_KMS_REGION",
        "ETP_KMS_KEY_ARN",
        "ETP_HSM_PROVIDER",
        "ETP_HSM_KEY_ID",
        "ETP_HSM_SLOT_LABEL",
        "ETP_HSM_PKCS11_URI",
        "ETP_TLS_ENABLED",
        "ETP_TLS_REQUIRE_CLIENT_CERT",
        "ETP_TLS_CERT_PATH",
        "ETP_TLS_KEY_PATH",
        "ETP_TLS_CA_PATH",
        "ETP_BRIDGE_OPERATOR_ZK_MODE",
        "ETP_GATEWAY_VM_PROVER_MODE",
        "ETP_GATEWAY_VM_CHALLENGE_MODE",
        "ETP_ZK_PROVER_MODE",
        "SP1_PROVE_MODE",
        "RISC0_PROVE_MODE",
        "ETP_SIEM_EXPORT_URL",
        "ETP_AUDIT_SIEM_SINK",
        "ETP_AUDIT_SIEM_ENDPOINT",
    }
    for name in names:
        monkeypatch.delenv(name, raising=False)


def test_fedramp_preflight_rejects_insecure_static_config(monkeypatch):
    _clear_preflight_env(monkeypatch)
    monkeypatch.setenv("ETP_DEPLOYMENT_PROFILE", "fedramp-high")
    monkeypatch.setenv("ETP_REQUIRE_REAL_CRYPTO", "false")
    monkeypatch.setenv("ETP_GATEWAY_VM_SOURCE_RPC_URL", "http://localhost:8545")
    monkeypatch.setenv("ETP_GATEWAY_VM_DEST_RPC_URL", "https://base-sepolia.example")
    monkeypatch.setenv("ETP_GATEWAY_VM_SOURCE_CHAIN_ID", "84532")
    monkeypatch.setenv("ETP_GATEWAY_VM_DEST_CHAIN_ID", "103115120")
    monkeypatch.setenv("ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT", "0x" + "1" * 40)
    monkeypatch.setenv("ETP_GATEWAY_VM_DEST_REGISTRY", "0x" + "2" * 40)
    monkeypatch.setenv("ETP_GATEWAY_VM_OPERATOR_KEY", "0x" + "a" * 64)
    monkeypatch.setenv("ETP_KMS_BACKEND", "memory")
    monkeypatch.setenv("ETP_TLS_ENABLED", "false")
    monkeypatch.setenv("ETP_TLS_REQUIRE_CLIENT_CERT", "false")
    monkeypatch.setenv("ETP_BRIDGE_OPERATOR_ZK_MODE", "mock")

    assert preflight.check_required_env_vars()[0] is True
    checks = [
        preflight.check_fedramp_real_crypto(),
        preflight.check_fedramp_no_plaintext_operator_keys(),
        preflight.check_fedramp_key_management_config(),
        preflight.check_fedramp_mtls_config(),
        preflight.check_fedramp_siem_export(),
        preflight.check_fedramp_prover_modes(),
        preflight.check_fedramp_production_networks(
            "http://localhost:8545",
            "https://base-sepolia.example",
        ),
    ]
    assert all(passed is False for passed, _ in checks)


def test_fedramp_preflight_accepts_secure_static_config(monkeypatch):
    _clear_preflight_env(monkeypatch)
    monkeypatch.setenv("ETP_DEPLOYMENT_PROFILE", "fedramp-high")
    monkeypatch.setenv("ETP_REQUIRE_REAL_CRYPTO", "true")
    monkeypatch.setenv("ETP_GATEWAY_VM_SOURCE_CHAIN_ID", "1")
    monkeypatch.setenv("ETP_GATEWAY_VM_DEST_CHAIN_ID", "42161")
    monkeypatch.setenv("ETP_GATEWAY_VM_SOURCE_RPC_URL", "https://rpc.ethereum-mainnet.internal")
    monkeypatch.setenv("ETP_GATEWAY_VM_DEST_RPC_URL", "https://rpc.suwappu-prod.internal")
    monkeypatch.setenv("ETP_GATEWAY_VM_SOURCE_BRIDGE_CONTRACT", "0x" + "1" * 40)
    monkeypatch.setenv("ETP_GATEWAY_VM_DEST_REGISTRY", "0x" + "2" * 40)
    monkeypatch.setenv("ETP_GATEWAY_VM_OPERATOR_KMS_KEY_ID", "alias/ltp-gateway")
    monkeypatch.setenv("ETP_KMS_BACKEND", "aws")
    monkeypatch.setenv("ETP_KMS_KEY_ARN", "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/abcd")
    monkeypatch.setenv("ETP_TLS_ENABLED", "true")
    monkeypatch.setenv("ETP_TLS_REQUIRE_CLIENT_CERT", "true")
    monkeypatch.setenv("ETP_TLS_CERT_PATH", "/etc/ltp/tls/tls.crt")
    monkeypatch.setenv("ETP_TLS_KEY_PATH", "/etc/ltp/tls/tls.key")
    monkeypatch.setenv("ETP_TLS_CA_PATH", "/etc/ltp/tls/ca.crt")
    monkeypatch.setenv("ETP_BRIDGE_OPERATOR_ZK_MODE", "stark")
    monkeypatch.setenv("ETP_SIEM_EXPORT_URL", "https://siem.ingest.internal")

    checks = [
        preflight.check_required_env_vars(),
        preflight.check_fedramp_real_crypto(),
        preflight.check_fedramp_no_plaintext_operator_keys(),
        preflight.check_fedramp_key_management_config(),
        preflight.check_fedramp_mtls_config(),
        preflight.check_fedramp_siem_export(),
        preflight.check_fedramp_prover_modes(),
        preflight.check_fedramp_production_networks(
            "https://rpc.ethereum-mainnet.internal",
            "https://rpc.suwappu-prod.internal",
        ),
        preflight.check_fedramp_contract_addresses("0x" + "1" * 40, "0x" + "2" * 40),
    ]
    assert all(passed is True for passed, _ in checks)


def test_audit_event_schema_has_fedramp_required_fields_and_event_types():
    event = AuditEvent(
        event_type=AuditEventType.PREFLIGHT_FAILURE,
        actor_id="preflight",
        action="reject_insecure_config",
        outcome="failure",
        component="deploy.preflight_gateway",
        source="gateway-preflight",
        correlation_id="release-2026-05-14",
        control_ids=["CM-6", "SC-12", "AU-2"],
        details={"profile": "fedramp-high"},
    )
    payload = event.to_dict()
    required = {
        "event_id",
        "schema_version",
        "event_type",
        "actor_id",
        "action",
        "timestamp",
        "outcome",
        "component",
        "source",
        "control_ids",
        "details",
    }
    assert required.issubset(payload)
    assert payload["schema_version"] == "ltp.audit.v1"
    assert payload["control_ids"] == ["CM-6", "SC-12", "AU-2"]

    required_event_types = {
        AuditEventType.AUTHN_DECISION,
        AuditEventType.AUTHZ_DECISION,
        AuditEventType.LATTICE_KEY_ISSUED,
        AuditEventType.LATTICE_KEY_MATERIALIZED,
        AuditEventType.ANCHOR_SUBMITTED,
        AuditEventType.ANCHOR_VERIFIED,
        AuditEventType.DKG_EVENT,
        AuditEventType.THRESHOLD_SIGNING_QUORUM,
        AuditEventType.KMS_OPERATION,
        AuditEventType.HSM_OPERATION,
        AuditEventType.GOVERNANCE_ACTION,
        AuditEventType.CONFIG_CHANGED,
        AuditEventType.PREFLIGHT_FAILURE,
        AuditEventType.CROSS_REPO_SYNC_FAILURE,
    }
    assert required_event_types.issubset(set(AuditEventType))


def test_fedramp_high_compliance_config_requires_hsm_siem_and_rotation():
    invalid = ComplianceConfig(
        frameworks={ComplianceFramework.FEDRAMP_HIGH},
        crypto_mode=CryptoProviderMode.FIPS,
        enable_rbac=True,
        enable_audit_logging=True,
    )
    valid, violations = invalid.validate()
    assert valid is False
    assert any("key rotation" in v for v in violations)
    assert any("KMS/HSM" in v for v in violations)
    assert any("SIEM" in v for v in violations)

    ready = ComplianceConfig(
        frameworks={ComplianceFramework.FEDRAMP_HIGH},
        crypto_mode=CryptoProviderMode.FIPS,
        enable_rbac=True,
        enable_audit_logging=True,
        enable_key_rotation=True,
        hsm_config=HSMConfig(provider="pkcs11", pkcs11_slot=1),
        siem_export_enabled=True,
        siem_destination="https://siem.ingest.internal",
    )
    valid, violations = ready.validate()
    assert valid is True
    assert violations == []


def test_evidence_manifest_has_existing_paths_and_commands():
    manifest_path = REPO_ROOT / "docs/compliance/fedramp-high/evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())

    assert manifest["deployment_profile"] == "fedramp-high"
    assert {
        "suwappu-lattice-protocol",
        "suwappu-dag",
        "suwappu-db",
    }.issubset(set(manifest["required_release_repositories"]))

    for entry in manifest["evidence"]:
        assert entry["control_ids"], entry["id"]
        assert entry["owner"], entry["id"]
        assert entry["status"], entry["id"]
        assert entry["test_command"], entry["id"]
        assert (REPO_ROOT / entry["evidence_path"]).exists(), entry["evidence_path"]


def test_suwappu_integration_doc_preserves_cross_repo_boundaries():
    doc = (REPO_ROOT / "docs/design-decisions/SUWAPPU_DAG_DB_INTEGRATION.md").read_text()
    lower = doc.lower()
    assert "assessment boundary" in lower
    assert "`suwappu-dag` provides ordering" in doc
    assert "`suwappu-db` provides state mutation" in doc
    assert "cannot mutate SUWAPPU-DB state" in doc
    assert "exact commits or tags" in doc


def test_release_evidence_requires_exact_cross_repo_commits():
    doc = (REPO_ROOT / "docs/compliance/fedramp-high/release-evidence.md").read_text()
    assert "suwappu-lattice-protocol commit/tag" in doc
    assert "suwappu-dag commit/tag" in doc
    assert "suwappu-db commit/tag" in doc
    assert "SBOM" in doc
    assert "Semgrep" in doc
    assert "Provenance" in doc or "provenance" in doc
