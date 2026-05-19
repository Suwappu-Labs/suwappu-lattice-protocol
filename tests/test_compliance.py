"""
Tests for the institutional compliance framework and security hardening features.

Covers:
  Part 1 (compliance): FIPS CryptoProvider, RBAC, GeoFencing, AuditLogger, KeyRotation,
        GDPR Deletion, SIEM Export, HSM Interface, ComplianceConfig.
  Part 2 (security hardening):
    1. SecurityProfile: configurable Level 3 / Level 5 parameter sets
    2. HashFunction: pluggable BLAKE2b-256, SHA-384, SHA-512
    3. HSMBackend / SoftwareHSM: key management interface for regulated environments
    4. End-to-end: full protocol under Level 5 / SHA-384 / HSM
"""

import json
import os

import pytest

from src.ltp.commitment import CommitmentNetwork
from src.ltp.compliance import (
    AuditEvent,
    AuditEventType,
    ComplianceAuditLogger,
    ComplianceConfig,
    ComplianceFramework,
    ComplianceRole,
    CryptoProviderMode,
    DeletionProof,
    DeletionRequest,
    FIPSCryptoProvider,
    GDPRDeletionManager,
    GeoFencePolicy,
    HSMConfig,
    Jurisdiction,
    KeyRotationManager,
    KeyRotationPolicy,
    KeyVersion,
    Permission,
    RBACManager,
    RBACPolicy,
    SIEMExporter,
    SIEMFormat,
)
from src.ltp.compliance import (
    SoftwareHSM as ComplianceSoftwareHSM,
)
from src.ltp.entity import Entity
from src.ltp.hsm import HSMBackend, SoftwareHSM
from src.ltp.keypair import KeyPair, SealedBox
from src.ltp.primitives import (
    AEAD,
    MLDSA,
    MLKEM,
    HashFunction,
    SecurityProfile,
    canonical_hash,
    canonical_hash_bytes,
    get_crypto_provider,
    get_security_profile,
    set_crypto_provider,
    set_security_profile,
)
from src.ltp.protocol import LTPProtocol

# ---------------------------------------------------------------------------
# Helpers: save/restore profile to avoid cross-test contamination
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def restore_default_profile():
    """Ensure every test starts and ends with the default Level 3 profile."""
    original = get_security_profile()
    set_security_profile(SecurityProfile.level3())
    yield
    set_security_profile(original)


# ============================================================================
# FIPS Crypto Provider
# ============================================================================


class TestFIPSCryptoProvider:
    """Tests for the FIPS 140-3 crypto provider."""

    def test_default_mode_uses_sha3(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        h = provider.hash(b"test")
        assert h.startswith("sha3-256:")
        assert not provider.is_fips_mode

    def test_default_mode_hash_bytes(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        raw = provider.hash_bytes(b"test")
        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_default_mode_aead_roundtrip(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        key = os.urandom(32)
        nonce = os.urandom(AEAD.NONCE_SIZE)
        plaintext = b"hello world"
        ct = provider.encrypt(key, plaintext, nonce)
        pt = provider.decrypt(key, ct, nonce)
        assert pt == plaintext

    def test_fips_mode_hash_uses_sha3(self):
        # FIPS mode should work even if OpenSSL FIPS isn't available
        # (it falls back to hashlib SHA3 which is always available)
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.FIPS
        provider._fips_available = True  # Skip check
        h = provider.hash(b"test")
        assert h.startswith("sha3-256:")

    def test_fips_mode_hash_bytes_sha3(self):
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.FIPS
        provider._fips_available = True
        raw = provider.hash_bytes(b"test")
        assert len(raw) == 32
        # Verify it's SHA3, not BLAKE2b
        import hashlib

        expected = hashlib.sha3_256(b"test").digest()
        assert raw == expected

    def test_algorithm_info_default(self):
        provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
        info = provider.algorithm_info()
        assert info["mode"] == "default (PoC)"
        assert "BLAKE2b" in info["hash"]

    def test_algorithm_info_fips(self):
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.FIPS
        provider._fips_available = True
        info = provider.algorithm_info()
        assert info["mode"] == "FIPS 140-3"
        assert "SHA3-256" in info["hash"]
        assert "AES-256-GCM" in info["aead"]

    def test_hybrid_mode_is_fips(self):
        provider = FIPSCryptoProvider.__new__(FIPSCryptoProvider)
        provider.mode = CryptoProviderMode.HYBRID
        provider._fips_available = True
        assert provider.is_fips_mode

    def test_set_crypto_provider_global(self):
        original = get_crypto_provider()
        try:
            provider = FIPSCryptoProvider(CryptoProviderMode.DEFAULT)
            set_crypto_provider(provider)
            assert get_crypto_provider() is provider
        finally:
            set_crypto_provider(original)


# ============================================================================
# RBAC
# ============================================================================


class TestRBAC:
    """Tests for Role-Based Access Control."""

    def test_create_policy_with_roles(self):
        mgr = RBACManager()
        policy = mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert ComplianceRole.SENDER in policy.roles
        assert policy.identity_id == "alice"

    def test_sender_can_commit(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert mgr.check_permission("alice", Permission.ENTITY_COMMIT)

    def test_sender_cannot_slash(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert not mgr.check_permission("alice", Permission.SLASH_EXECUTE)

    def test_receiver_can_materialize(self):
        mgr = RBACManager()
        mgr.create_policy("bob", {ComplianceRole.RECEIVER})
        assert mgr.check_permission("bob", Permission.ENTITY_MATERIALIZE)

    def test_auditor_can_read_logs(self):
        mgr = RBACManager()
        mgr.create_policy("charlie", {ComplianceRole.AUDITOR})
        assert mgr.check_permission("charlie", Permission.AUDIT_LOG_READ)
        assert mgr.check_permission("charlie", Permission.AUDIT_LOG_EXPORT)

    def test_auditor_cannot_commit(self):
        mgr = RBACManager()
        mgr.create_policy("charlie", {ComplianceRole.AUDITOR})
        assert not mgr.check_permission("charlie", Permission.ENTITY_COMMIT)

    def test_compliance_officer_can_gdpr_delete(self):
        mgr = RBACManager()
        mgr.create_policy("dave", {ComplianceRole.COMPLIANCE_OFFICER})
        assert mgr.check_permission("dave", Permission.GDPR_DELETE)
        assert mgr.check_permission("dave", Permission.COMPLIANCE_REPORT)

    def test_admin_has_all_permissions(self):
        mgr = RBACManager()
        mgr.create_policy("root", {ComplianceRole.ADMIN})
        for perm in Permission:
            assert mgr.check_permission("root", perm), f"Admin missing {perm}"

    def test_unknown_identity_denied(self):
        mgr = RBACManager()
        assert not mgr.check_permission("unknown", Permission.ENTITY_COMMIT)

    def test_require_permission_raises(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        with pytest.raises(PermissionError):
            mgr.require_permission("alice", Permission.SLASH_EXECUTE)

    def test_policy_expiration(self):
        mgr = RBACManager()
        mgr.create_policy("temp", {ComplianceRole.SENDER}, epoch=0, expires_epoch=100)
        assert mgr.check_permission("temp", Permission.ENTITY_COMMIT, current_epoch=50)
        assert not mgr.check_permission("temp", Permission.ENTITY_COMMIT, current_epoch=101)

    def test_revoke_policy(self):
        mgr = RBACManager()
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert mgr.check_permission("alice", Permission.ENTITY_COMMIT)
        mgr.revoke_policy("alice")
        assert not mgr.check_permission("alice", Permission.ENTITY_COMMIT)

    def test_denied_permissions_override(self):
        mgr = RBACManager()
        policy = mgr.create_policy("alice", {ComplianceRole.ADMIN})
        policy.denied_permissions.add(Permission.GDPR_DELETE)
        assert not mgr.check_permission("alice", Permission.GDPR_DELETE)
        # Other admin perms still work
        assert mgr.check_permission("alice", Permission.CONFIG_MODIFY)

    def test_list_identities_with_role(self):
        mgr = RBACManager()
        mgr.create_policy("a", {ComplianceRole.AUDITOR})
        mgr.create_policy("b", {ComplianceRole.AUDITOR})
        mgr.create_policy("c", {ComplianceRole.SENDER})
        auditors = mgr.list_identities_with_role(ComplianceRole.AUDITOR)
        assert set(auditors) == {"a", "b"}

    def test_rbac_with_audit_logger(self):
        logger = ComplianceAuditLogger()
        mgr = RBACManager()
        mgr.set_audit_logger(logger)
        mgr.create_policy("alice", {ComplianceRole.SENDER})
        assert logger.length >= 1


# ============================================================================
# Geo-Fencing
# ============================================================================


class TestGeoFencing:
    """Tests for jurisdiction-constrained shard placement."""

    def test_global_allows_all(self):
        policy = GeoFencePolicy()
        assert policy.is_region_allowed("us-east-1")
        assert policy.is_region_allowed("eu-west-1")
        assert policy.is_region_allowed("ap-southeast-1")

    def test_us_only_policy(self):
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US})
        assert policy.is_region_allowed("us-east-1")
        assert policy.is_region_allowed("us-west-2")
        assert not policy.is_region_allowed("eu-west-1")
        assert not policy.is_region_allowed("ap-southeast-1")

    def test_eu_only_policy(self):
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.EU})
        assert not policy.is_region_allowed("us-east-1")
        assert policy.is_region_allowed("eu-west-1")
        assert policy.is_region_allowed("europe-west1")

    def test_exclusion_overrides_global(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.GLOBAL},
            excluded_jurisdictions={Jurisdiction.EU},
        )
        assert policy.is_region_allowed("us-east-1")
        assert not policy.is_region_allowed("eu-west-1")

    def test_govcloud_mapping(self):
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US_GOVCLOUD})
        assert policy.is_region_allowed("us_gov-east-1")
        assert not policy.is_region_allowed("us-east-1")

    def test_filter_nodes(self):
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US})
        network = CommitmentNetwork()
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "eu-west-1")
        n3 = network.add_node("n3", "us-west-2")
        filtered = policy.filter_nodes(network.nodes)
        assert len(filtered) == 2
        assert n1 in filtered
        assert n3 in filtered
        assert n2 not in filtered

    def test_validate_placement(self):
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US})
        network = CommitmentNetwork()
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "eu-west-1")
        valid, violations = policy.validate_placement([n1])
        assert valid
        valid, violations = policy.validate_placement([n1, n2])
        assert not valid
        assert len(violations) == 1

    def test_cross_jurisdiction_requirement(self):
        policy = GeoFencePolicy(
            allowed_jurisdictions={Jurisdiction.US, Jurisdiction.EU},
            require_cross_jurisdiction=True,
            min_jurisdictions=2,
        )
        network = CommitmentNetwork()
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "us-west-2")
        # Both in US — fails cross-jurisdiction
        valid, violations = policy.validate_placement([n1, n2])
        assert not valid

    def test_geo_fence_on_commitment_network(self):
        """Geo-fence policy integrated with CommitmentNetwork._placement."""
        network = CommitmentNetwork()
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US})
        network.set_geo_fence_policy(policy)
        network.add_node("us1", "us-east-1")
        network.add_node("us2", "us-west-2")
        network.add_node("eu1", "eu-west-1")

        shards = [os.urandom(64) for _ in range(4)]
        network.distribute_encrypted_shards("test-entity", shards)

        # EU node should have zero shards
        eu_node = network.nodes[2]
        assert eu_node.shard_count == 0

    def test_geo_fence_raises_when_no_eligible_nodes(self):
        network = CommitmentNetwork()
        policy = GeoFencePolicy(allowed_jurisdictions={Jurisdiction.JP})
        network.set_geo_fence_policy(policy)
        network.add_node("us1", "us-east-1")
        with pytest.raises(ValueError, match="allowed jurisdictions"):
            network.distribute_encrypted_shards("test", [os.urandom(32)])


# ============================================================================
# Audit Logger
# ============================================================================


class TestComplianceAuditLogger:
    """Tests for the immutable audit log."""

    def test_log_event(self):
        logger = ComplianceAuditLogger()
        event = AuditEvent(
            event_type=AuditEventType.NODE_REGISTERED,
            actor_id="node-1",
            action="registered",
            epoch=1,
        )
        chain_hash = logger.log(event)
        assert chain_hash.startswith("sha3-256:")
        assert logger.length == 1

    def test_chain_integrity_valid(self):
        logger = ComplianceAuditLogger()
        for i in range(10):
            logger.log(
                AuditEvent(
                    event_type=AuditEventType.NODE_AUDITED,
                    actor_id="system",
                    action=f"audit-{i}",
                    epoch=i,
                )
            )
        valid, idx = logger.verify_chain_integrity()
        assert valid
        assert idx == 10

    def test_chain_integrity_detects_tampering(self):
        logger = ComplianceAuditLogger()
        for i in range(5):
            logger.log(
                AuditEvent(
                    event_type=AuditEventType.NODE_AUDITED,
                    actor_id="system",
                    action=f"audit-{i}",
                    epoch=i,
                )
            )
        # Tamper with chain hash
        logger._chain_hashes[2] = "sha3-256:tampered"
        valid, idx = logger.verify_chain_integrity()
        assert not valid
        assert idx == 2

    def test_query_by_event_type(self):
        logger = ComplianceAuditLogger()
        logger.log(
            AuditEvent(
                event_type=AuditEventType.NODE_REGISTERED,
                actor_id="n1",
                action="reg",
                epoch=1,
            )
        )
        logger.log(
            AuditEvent(
                event_type=AuditEventType.ACCESS_DENIED,
                actor_id="eve",
                action="denied",
                epoch=2,
            )
        )
        logger.log(
            AuditEvent(
                event_type=AuditEventType.NODE_REGISTERED,
                actor_id="n2",
                action="reg",
                epoch=3,
            )
        )
        results = logger.query(event_type=AuditEventType.NODE_REGISTERED)
        assert len(results) == 2

    def test_query_by_actor(self):
        logger = ComplianceAuditLogger()
        logger.log(
            AuditEvent(
                event_type=AuditEventType.ENTITY_COMMITTED,
                actor_id="alice",
                action="commit",
                epoch=1,
            )
        )
        logger.log(
            AuditEvent(
                event_type=AuditEventType.ENTITY_COMMITTED,
                actor_id="bob",
                action="commit",
                epoch=2,
            )
        )
        results = logger.query(actor_id="alice")
        assert len(results) == 1
        assert results[0].actor_id == "alice"

    def test_query_with_limit(self):
        logger = ComplianceAuditLogger()
        for i in range(20):
            logger.log(
                AuditEvent(
                    event_type=AuditEventType.SHARD_STORED,
                    actor_id="system",
                    action=f"store-{i}",
                    epoch=i,
                )
            )
        results = logger.query(limit=5)
        assert len(results) == 5

    def test_export_json(self):
        logger = ComplianceAuditLogger()
        logger.log(
            AuditEvent(
                event_type=AuditEventType.ENTITY_COMMITTED,
                actor_id="alice",
                action="commit",
                epoch=5,
            )
        )
        exported = logger.export_json(since_epoch=0)
        assert len(exported) == 1
        assert exported[0]["actor_id"] == "alice"

    def test_evict_expired(self):
        logger = ComplianceAuditLogger(retention_epochs=100)
        for i in range(10):
            logger.log(
                AuditEvent(
                    event_type=AuditEventType.SHARD_STORED,
                    actor_id="system",
                    action=f"store-{i}",
                    epoch=i,
                )
            )
        removed = logger.evict_expired(current_epoch=105)
        assert removed == 5  # epochs 0-4 should be evicted
        assert logger.length == 5

    def test_head_hash_changes(self):
        logger = ComplianceAuditLogger()
        h0 = logger.head_hash
        logger.log(
            AuditEvent(
                event_type=AuditEventType.NODE_REGISTERED,
                actor_id="n1",
                action="reg",
                epoch=1,
            )
        )
        h1 = logger.head_hash
        assert h0 != h1

    def test_audit_logger_on_commitment_network(self):
        """Audit logger integrated with CommitmentNetwork."""
        logger = ComplianceAuditLogger()
        network = CommitmentNetwork()
        network.set_audit_logger(logger)
        network.add_node("n1", "us-east-1")
        assert logger.length >= 1
        events = logger.query(event_type=AuditEventType.NODE_REGISTERED)
        assert len(events) == 1


# ============================================================================
# SIEM Export
# ============================================================================


class TestSIEMExporter:
    """Tests for SIEM-compatible audit event export."""

    def test_export_json(self):
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            actor_id="eve",
            action="unauthorized",
            epoch=1,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.JSON)
        parsed = json.loads(output)
        assert parsed["actor_id"] == "eve"
        assert parsed["event_type"] == "access.denied"

    def test_export_cef(self):
        event = AuditEvent(
            event_type=AuditEventType.NODE_EVICTED,
            actor_id="system",
            target_id="bad-node",
            action="evicted",
            epoch=1,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.CEF)
        assert output.startswith("CEF:0|LTP|")
        assert "act=evicted" in output
        assert "dst=bad-node" in output

    def test_export_json_ld(self):
        event = AuditEvent(
            event_type=AuditEventType.ENTITY_COMMITTED,
            actor_id="alice",
            target_id="entity-001",
            action="committed",
            epoch=5,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.JSON_LD)
        parsed = json.loads(output)
        assert parsed["@context"] == "https://ltp.network/compliance/v1"
        assert parsed["@type"] == "AuditEvent"
        assert parsed["actor"]["id"] == "alice"

    def test_export_multiple_events(self):
        events = [
            AuditEvent(
                event_type=AuditEventType.SHARD_STORED,
                actor_id="n1",
                action=f"store-{i}",
                epoch=i,
            )
            for i in range(3)
        ]
        output = SIEMExporter.export_events(events, SIEMFormat.JSON)
        parsed = json.loads(output)
        assert len(parsed) == 3

    def test_cef_severity_mapping(self):
        # Security violation should be high severity
        event = AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            actor_id="attacker",
            action="exploit",
            epoch=1,
        )
        output = SIEMExporter.export_event(event, SIEMFormat.CEF)
        # Severity 9 for security violations
        assert "|9|" in output


# ============================================================================
# Key Rotation
# ============================================================================


class TestKeyRotation:
    """Tests for key rotation policy and manager."""

    def test_register_key(self):
        mgr = KeyRotationManager()
        kv = mgr.register_key("bob", "fp-abc", epoch=0)
        assert kv.version == 1
        assert kv.key_fingerprint == "fp-abc"
        assert kv.expires_epoch == 8760  # default max age

    def test_get_active_key(self):
        mgr = KeyRotationManager()
        mgr.register_key("bob", "fp-v1", epoch=0)
        mgr.register_key("bob", "fp-v2", epoch=100)
        active = mgr.get_active_key("bob")
        assert active.key_fingerprint == "fp-v2"

    def test_rotation_needed_at_expiry(self):
        mgr = KeyRotationManager(policy=KeyRotationPolicy(max_key_age_epochs=1000))
        mgr.register_key("bob", "fp-v1", epoch=0)
        needs, reason = mgr.check_rotation_needed("bob", current_epoch=1000)
        assert needs
        assert reason == "key_expired"

    def test_rotation_warning(self):
        mgr = KeyRotationManager(
            policy=KeyRotationPolicy(
                max_key_age_epochs=1000,
                rotation_warning_epochs=100,
            )
        )
        mgr.register_key("bob", "fp-v1", epoch=0)
        needs, reason = mgr.check_rotation_needed("bob", current_epoch=950)
        assert needs
        assert reason == "approaching_expiry"

    def test_no_rotation_needed(self):
        mgr = KeyRotationManager(
            policy=KeyRotationPolicy(
                max_key_age_epochs=1000,
                rotation_warning_epochs=100,
            )
        )
        mgr.register_key("bob", "fp-v1", epoch=0)
        needs, reason = mgr.check_rotation_needed("bob", current_epoch=500)
        assert not needs
        assert reason is None

    def test_rotation_needed_no_key(self):
        mgr = KeyRotationManager()
        needs, reason = mgr.check_rotation_needed("unknown", current_epoch=0)
        assert needs
        assert reason == "no_active_key"

    def test_revoke_key(self):
        mgr = KeyRotationManager()
        kv = mgr.register_key("bob", "fp-v1", epoch=0)
        result = mgr.revoke_key("bob", kv.version, epoch=100, reason="compromised")
        assert result
        assert kv.revoked
        assert kv.revoked_epoch == 100

    def test_max_versions_retained(self):
        mgr = KeyRotationManager(policy=KeyRotationPolicy(max_versions_retained=3))
        for i in range(5):
            mgr.register_key("bob", f"fp-v{i}", epoch=i * 100)
        history = mgr.get_key_history("bob")
        assert len(history) == 3

    def test_key_history_newest_first(self):
        mgr = KeyRotationManager()
        mgr.register_key("bob", "fp-old", epoch=0)
        mgr.register_key("bob", "fp-new", epoch=100)
        history = mgr.get_key_history("bob")
        assert history[0].key_fingerprint == "fp-new"

    def test_rotation_with_audit_logger(self):
        logger = ComplianceAuditLogger()
        mgr = KeyRotationManager(audit_logger=logger)
        mgr.register_key("bob", "fp-v1", epoch=0)
        assert logger.length >= 1
        events = logger.query(event_type=AuditEventType.KEY_GENERATED)
        assert len(events) == 1


# ============================================================================
# GDPR Deletion
# ============================================================================


class TestGDPRDeletion:
    """Tests for GDPR right-to-erasure with deletion proofs."""

    def _setup_network_with_entity(self):
        """Helper: create network with an entity's shards distributed."""
        network = CommitmentNetwork()
        n1 = network.add_node("node-a", "eu-west-1")
        n2 = network.add_node("node-b", "eu-central-1")
        shards = [os.urandom(128) for _ in range(4)]
        network.distribute_encrypted_shards("entity-to-delete", shards)
        return network, [n1, n2]

    def test_submit_deletion_request(self):
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-1", "subject-1", epoch=100)
        assert req.status == "pending"
        assert req.entity_id == "entity-1"

    def test_execute_deletion_removes_shards(self):
        network, nodes = self._setup_network_with_entity()
        total_before = sum(n.shard_count for n in nodes)
        assert total_before > 0

        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof = gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        total_after = sum(n.shard_count for n in nodes)
        assert total_after == 0
        assert req.status == "completed"

    def test_deletion_produces_proof(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof = gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        assert proof is not None
        assert proof.entity_id == "entity-to-delete"
        assert proof.shard_count_destroyed > 0
        assert proof.node_count_participating > 0
        assert proof.destruction_merkle_root.startswith("sha3-256:")
        assert len(proof.node_attestations) > 0
        assert proof.proof_hash.startswith("sha3-256:")

    def test_deletion_proof_retrievable(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        proof = gdpr.get_proof("entity-to-delete")
        assert proof is not None

    def test_deletion_proof_to_dict(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof = gdpr.execute_deletion(req.request_id, nodes, epoch=101)
        d = proof.to_dict()
        assert "entity_id" in d
        assert "destruction_merkle_root" in d
        assert "proof_hash" in d

    def test_double_deletion_idempotent(self):
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager()
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        proof1 = gdpr.execute_deletion(req.request_id, nodes, epoch=101)
        proof2 = gdpr.execute_deletion(req.request_id, nodes, epoch=102)
        # Second call returns cached proof
        assert proof2 is proof1

    def test_list_pending_requests(self):
        gdpr = GDPRDeletionManager()
        gdpr.submit_request("e1", "s1", epoch=1)
        gdpr.submit_request("e2", "s2", epoch=2)
        pending = gdpr.list_pending_requests()
        assert len(pending) == 2

    def test_deletion_with_audit_logger(self):
        logger = ComplianceAuditLogger()
        network, nodes = self._setup_network_with_entity()
        gdpr = GDPRDeletionManager(audit_logger=logger)
        req = gdpr.submit_request("entity-to-delete", "subject-1", epoch=100)
        gdpr.execute_deletion(req.request_id, nodes, epoch=101)

        deletion_events = logger.query(event_type=AuditEventType.GDPR_DELETION_COMPLETE)
        assert len(deletion_events) == 1

    def test_deletion_nonexistent_request(self):
        gdpr = GDPRDeletionManager()
        result = gdpr.execute_deletion("nonexistent", [], epoch=1)
        assert result is None


# ============================================================================
# HSM Interface (Compliance Module)
# ============================================================================


class TestComplianceSoftwareHSM:
    """Tests for the compliance module's software HSM implementation."""

    def test_generate_keypair(self):
        hsm = ComplianceSoftwareHSM()
        result = hsm.generate_keypair("test-key")
        assert "key_id" in result
        assert "public_key" in result
        assert result["label"] == "test-key"

    def test_sign(self):
        hsm = ComplianceSoftwareHSM()
        result = hsm.generate_keypair("sign-key")
        sig = hsm.sign(result["key_id"], b"test message")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_destroy_key(self):
        hsm = ComplianceSoftwareHSM()
        result = hsm.generate_keypair("temp-key")
        assert len(hsm.list_keys()) == 1
        destroyed = hsm.destroy_key(result["key_id"])
        assert destroyed
        assert len(hsm.list_keys()) == 0

    def test_destroy_nonexistent_key(self):
        hsm = ComplianceSoftwareHSM()
        assert not hsm.destroy_key("nonexistent")

    def test_list_keys(self):
        hsm = ComplianceSoftwareHSM()
        hsm.generate_keypair("key-1")
        hsm.generate_keypair("key-2")
        keys = hsm.list_keys()
        assert len(keys) == 2

    def test_export_public_key(self):
        hsm = ComplianceSoftwareHSM()
        result = hsm.generate_keypair("export-key")
        pub = hsm.export_public_key(result["key_id"])
        assert isinstance(pub, bytes)
        assert len(pub) > 0

    def test_sign_nonexistent_key_raises(self):
        hsm = ComplianceSoftwareHSM()
        with pytest.raises(KeyError):
            hsm.sign("nonexistent", b"test")

    def test_hsm_config(self):
        config = HSMConfig(provider="pkcs11", pkcs11_slot=1)
        hsm = ComplianceSoftwareHSM(config)
        assert hsm.config.provider == "pkcs11"

    def test_key_label_prefix(self):
        config = HSMConfig(key_label_prefix="prod-")
        hsm = ComplianceSoftwareHSM(config)
        result = hsm.generate_keypair("my-key")
        assert result["key_id"].startswith("prod-")


# ============================================================================
# Compliance Configuration
# ============================================================================


class TestComplianceConfig:
    """Tests for unified compliance configuration validation."""

    def test_fedramp_requires_fips(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.FEDRAMP_MODERATE},
            crypto_mode=CryptoProviderMode.DEFAULT,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("FIPS" in v for v in violations)

    def test_fedramp_requires_rbac(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.FEDRAMP_MODERATE},
            crypto_mode=CryptoProviderMode.FIPS,
            enable_rbac=False,
            enable_audit_logging=True,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("RBAC" in v for v in violations)

    def test_soc2_requires_key_rotation(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=False,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("key management" in v for v in violations)

    def test_soc2_valid_config(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
        )
        valid, violations = config.validate()
        assert valid
        assert len(violations) == 0

    def test_gdpr_requires_deletion(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.GDPR},
            enable_gdpr_deletion=False,
            enable_audit_logging=True,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("Art. 17" in v for v in violations)

    def test_gdpr_valid_config(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.GDPR},
            enable_gdpr_deletion=True,
            enable_audit_logging=True,
        )
        valid, violations = config.validate()
        assert valid

    def test_pci_dss_requires_fips_and_rotation(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.PCI_DSS},
            crypto_mode=CryptoProviderMode.DEFAULT,
            enable_key_rotation=False,
        )
        valid, violations = config.validate()
        assert not valid
        assert len(violations) >= 2

    def test_hipaa_requires_rbac_and_audit(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.HIPAA},
            enable_rbac=False,
            enable_audit_logging=False,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("164.312(a)" in v for v in violations)

    def test_basel_requires_hsm(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.BASEL_III},
            enable_rbac=True,
            hsm_config=None,
        )
        valid, violations = config.validate()
        assert not valid
        assert any("hardware" in v.lower() for v in violations)

    def test_occ_custody_requirements(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.OCC_CUSTODY},
            enable_rbac=False,
        )
        valid, violations = config.validate()
        assert not valid

    def test_controls_summary(self):
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
        )
        summary = config.controls_summary()
        assert summary["rbac_enabled"] is True
        assert summary["audit_logging_enabled"] is True
        assert "soc2-type2" in summary["target_frameworks"]

    def test_empty_frameworks_always_valid(self):
        config = ComplianceConfig()
        valid, violations = config.validate()
        assert valid

    def test_multiple_frameworks(self):
        config = ComplianceConfig(
            frameworks={
                ComplianceFramework.SOC2_TYPE2,
                ComplianceFramework.GDPR,
            },
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
            enable_gdpr_deletion=True,
        )
        valid, violations = config.validate()
        assert valid


# ============================================================================
# Integration: Audit Logger + Commitment Network
# ============================================================================


class TestComplianceIntegration:
    """Integration tests for compliance features with the commitment network."""

    def test_full_audit_trail(self):
        """End-to-end: nodes, shards, eviction all logged."""
        logger = ComplianceAuditLogger()
        network = CommitmentNetwork()
        network.set_audit_logger(logger)

        # Add nodes
        n1 = network.add_node("n1", "us-east-1")
        n2 = network.add_node("n2", "us-west-2")

        # Distribute shards
        shards = [os.urandom(64) for _ in range(4)]
        network.distribute_encrypted_shards("entity-1", shards)

        # Evict a node
        network.evict_node(n1)

        # Verify audit trail
        assert logger.length >= 4  # 2 registrations + 1 distribution + 1 eviction
        valid, _ = logger.verify_chain_integrity()
        assert valid

        # Check specific events
        reg_events = logger.query(event_type=AuditEventType.NODE_REGISTERED)
        assert len(reg_events) == 2
        evict_events = logger.query(event_type=AuditEventType.NODE_EVICTED)
        assert len(evict_events) == 1

    def test_geo_fence_with_audit(self):
        """Geo-fence + audit logger together."""
        logger = ComplianceAuditLogger()
        network = CommitmentNetwork()
        network.set_audit_logger(logger)
        network.set_geo_fence_policy(GeoFencePolicy(allowed_jurisdictions={Jurisdiction.US}))

        network.add_node("us1", "us-east-1")
        network.add_node("eu1", "eu-west-1")

        shards = [os.urandom(32) for _ in range(2)]
        network.distribute_encrypted_shards("entity-1", shards)

        # EU node should have no shards
        assert network.nodes[1].shard_count == 0
        # All events logged
        assert logger.length >= 3

    def test_soc2_compliant_setup(self):
        """Verify a SOC 2-compliant deployment configuration."""
        config = ComplianceConfig(
            frameworks={ComplianceFramework.SOC2_TYPE2},
            enable_rbac=True,
            enable_audit_logging=True,
            enable_key_rotation=True,
        )
        valid, violations = config.validate()
        assert valid

        # Set up all components
        logger = ComplianceAuditLogger(retention_epochs=26_280)
        rbac = RBACManager()
        rbac.set_audit_logger(logger)
        rotation = KeyRotationManager(
            policy=KeyRotationPolicy(max_key_age_epochs=8760),
            audit_logger=logger,
        )

        # Create policies
        rbac.create_policy("operator-1", {ComplianceRole.OPERATOR}, epoch=0)
        rbac.create_policy("auditor-1", {ComplianceRole.AUDITOR}, epoch=0)

        # Register keys
        rotation.register_key("operator-1", "fp-op1-v1", epoch=0)

        # Verify audit trail captures everything
        assert logger.length >= 3  # 2 policies + 1 key
        valid, _ = logger.verify_chain_integrity()
        assert valid


# ===========================================================================
# 1. SECURITY PROFILE (§7.2)
# ===========================================================================


class TestSecurityProfileConstruction:
    def test_level3_defaults(self):
        p = SecurityProfile.level3()
        assert p.level == 3
        assert p.canonical_hash_fn == HashFunction.SHA3_256
        assert p.kem_ek_size == 1184
        assert p.kem_dk_size == 2400
        assert p.kem_ct_size == 1088
        assert p.dsa_vk_size == 1952
        assert p.dsa_sk_size == 4032
        assert p.dsa_sig_size == 3309

    def test_level5_defaults(self):
        p = SecurityProfile.level5()
        assert p.level == 5
        assert p.canonical_hash_fn == HashFunction.SHA_384
        assert p.kem_ek_size == 1568
        assert p.kem_dk_size == 3168
        assert p.kem_ct_size == 1568
        assert p.dsa_vk_size == 2592
        assert p.dsa_sk_size == 4896
        assert p.dsa_sig_size == 4627

    def test_cnsa2_is_level5_sha384(self):
        p = SecurityProfile.cnsa2()
        assert p.level == 5
        assert p.canonical_hash_fn == HashFunction.SHA_384

    def test_invalid_level_raises(self):
        with pytest.raises(ValueError, match="must be 3 or 5"):
            SecurityProfile(level=4)

    def test_custom_hash_on_level3(self):
        p = SecurityProfile(level=3, canonical_hash=HashFunction.SHA_512)
        assert p.level == 3
        assert p.canonical_hash_fn == HashFunction.SHA_512

    def test_label_format(self):
        p = SecurityProfile.level3()
        assert p.label == "Level-3/sha3-256+blake3"
        p5 = SecurityProfile.cnsa2()
        assert p5.label == "Level-5/sha384+sha384"

    def test_repr(self):
        p = SecurityProfile.level3()
        r = repr(p)
        assert "level=3" in r
        assert "sha3-256" in r


class TestSecurityProfileActivation:
    def test_default_is_level3(self):
        p = get_security_profile()
        assert p.level == 3

    def test_set_returns_previous(self):
        prev = set_security_profile(SecurityProfile.level5())
        assert prev.level == 3
        current = get_security_profile()
        assert current.level == 5

    def test_mlkem_sizes_sync_on_level5(self):
        set_security_profile(SecurityProfile.level5())
        assert MLKEM.EK_SIZE == 1568
        assert MLKEM.DK_SIZE == 3168
        assert MLKEM.CT_SIZE == 1568

    def test_mldsa_sizes_sync_on_level5(self):
        set_security_profile(SecurityProfile.level5())
        assert MLDSA.VK_SIZE == 2592
        assert MLDSA.SK_SIZE == 4896
        assert MLDSA.SIG_SIZE == 4627

    def test_sizes_revert_on_level3(self):
        set_security_profile(SecurityProfile.level5())
        set_security_profile(SecurityProfile.level3())
        assert MLKEM.EK_SIZE == 1184
        assert MLDSA.VK_SIZE == 1952


class TestLevel5KeyGeneration:
    def test_kem_keygen_level5_sizes(self):
        set_security_profile(SecurityProfile.level5())
        ek, dk = MLKEM.keygen()
        assert len(ek) == 1568
        assert len(dk) == 3168

    def test_dsa_keygen_level5_sizes(self):
        set_security_profile(SecurityProfile.level5())
        vk, sk = MLDSA.keygen()
        assert len(vk) == 2592
        assert len(sk) == 4896

    def test_kem_encaps_level5_ciphertext_size(self):
        set_security_profile(SecurityProfile.level5())
        ek, dk = MLKEM.keygen()
        ss, ct = MLKEM.encaps(ek)
        assert len(ss) == 32
        assert len(ct) == 1568

    def test_dsa_sign_level5_signature_size(self):
        set_security_profile(SecurityProfile.level5())
        vk, sk = MLDSA.keygen()
        sig = MLDSA.sign(sk, b"test message")
        assert len(sig) == 4627

    def test_dsa_verify_level5(self):
        set_security_profile(SecurityProfile.level5())
        vk, sk = MLDSA.keygen()
        msg = b"compliance test"
        sig = MLDSA.sign(sk, msg)
        assert MLDSA.verify(vk, msg, sig) is True
        assert MLDSA.verify(vk, b"wrong message", sig) is False

    def test_keypair_generate_level5(self):
        set_security_profile(SecurityProfile.level5())
        kp = KeyPair.generate("level5-test")
        assert len(kp.ek) == 1568
        assert len(kp.dk) == 3168
        assert len(kp.vk) == 2592
        assert len(kp.sk) == 4896


class TestLevel5SealedBox:
    def test_seal_unseal_level5(self):
        set_security_profile(SecurityProfile.level5())
        kp = KeyPair.generate("seal-test")
        plaintext = b"secret data for Level 5"
        sealed = SealedBox.seal(plaintext, kp.ek)
        recovered = SealedBox.unseal(sealed, kp)
        assert recovered == plaintext

    def test_sealed_size_level5(self):
        set_security_profile(SecurityProfile.level5())
        kp = KeyPair.generate("size-test")
        sealed = SealedBox.seal(b"test", kp.ek)
        # Level 5: ct=1568 + nonce(dynamic) + payload + tag(dynamic)
        assert len(sealed) > MLKEM.CT_SIZE + AEAD.NONCE_SIZE + AEAD._tag_size()

    def test_wrong_key_fails_level5(self):
        set_security_profile(SecurityProfile.level5())
        alice = KeyPair.generate("alice-l5")
        bob = KeyPair.generate("bob-l5")
        sealed = SealedBox.seal(b"for alice", alice.ek)
        with pytest.raises(ValueError):
            SealedBox.unseal(sealed, bob)


# ===========================================================================
# 2. HASH FUNCTION (§7.1)
# ===========================================================================


class TestHashFunction:
    def test_sha3_256_prefix(self):
        h = canonical_hash(b"test")
        assert h.startswith("sha3-256:")

    def test_sha384_prefix(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_384))
        h = canonical_hash(b"test")
        assert h.startswith("sha384:")

    def test_sha512_prefix(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_512))
        h = canonical_hash(b"test")
        assert h.startswith("sha512:")

    def test_blake2b_bytes_size(self):
        raw = canonical_hash_bytes(b"test")
        assert len(raw) == 32

    def test_sha384_bytes_size(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_384))
        raw = canonical_hash_bytes(b"test")
        assert len(raw) == 48

    def test_sha512_bytes_size(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_512))
        raw = canonical_hash_bytes(b"test")
        assert len(raw) == 64

    def test_different_algos_different_hashes(self):
        data = b"comparison test"

        set_security_profile(SecurityProfile(level=3))
        h_sha3 = canonical_hash(data)

        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_384))
        h_sha384 = canonical_hash(data)

        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_512))
        h_sha512 = canonical_hash(data)

        assert h_sha3 != h_sha384
        assert h_sha384 != h_sha512
        assert h_sha3 != h_sha512

    def test_same_algo_deterministic(self):
        data = b"determinism test"
        h1 = canonical_hash(data)
        h2 = canonical_hash(data)
        assert h1 == h2

    def test_aead_works_with_sha384(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_384))
        key = b"k" * 32
        nonce = b"n" * AEAD.NONCE_SIZE
        plaintext = b"encrypt me with sha384 hash"
        ct = AEAD.encrypt(key, plaintext, nonce)
        pt = AEAD.decrypt(key, ct, nonce)
        assert pt == plaintext

    def test_aead_works_with_sha512(self):
        set_security_profile(SecurityProfile(level=3, canonical_hash=HashFunction.SHA_512))
        key = b"k" * 32
        nonce = b"n" * AEAD.NONCE_SIZE
        plaintext = b"encrypt me with sha512 hash"
        ct = AEAD.encrypt(key, plaintext, nonce)
        pt = AEAD.decrypt(key, ct, nonce)
        assert pt == plaintext


class TestHashFunctionEnum:
    def test_blake2b_value(self):
        assert HashFunction.BLAKE2B_256.value == "blake2b"

    def test_sha384_value(self):
        assert HashFunction.SHA_384.value == "sha384"

    def test_sha512_value(self):
        assert HashFunction.SHA_512.value == "sha512"

    def test_all_members(self):
        members = set(HashFunction)
        assert len(members) == 5


# ===========================================================================
# 3. HSM INTERFACE (§7.3)
# ===========================================================================


class TestSoftwareHSMKEM:
    def test_generate_kem_keypair(self):
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("test-kem-1")
        assert len(ek) == MLKEM.EK_SIZE
        assert hsm.has_key("test-kem-1")

    def test_duplicate_key_id_raises(self):
        hsm = SoftwareHSM()
        hsm.generate_kem_keypair("dup")
        with pytest.raises(ValueError, match="already exists"):
            hsm.generate_kem_keypair("dup")

    def test_kem_decaps(self):
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("decaps-test")
        # Simulate encapsulation (normally done by sender)
        ss, ct = MLKEM.encaps(ek)
        # Decapsulate through HSM — uses MLKEM.decaps() directly
        recovered_ss = hsm.kem_decaps("decaps-test", ct)
        assert recovered_ss == ss

    def test_kem_decaps_wrong_key_fails(self):
        hsm = SoftwareHSM()
        ek1 = hsm.generate_kem_keypair("key-1")
        hsm.generate_kem_keypair("key-2")
        ss, ct = MLKEM.encaps(ek1)
        # Real ML-KEM uses implicit rejection (returns different ss).
        # PoC backend raises ValueError. Either way, correct ss must not leak.
        try:
            recovered = hsm.kem_decaps("key-2", ct)
            assert recovered != ss, "Wrong key must not recover correct shared secret"
        except ValueError:
            pass  # PoC backend raises


class TestSoftwareHSMDSA:
    def test_generate_dsa_keypair(self):
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("test-dsa-1")
        assert len(vk) == MLDSA.VK_SIZE
        assert hsm.has_key("test-dsa-1")

    def test_sign_through_hsm(self):
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("signer")
        msg = b"sign this message"
        sig = hsm.sign("signer", msg)
        assert len(sig) == MLDSA.SIG_SIZE
        # Verify with public key
        assert MLDSA.verify(vk, msg, sig) is True

    def test_sign_wrong_key_type_raises(self):
        hsm = SoftwareHSM()
        hsm.generate_kem_keypair("kem-key")
        with pytest.raises(TypeError, match="not 'dsa'"):
            hsm.sign("kem-key", b"test")

    def test_sign_nonexistent_key_raises(self):
        hsm = SoftwareHSM()
        with pytest.raises(KeyError, match="not found"):
            hsm.sign("no-such-key", b"test")


class TestSoftwareHSMLifecycle:
    def test_destroy_key(self):
        hsm = SoftwareHSM()
        hsm.generate_dsa_keypair("ephemeral")
        assert hsm.has_key("ephemeral")
        assert hsm.destroy_key("ephemeral") is True
        assert hsm.has_key("ephemeral") is False

    def test_destroy_nonexistent_returns_false(self):
        hsm = SoftwareHSM()
        assert hsm.destroy_key("ghost") is False

    def test_list_keys(self):
        hsm = SoftwareHSM()
        hsm.generate_kem_keypair("kem-1")
        hsm.generate_dsa_keypair("dsa-1")
        keys = hsm.list_keys()
        assert len(keys) == 2
        key_ids = {k["key_id"] for k in keys}
        assert key_ids == {"kem-1", "dsa-1"}
        types = {k["type"] for k in keys}
        assert types == {"kem", "dsa"}

    def test_list_keys_empty(self):
        hsm = SoftwareHSM()
        assert hsm.list_keys() == []

    def test_get_public_key(self):
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("pub-test")
        assert hsm.get_public_key("pub-test") == ek

    def test_get_public_key_nonexistent_raises(self):
        hsm = SoftwareHSM()
        with pytest.raises(KeyError):
            hsm.get_public_key("missing")


class TestSoftwareHSMLevel5:
    def test_kem_keygen_level5(self):
        set_security_profile(SecurityProfile.level5())
        hsm = SoftwareHSM()
        ek = hsm.generate_kem_keypair("l5-kem")
        assert len(ek) == 1568

    def test_dsa_keygen_level5(self):
        set_security_profile(SecurityProfile.level5())
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("l5-dsa")
        assert len(vk) == 2592

    def test_sign_verify_level5(self):
        set_security_profile(SecurityProfile.level5())
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("l5-signer")
        msg = b"level 5 message"
        sig = hsm.sign("l5-signer", msg)
        assert len(sig) == 4627
        assert MLDSA.verify(vk, msg, sig) is True


# ===========================================================================
# 4. END-TO-END: Full protocol under Level 5 + SHA-384
# ===========================================================================


class TestEndToEndLevel5:
    def test_full_protocol_level5_sha384(self):
        """Complete COMMIT -> LATTICE -> MATERIALIZE under Level 5 / SHA-384."""
        set_security_profile(SecurityProfile.cnsa2())

        # Setup
        net = CommitmentNetwork()
        for nid, reg in [
            ("n1", "US-East"),
            ("n2", "US-West"),
            ("n3", "EU-West"),
            ("n4", "EU-East"),
            ("n5", "AP-East"),
            ("n6", "AP-South"),
        ]:
            net.add_node(nid, reg)

        protocol = LTPProtocol(net)
        alice = KeyPair.generate("alice-cnsa2")
        bob = KeyPair.generate("bob-cnsa2")

        # Verify key sizes are Level 5
        assert len(alice.ek) == 1568
        assert len(alice.vk) == 2592

        # COMMIT
        entity = Entity(content=b"CNSA 2.0 classified data", shape="x-ltp/test")
        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)

        # Verify hash prefix matches profile
        assert entity_id.startswith("sha384:")

        # Verify signature is Level 5 size
        assert len(record.signature) == 4627

        # LATTICE
        sealed = protocol.lattice(entity_id, record, cek, bob)
        # Level 5 sealed size: ct=1568 + nonce=16 + payload + tag
        assert len(sealed) > 1568

        # MATERIALIZE
        content = protocol.materialize(sealed, bob)
        assert content == b"CNSA 2.0 classified data"

    def test_wrong_receiver_level5(self):
        """Unauthorized receiver cannot materialize under Level 5."""
        set_security_profile(SecurityProfile.level5())

        net = CommitmentNetwork()
        for i in range(6):
            net.add_node(f"n{i}", f"R{i}")

        protocol = LTPProtocol(net)
        alice = KeyPair.generate("alice-l5")
        bob = KeyPair.generate("bob-l5")
        eve = KeyPair.generate("eve-l5")

        entity = Entity(content=b"secret", shape="x-ltp/test")
        eid, rec, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(eid, rec, cek, bob)

        # Eve cannot unseal
        result = protocol.materialize(sealed, eve)
        assert result is None


class TestEndToEndWithHSM:
    def test_hsm_sign_verify_roundtrip(self):
        """HSM-generated signatures verify with extracted public key."""
        hsm = SoftwareHSM()
        vk = hsm.generate_dsa_keypair("protocol-signer")
        msg = b"commitment record payload"
        sig = hsm.sign("protocol-signer", msg)
        assert MLDSA.verify(vk, msg, sig) is True

    def test_hsm_multiple_keys(self):
        """HSM manages multiple key pairs simultaneously."""
        hsm = SoftwareHSM()
        vk1 = hsm.generate_dsa_keypair("node-1-dsa")
        vk2 = hsm.generate_dsa_keypair("node-2-dsa")
        ek1 = hsm.generate_kem_keypair("node-1-kem")

        assert len(hsm.list_keys()) == 3

        sig1 = hsm.sign("node-1-dsa", b"msg1")
        sig2 = hsm.sign("node-2-dsa", b"msg2")

        assert MLDSA.verify(vk1, b"msg1", sig1) is True
        assert MLDSA.verify(vk2, b"msg2", sig2) is True
        # Cross-verify should fail
        assert MLDSA.verify(vk1, b"msg2", sig2) is False

    def test_hsm_key_destruction_prevents_signing(self):
        """Destroyed keys cannot be used for operations."""
        hsm = SoftwareHSM()
        hsm.generate_dsa_keypair("destroy-me")
        hsm.destroy_key("destroy-me")
        with pytest.raises(KeyError):
            hsm.sign("destroy-me", b"test")
