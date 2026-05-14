"""
Tests for AWS KMS Backend using moto (AWS mock library).

Validates envelope encryption pattern: PQ keys generated locally,
private material encrypted via KMS, signing requires KMS decrypt.
"""

from __future__ import annotations

import os
import threading

import pytest

try:
    import boto3
    from moto import mock_aws
except ImportError:
    boto3 = None

    def mock_aws(func=None, *args, **kwargs):
        if func is None:
            return lambda wrapped: wrapped
        return func


pytestmark = pytest.mark.skipif(
    boto3 is None,
    reason="boto3/moto cloud test dependencies not installed",
)

from src.ltp.cloud.aws_kms import AWSKMSBackend
from src.ltp.primitives import MLDSA


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def kms_key_arn():
    """Create a mocked KMS key and return its ARN."""
    with mock_aws():
        client = boto3.client("kms", region_name="us-east-1")
        response = client.create_key(Description="ETP test key")
        arn = response["KeyMetadata"]["Arn"]
        yield arn


@pytest.fixture
def aws_kms(kms_key_arn):
    """Create an AWSKMSBackend with a mocked KMS key."""
    with mock_aws():
        # Re-create the key inside the mock context
        client = boto3.client("kms", region_name="us-east-1")
        response = client.create_key(Description="ETP test key")
        arn = response["KeyMetadata"]["Arn"]
        backend = AWSKMSBackend(key_arn=arn, region="us-east-1")
        yield backend


# ---------------------------------------------------------------------------
# Create Key
# ---------------------------------------------------------------------------


class TestCreateKey:

    @mock_aws
    def test_create_key_returns_public_bytes(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        vk = backend.create_key("test-key", algorithm="ML-DSA-65")
        assert isinstance(vk, bytes)
        assert len(vk) > 0

    @mock_aws
    def test_create_key_duplicate_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("dup-key")
        with pytest.raises(ValueError, match="already exists"):
            backend.create_key("dup-key")

    @mock_aws
    def test_create_kem_key(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        ek = backend.create_key("kem-key", algorithm="ML-KEM-768")
        assert isinstance(ek, bytes)
        assert len(ek) > 0

    @mock_aws
    def test_unsupported_algorithm_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        with pytest.raises(ValueError, match="Unsupported"):
            backend.create_key("bad-key", algorithm="RSA-2048")


# ---------------------------------------------------------------------------
# Get Public Key
# ---------------------------------------------------------------------------


class TestGetPublicKey:

    @mock_aws
    def test_get_public_key(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        original_vk = backend.create_key("lookup-key")
        retrieved_vk = backend.get_public_key("lookup-key")
        assert retrieved_vk == original_vk

    @mock_aws
    def test_get_public_key_missing_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        with pytest.raises(KeyError):
            backend.get_public_key("nonexistent")


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


class TestSign:

    @mock_aws
    def test_sign_produces_valid_signature(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        vk = backend.create_key("sign-key", algorithm="ML-DSA-65")
        msg = b"test message for signing"
        sig = backend.sign("sign-key", msg)

        assert isinstance(sig, bytes)
        assert len(sig) > 0
        # Verify signature with public key
        assert MLDSA.verify(vk, msg, sig) is True

    @mock_aws
    def test_sign_missing_key_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        with pytest.raises(KeyError):
            backend.sign("nonexistent", b"msg")

    @mock_aws
    def test_sign_kem_key_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("kem-key", algorithm="ML-KEM-768")
        with pytest.raises(ValueError, match="not a signing key"):
            backend.sign("kem-key", b"msg")


# ---------------------------------------------------------------------------
# Destroy
# ---------------------------------------------------------------------------


class TestDestroy:

    @mock_aws
    def test_destroy_existing_returns_true(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("destroy-key")
        assert backend.destroy_key("destroy-key") is True

    @mock_aws
    def test_destroy_missing_returns_false(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        assert backend.destroy_key("nonexistent") is False

    @mock_aws
    def test_destroy_then_get_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("gone-key")
        backend.destroy_key("gone-key")
        with pytest.raises(KeyError):
            backend.get_public_key("gone-key")


# ---------------------------------------------------------------------------
# Rotate
# ---------------------------------------------------------------------------


class TestRotate:

    @mock_aws
    def test_rotate_returns_version_id(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("rotate-key")
        version_id = backend.rotate_key("rotate-key")
        assert version_id == "rotate-key-v2"

    @mock_aws
    def test_rotate_missing_raises(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        with pytest.raises(KeyError):
            backend.rotate_key("nonexistent")

    @mock_aws
    def test_rotate_sign_with_new_key(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("rotate-sign-key", algorithm="ML-DSA-65")
        backend.rotate_key("rotate-sign-key")
        new_vk = backend.get_public_key("rotate-sign-key")
        sig = backend.sign("rotate-sign-key", b"after rotation")
        assert MLDSA.verify(new_vk, b"after rotation", sig) is True


# ---------------------------------------------------------------------------
# List + Metadata
# ---------------------------------------------------------------------------


class TestListAndMetadata:

    @mock_aws
    def test_list_keys(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("key-a")
        backend.create_key("key-b")
        backend.create_key("other-c")
        assert set(backend.list_keys()) == {"key-a", "key-b", "other-c"}

    @mock_aws
    def test_list_keys_prefix(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("prefix-a")
        backend.create_key("prefix-b")
        backend.create_key("other-c")
        assert set(backend.list_keys("prefix-")) == {"prefix-a", "prefix-b"}

    @mock_aws
    def test_metadata(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        backend.create_key("meta-key", algorithm="ML-DSA-65")
        meta = backend.get_key_metadata("meta-key")
        assert meta["key_id"] == "meta-key"
        assert meta["algorithm"] == "ML-DSA-65"
        assert meta["state"] == "active"
        assert meta["versions"] == [1]
        assert "kms_key_arn" in meta


# ---------------------------------------------------------------------------
# Thread Safety
# ---------------------------------------------------------------------------


class TestThreadSafety:

    @mock_aws
    def test_concurrent_creates(self):
        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        errors = []

        def create(i):
            try:
                backend.create_key(f"thread-key-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(backend.list_keys()) == 10


# ---------------------------------------------------------------------------
# Integration with KeyRotationManager
# ---------------------------------------------------------------------------


class TestKeyRotationIntegration:

    @mock_aws
    def test_complete_retirement_calls_destroy(self):
        from src.ltp.keypair import KeyPair, KeyRotationManager, KeyState

        client = boto3.client("kms", region_name="us-east-1")
        key = client.create_key(Description="test")
        backend = AWSKMSBackend(key_arn=key["KeyMetadata"]["Arn"], region="us-east-1")

        # Create key in backend
        backend.create_key("retire-test-v1")

        # Create KeyRotationManager with KMS
        mgr = KeyRotationManager(kms=backend)
        kp = KeyPair.generate("retire-test")
        kp.version = 1
        # KeyPair.generate() sets state=ACTIVE, so go straight to retirement
        mgr.begin_retirement(kp, grace_period_seconds=0)
        mgr.complete_retirement(kp)

        assert kp.state == KeyState.RETIRED
        # Key should be destroyed in backend
        assert backend.destroy_key("retire-test-v1") is False  # Already gone
