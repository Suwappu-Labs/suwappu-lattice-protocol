"""
DNS discovery tests — pluggable DNSProvider backend + real dnspython TXT lookups.

Covers:
  - NIR JSON round-trip through a TXT record
  - LocalCacheDNSProvider publish / query / delete
  - DNSDiscoveryService with a custom provider
  - Real-DNS query path (mocked via dnspython monkeypatch)
  - Malformed / tampered TXT records rejected
  - Cross-provider dedup in discover()
"""

from __future__ import annotations

import pytest

from src.ltp import KeyPair
from src.ltp.federation import (
    DNSDiscoveryService,
    DNSProvider,
    LocalCacheDNSProvider,
    NetworkIdentityRecord,
)


@pytest.fixture(scope="session")
def operator() -> KeyPair:
    return KeyPair.generate("dns-test-operator")


@pytest.fixture(scope="session")
def other_operator() -> KeyPair:
    return KeyPair.generate("dns-test-other-operator")


def _nir(
    op: KeyPair, endpoint: str = "a.example.com", name: str = "Test Net"
) -> NetworkIdentityRecord:
    return NetworkIdentityRecord.create(op, b"\xaa" * 32, 0, name, endpoint)


# ---------------------------------------------------------------------------
# NIR JSON round-trip
# ---------------------------------------------------------------------------


class TestNIRSerialization:
    def test_round_trip_preserves_all_fields(self, operator):
        nir = _nir(operator)
        txt = DNSDiscoveryService._serialize_nir(nir)
        restored = DNSDiscoveryService._deserialize_nir(txt)
        assert restored is not None
        assert restored.network_id == nir.network_id
        assert restored.operator_vk == nir.operator_vk
        assert restored.genesis_sth_root == nir.genesis_sth_root
        assert restored.genesis_sth_sequence == nir.genesis_sth_sequence
        assert restored.display_name == nir.display_name
        assert restored.discovery_endpoint == nir.discovery_endpoint
        assert restored.signature == nir.signature

    def test_round_trip_preserves_signature_validity(self, operator):
        """Deserialized NIR must still verify under ML-DSA-65."""
        nir = _nir(operator)
        txt = DNSDiscoveryService._serialize_nir(nir)
        restored = DNSDiscoveryService._deserialize_nir(txt)
        assert restored.verify() is True

    def test_deserialize_rejects_malformed_json(self):
        assert DNSDiscoveryService._deserialize_nir("not-json") is None
        assert DNSDiscoveryService._deserialize_nir("") is None
        assert DNSDiscoveryService._deserialize_nir('{"v":1}') is None  # missing fields

    def test_deserialize_rejects_wrong_schema_version(self):
        assert DNSDiscoveryService._deserialize_nir('{"v":999}') is None


# ---------------------------------------------------------------------------
# LocalCacheDNSProvider
# ---------------------------------------------------------------------------


class TestLocalCacheDNSProvider:
    def test_publish_and_query_single_record(self):
        p = LocalCacheDNSProvider()
        assert p.publish_txt("_etp-nir.a.example.com", "record-1") is True
        assert p.query_txt("_etp-nir.a.example.com") == ["record-1"]

    def test_publish_multiple_records_same_name(self):
        p = LocalCacheDNSProvider()
        p.publish_txt("_etp-nir.a.example.com", "record-1")
        p.publish_txt("_etp-nir.a.example.com", "record-2")
        assert p.query_txt("_etp-nir.a.example.com") == ["record-1", "record-2"]

    def test_publish_duplicate_deduped(self):
        p = LocalCacheDNSProvider()
        p.publish_txt("_etp-nir.a.example.com", "record-1")
        p.publish_txt("_etp-nir.a.example.com", "record-1")
        assert p.query_txt("_etp-nir.a.example.com") == ["record-1"]

    def test_delete_existing(self):
        p = LocalCacheDNSProvider()
        p.publish_txt("_etp-nir.a.example.com", "record-1")
        assert p.delete_txt("_etp-nir.a.example.com") is True
        assert p.query_txt("_etp-nir.a.example.com") == []

    def test_delete_missing_returns_false(self):
        p = LocalCacheDNSProvider()
        assert p.delete_txt("_etp-nir.missing.com") is False

    def test_query_missing_returns_empty(self):
        p = LocalCacheDNSProvider()
        assert p.query_txt("_etp-nir.missing.com") == []


# ---------------------------------------------------------------------------
# DNSDiscoveryService with pluggable provider
# ---------------------------------------------------------------------------


class TestDiscoveryServiceWithProvider:
    def test_publish_writes_to_provider(self, operator):
        provider = LocalCacheDNSProvider()
        svc = DNSDiscoveryService(domain="etp.test", provider=provider)
        nir = _nir(operator, endpoint="dns.example.com")
        assert svc.publish(nir) is True

        # Provider should have one record at the FQDN
        records = provider.query_txt("_etp-nir.dns.example.com")
        assert len(records) == 1
        # Record is the serialized NIR
        assert nir.network_id in records[0]

    def test_discover_from_provider_only(self, operator):
        """NIRs published to a provider-backed service are discoverable via the provider."""
        provider = LocalCacheDNSProvider()
        svc1 = DNSDiscoveryService(domain="etp.test", provider=provider)
        svc1.publish(_nir(operator, endpoint="dns.example.com", name="Provider Net"))

        # Second instance sharing the same provider — no local cache overlap
        svc2 = DNSDiscoveryService(domain="etp.test", provider=provider)
        # Seed svc2's domain index so it knows where to look
        svc2._domain_index["dns.example.com"] = []
        found = svc2.discover("dns.example.com")
        assert len(found) >= 1
        assert any(n.display_name == "Provider Net" for n in found)

    def test_resolve_from_provider_only(self, operator):
        provider = LocalCacheDNSProvider()
        svc1 = DNSDiscoveryService(domain="etp.test", provider=provider)
        nir = _nir(operator, endpoint="dns.example.com")
        svc1.publish(nir)

        svc2 = DNSDiscoveryService(domain="etp.test", provider=provider)
        svc2._domain_index["dns.example.com"] = []
        resolved = svc2.resolve(nir.network_id)
        assert resolved is not None
        assert resolved.network_id == nir.network_id

    def test_tampered_record_rejected(self, operator):
        """TXT records whose signatures fail ML-DSA verify must be dropped."""

        class TamperingProvider(DNSProvider):
            def publish_txt(self, name, value):
                return True

            def delete_txt(self, name):
                return True

            def query_txt(self, name):
                # Return a NIR with a bogus signature
                import json

                return [
                    json.dumps(
                        {
                            "v": 1,
                            "network_id": "deadbeef",
                            "operator_vk": "00" * 1952,
                            "genesis_sth_root": "11" * 32,
                            "genesis_sth_sequence": 0,
                            "display_name": "Attacker",
                            "discovery_endpoint": "evil.example.com",
                            "created_at": 0.0,
                            "signature": "ff" * 3309,
                        },
                        separators=(",", ":"),
                    )
                ]

        svc = DNSDiscoveryService(domain="evil.example.com", provider=TamperingProvider())
        svc._domain_index["evil.example.com"] = []
        results = svc.discover("evil.example.com")
        # Tampered NIR should NOT appear
        assert not any(n.display_name == "Attacker" for n in results)

    def test_malformed_txt_silently_ignored(self, operator):
        class MalformedProvider(DNSProvider):
            def publish_txt(self, name, value):
                return True

            def delete_txt(self, name):
                return True

            def query_txt(self, name):
                return ["not-json", "", "{}"]

        svc = DNSDiscoveryService(domain="mal.example.com", provider=MalformedProvider())
        svc._domain_index["mal.example.com"] = []
        # Should not crash, should return empty (or local cache only)
        results = svc.discover("mal.example.com")
        assert results == []


# ---------------------------------------------------------------------------
# Real dnspython path (mocked)
# ---------------------------------------------------------------------------


class TestRealDNSPath:
    def test_dns_query_timeout_returns_empty(self, monkeypatch):
        """When dnspython raises, _query_real_dns returns []."""
        import dns.exception
        import dns.resolver

        def raise_timeout(*args, **kwargs):
            raise dns.exception.Timeout()

        monkeypatch.setattr(dns.resolver, "resolve", raise_timeout)
        result = DNSDiscoveryService._query_real_dns("_etp-nir.nonexistent.example.com")
        assert result == []

    def test_dns_query_parses_chunked_txt(self, monkeypatch):
        """TXT records are split into <=255-byte strings on the wire; they
        must be joined on decode."""
        import dns.resolver

        class FakeRdata:
            # Simulate a chunked TXT record
            strings = [b"hello ", b"world"]

        class FakeAnswer:
            def __iter__(self):
                return iter([FakeRdata()])

        monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **kw: FakeAnswer())
        result = DNSDiscoveryService._query_real_dns("_etp-nir.chunked.example.com")
        assert result == ["hello world"]

    def test_dns_query_returns_real_nir(self, monkeypatch, operator):
        """A DNS TXT that happens to be a valid serialized NIR should be
        picked up by discover()."""
        import dns.resolver

        nir = _nir(operator, endpoint="real.example.com")
        txt = DNSDiscoveryService._serialize_nir(nir)

        class FakeRdata:
            strings = [txt.encode()]

        class FakeAnswer:
            def __iter__(self):
                return iter([FakeRdata()])

        def fake_resolve(name, rdtype, *args, **kwargs):
            if name == "_etp-nir.real.example.com" and rdtype == "TXT":
                return FakeAnswer()
            import dns.exception

            raise dns.exception.Timeout()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

        svc = DNSDiscoveryService(domain="real.example.com")
        svc._domain_index["real.example.com"] = []
        results = svc.discover("real.example.com")
        assert any(n.network_id == nir.network_id for n in results)


# ---------------------------------------------------------------------------
# Default provider is LocalCacheDNSProvider
# ---------------------------------------------------------------------------


class TestDefaultProvider:
    def test_default_provider_is_local_cache(self):
        svc = DNSDiscoveryService()
        assert isinstance(svc._provider, LocalCacheDNSProvider)

    def test_default_provider_roundtrip(self, operator):
        """Backward compat: DNSDiscoveryService() with no provider still
        supports publish/discover/resolve against the in-memory cache."""
        svc = DNSDiscoveryService()
        nir = _nir(operator, endpoint="default.example.com", name="Default")
        assert svc.publish(nir) is True
        assert any(n.network_id == nir.network_id for n in svc.discover())
        assert svc.resolve(nir.network_id) is not None
