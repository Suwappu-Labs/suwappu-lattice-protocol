"""
HeaderRelayer — GSX-DAG validator-quorum header-attestation AGGREGATOR.

This relayer polls the GSX-DAG validator set for per-validator header
attestations (via ``gsx_getHeaderAttestation``), aggregates the set that
backs a given ``(block_number, state_root)`` header, orders + dedups the
signers, and submits the aggregate to ``GsxDagQuorumHeaderOracle.submitHeader``.

TRUST MODEL (honest, non-negotiable):
    This relayer is **LIVENESS-trusted but CANNOT forge**. It is a
    validator-quorum SIDE-ATTESTATION aggregator (sync-committee class):

      - The ON-CHAIN oracle re-verifies *every* ML-DSA signature against the
        registry's epoch validator set, re-enforces the strictly-increasing
        ``keccak256(pubkey)`` dedup, and re-enforces the ``>2/3``-stake quorum
        threshold. None of those checks are trusted to the relayer.
      - A malicious or buggy relayer can therefore at worst **stall**
        (withhold a header) or submit a set the oracle **REJECTS** (reverts).
        It can NEVER finalize a header the quorum did not sign, NEVER inflate
        stake, and NEVER reorder past the on-chain dedup.

    This is **NOT** trustless, **NOT** a consensus light client, and **NOT**
    end-to-end post-quantum (the on-chain ML-DSA precompile is the PQ root;
    the relayer only forwards signatures it collected). ``state_root`` is the
    GSX-DAG BLAKE3 L1 root, not a storage-provable EVM root.

    Because safety lives entirely in the oracle, ``aggregate()`` does
    best-effort majority selection WITHOUT knowing validator stakes — picking
    the wrong (e.g. minority) set merely produces a submission the oracle
    rejects; it can never produce an *unsafe* finalization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

__all__ = ["HeaderAttestation", "AggregatedHeader", "HeaderRelayer"]


def _keccak(data: bytes) -> bytes:
    """keccak256 over raw bytes (matches the contract's pubkey dedup hash).

    Imported lazily from ``eth_hash`` (a hard dep of web3) so this module's
    top-level import surface stays minimal and free of network/web3 objects.
    """
    from eth_hash.auto import keccak

    return keccak(data)


def _hexbytes(s: str) -> bytes:
    """Decode an ``0x``-prefixed hex string (the RPC wire form) to bytes."""
    return bytes.fromhex(s[2:] if s.startswith(("0x", "0X")) else s)


@dataclass(frozen=True)
class HeaderAttestation:
    """One validator's signed attestation of a GSX-DAG header.

    Mirrors the ``HeaderAttestationView`` returned by ``gsx_getHeaderAttestation``
    (gsx-rpc ``context.rs``). All five hex fields arrive ``0x``-prefixed on the
    wire; ``pubkey``/``signature``/``state_root`` are stored as raw ``bytes``.

    NB: there is NO ``epoch`` field in the view — the signed digest binds
    ``HEADER_DOMAIN || network_id || oracle || block_number || state_root`` and
    the live submit-epoch is read on-chain at ``submit()`` time, not carried here.
    """

    block_number: int
    state_root: bytes
    authority_id: int
    pubkey: bytes
    signature: bytes
    network_id: bytes  # 32-byte uint256, normalized form
    oracle: str  # 0x-prefixed 20-byte address (lowercased)

    @classmethod
    def from_view(cls, view: dict[str, Any]) -> HeaderAttestation:
        """Parse a non-null ``HeaderAttestationView`` JSON object exactly.

        Raises KeyError/ValueError on a malformed view; callers in ``poll``
        treat such errors as "skip this validator" (a malformed attestation
        can never cause an unsafe submit — worst case it is dropped).
        """
        return cls(
            block_number=int(view["block_number"]),
            state_root=_hexbytes(view["state_root"]),
            authority_id=int(view["authority_id"]),
            pubkey=_hexbytes(view["pubkey"]),
            signature=_hexbytes(view["signature"]),
            # Normalize network_id to a left-padded 32-byte value so grouping is
            # canonical regardless of how the validator zero-pads the hex.
            network_id=_hexbytes(view["network_id"]).rjust(32, b"\x00"),
            oracle=str(view["oracle"]).lower(),
        )

    def group_key(self) -> tuple[int, bytes, bytes, str]:
        """Header-identity key: ``(block_number, state_root, network_id, oracle)``.

        Two attestations are over the SAME header iff their group keys match.
        epoch is deliberately absent (not in the view, not in the digest).
        """
        return (self.block_number, self.state_root, self.network_id, self.oracle)


@dataclass(frozen=True)
class AggregatedHeader:
    """The relayer's best-effort aggregate, ready for ``submitHeader``.

    ``pubkeys``/``sigs`` are index-aligned and sorted by strictly-increasing
    ``keccak256(pubkey)`` with duplicates dropped — matching the contract's
    ``UnsortedOrDuplicate`` dedup. ``epoch`` is intentionally NOT stored here:
    the live registry epoch is read at ``submit()`` time.
    """

    block_number: int
    state_root: bytes
    pubkeys: list[bytes]
    sigs: list[bytes]
    network_id: bytes = field(default=b"")
    oracle: str = field(default="")

    @property
    def signer_count(self) -> int:
        return len(self.pubkeys)


class HeaderRelayer:
    """Polls validators, aggregates a header quorum, submits to the oracle.

    LIVENESS-trusted, CANNOT forge (see module docstring). The relayer never
    needs stakes to be SAFE: the oracle enforces ``>2/3`` stake. Aggregation
    here is best-effort majority-by-attestation-count.
    """

    def __init__(self, *, request_timeout: float = 10.0) -> None:
        self.request_timeout = request_timeout

    # ------------------------------------------------------------------ poll
    def poll(self, validator_rpc_urls: list[str]) -> list[HeaderAttestation]:
        """JSON-RPC ``gsx_getHeaderAttestation`` against each validator.

        Args:
            validator_rpc_urls: validator RPC endpoints to query.

        Returns:
            One ``HeaderAttestation`` per validator that returned a non-null,
            well-formed view. Validators that are unreachable, return JSON
            ``null`` (no finalized header / no bridge signer configured), or
            return a malformed view are SKIPPED. Skipping is always safe — a
            dropped or malformed attestation can at worst reduce liveness, the
            oracle still re-verifies whatever is ultimately submitted.
        """
        import requests

        out: list[HeaderAttestation] = []
        for url in validator_rpc_urls:
            try:
                resp = requests.post(
                    url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "gsx_getHeaderAttestation",
                        "params": [],
                    },
                    timeout=self.request_timeout,
                )
                resp.raise_for_status()
                body = resp.json()
            except Exception as exc:  # unreachable / bad HTTP / bad JSON
                logger.warning("[HeaderRelayer] skip %s: unreachable/bad response: %s", url, exc)
                continue

            view = body.get("result")
            if view is None:
                # JSON null => no finalized header yet, or no bridge signer.
                logger.info("[HeaderRelayer] skip %s: null attestation", url)
                continue

            try:
                out.append(HeaderAttestation.from_view(view))
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning("[HeaderRelayer] skip %s: malformed attestation: %s", url, exc)
                continue

        logger.info(
            "[HeaderRelayer] polled %d validators, collected %d attestations",
            len(validator_rpc_urls),
            len(out),
        )
        return out

    # ------------------------------------------------------------- aggregate
    def aggregate(self, attestations: list[HeaderAttestation]) -> Optional[AggregatedHeader]:
        """Pick the most-attested header, sort + dedup its signers.

        Grouping is by ``(block_number, state_root, network_id, oracle)`` so
        attestations are NEVER merged across distinct state roots (an equivocating
        or split validator set yields separate groups; we pick one, never union).

        The chosen header's attestations are sorted strictly-increasing by
        ``keccak256(pubkey)`` and duplicate pubkeys are dropped — byte-for-byte
        the contract's ``_verifyQuorum`` ordering contract.

        SAFETY NOTE: this is best-effort and STAKE-BLIND. The relayer does not
        know validator stakes; it cannot and need not enforce the ``>2/3``
        threshold. The ORACLE does. Choosing a minority set merely yields a
        submission the oracle rejects (``BelowQuorum``) — never an unsafe finalize.

        Returns:
            The aggregate ready for ``submitHeader``, or ``None`` if there are
            no attestations.
        """
        if not attestations:
            return None

        # Group by header identity; never merge across state roots.
        groups: dict[tuple[int, bytes, bytes, str], list[HeaderAttestation]] = {}
        for att in attestations:
            groups.setdefault(att.group_key(), []).append(att)

        # Best-effort: pick the header backed by the most attestations.
        # Deterministic tie-break on the group key keeps behavior reproducible.
        best_key = max(
            groups,
            key=lambda k: (len(groups[k]), k[0], k[1]),
        )
        chosen = groups[best_key]
        block_number, state_root, network_id, oracle = best_key

        # Sort strictly-increasing by keccak256(pubkey); drop duplicate pubkeys.
        seen: set[bytes] = set()
        deduped: list[HeaderAttestation] = []
        for att in sorted(chosen, key=lambda a: _keccak(a.pubkey)):
            if att.pubkey in seen:
                continue
            seen.add(att.pubkey)
            deduped.append(att)

        agg = AggregatedHeader(
            block_number=block_number,
            state_root=state_root,
            pubkeys=[a.pubkey for a in deduped],
            sigs=[a.signature for a in deduped],
            network_id=network_id,
            oracle=oracle,
        )
        logger.info(
            "[HeaderRelayer] aggregated header block=%d root=0x%s with %d signers "
            "(%d groups seen; oracle enforces >2/3 stake quorum)",
            block_number,
            state_root.hex(),
            agg.signer_count,
            len(groups),
        )
        return agg

    # ---------------------------------------------------------------- submit
    def submit(self, w3: Any, oracle_address: str, agg: AggregatedHeader) -> Any:
        """Build + send ``submitHeader`` to the deployed oracle and return the receipt.

        The live submit ``epoch`` is read ON-CHAIN here
        (``oracle.registry().currentEpoch()``), NOT carried from ``aggregate``:
        the attestation view has no epoch field, and ``submitHeader`` reverts
        ``StaleEpoch`` unless ``epoch == registry.currentEpoch()``.

        This call cannot finalize anything the quorum did not sign — if the
        aggregate is short of ``>2/3`` stake, or any signature is invalid, or the
        ordering is off, the oracle REVERTS. The relayer is liveness-trusted only.

        Args:
            w3: a connected ``web3.Web3`` instance with a default account /
                signing middleware, or one configured by the caller.
            oracle_address: deployed ``GsxDagQuorumHeaderOracle`` address.
            agg: the aggregate from ``aggregate()``.

        Returns:
            The transaction receipt.
        """
        from web3 import Web3

        oracle = self._oracle_contract(w3, oracle_address)
        registry_addr = oracle.functions.registry().call()
        registry = self._registry_contract(w3, registry_addr)
        epoch = registry.functions.currentEpoch().call()

        state_root32 = agg.state_root.rjust(32, b"\x00")
        if state_root32 == b"\x00" * 32:
            raise ValueError(
                "refusing to submit zero state_root (oracle would revert ZeroStateRoot)"
            )

        logger.info(
            "[HeaderRelayer] submitting header block=%d epoch=%d signers=%d to oracle %s",
            agg.block_number,
            epoch,
            agg.signer_count,
            Web3.to_checksum_address(oracle_address),
        )

        fn = oracle.functions.submitHeader(
            agg.block_number,
            state_root32,
            epoch,
            agg.pubkeys,
            agg.sigs,
        )
        tx_hash = fn.transact()
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        logger.info(
            "[HeaderRelayer] submitHeader mined: status=%s block=%d",
            receipt.get("status"),
            agg.block_number,
        )
        return receipt

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _oracle_abi() -> list[dict]:
        """Minimal ABI for the oracle calls the relayer makes."""
        return [
            {
                "type": "function",
                "name": "submitHeader",
                "stateMutability": "nonpayable",
                "inputs": [
                    {"name": "blockNumber", "type": "uint256"},
                    {"name": "stateRoot", "type": "bytes32"},
                    {"name": "epoch", "type": "uint256"},
                    {"name": "pubkeys", "type": "bytes[]"},
                    {"name": "sigs", "type": "bytes[]"},
                ],
                "outputs": [],
            },
            {
                "type": "function",
                "name": "registry",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"name": "", "type": "address"}],
            },
        ]

    @staticmethod
    def _registry_abi() -> list[dict]:
        return [
            {
                "type": "function",
                "name": "currentEpoch",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"name": "", "type": "uint256"}],
            }
        ]

    def _oracle_contract(self, w3: Any, oracle_address: str) -> Any:
        from web3 import Web3

        return w3.eth.contract(
            address=Web3.to_checksum_address(oracle_address),
            abi=self._oracle_abi(),
        )

    def _registry_contract(self, w3: Any, registry_address: str) -> Any:
        from web3 import Web3

        return w3.eth.contract(
            address=Web3.to_checksum_address(registry_address),
            abi=self._registry_abi(),
        )
