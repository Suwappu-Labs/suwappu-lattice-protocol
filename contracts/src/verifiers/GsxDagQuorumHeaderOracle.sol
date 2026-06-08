// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceHeaderOracle} from "../interfaces/ISourceHeaderOracle.sol";
import {GsxDagValidatorRegistry} from "./GsxDagValidatorRegistry.sol";

/// @title GsxDagQuorumHeaderOracle
/// @notice Finalizes a GSX-DAG block's EVM state root once a >2/3-stake quorum of
///         the tracked validator set (GsxDagValidatorRegistry) ML-DSA-signs a
///         header attestation over (blockNumber, stateRoot), verified via the
///         native 0x0101/0x0102 precompiles. An ISourceHeaderOracle.
///
/// @dev HONEST framing (this is NOT "consensus verification"):
///   - Verifies a VALIDATOR-QUORUM SIDE-ATTESTATION over (blockNumber, stateRoot) —
///     a bridge-specific signature with no slashing and NO coupling to GSX-DAG's
///     actual block-commit (Mysticeti-C) rule. Sync-committee trust model: trust an
///     honest >2/3-stake quorum of the tracked set.
///   - Delta vs CommitteeHeaderOracle is the SAME TRUST CLASS, incrementally
///     improved: PQ sigs (ML-DSA), a self-rotating set (old set signs the new set
///     via the registry's epoch transitions), and the set mirrors the GSX-DAG
///     validator registry rather than a separately-appointed bridge committee. A
///     real but INCREMENTAL improvement, NOT a jump to a consensus light client.
///   - UNWIRED: GSX-DAG validators do NOT currently sign these header attestations
///     (the signing duty is unimplemented), so this is destination-side machinery
///     that cannot be exercised against real GSX-DAG consensus today.
///   - PQ only where 0x0101 exists (the GSX-DAG home chain). A conflicting root for
///     a finalized block reverts. See P11_GSXDAG_CONSENSUS_LIGHT_CLIENT.md.
contract GsxDagQuorumHeaderOracle is ISourceHeaderOracle {
    address public constant BLAKE3 = address(0x0102);

    bytes32 public constant HEADER_DOMAIN = keccak256("SUWAPPU_GSXDAG_HEADER_V1");

    GsxDagValidatorRegistry public immutable registry;
    /// The GSX-DAG source chain id this oracle serves.
    uint256 public immutable gsxDagChainId;

    /// blockNumber => finalized EVM state root
    mapping(uint256 => bytes32) private _stateRoots;

    event HeaderFinalized(
        uint256 indexed blockNumber, bytes32 stateRoot, uint256 epoch, uint256 sigStake
    );

    error ZeroStateRoot();
    error HeaderConflict(uint256 blockNumber);
    error StaleEpoch(uint256 epoch, uint256 currentEpoch);
    error BelowQuorum(uint256 sigStake, uint256 needed);
    error PrecompileFailed();

    constructor(GsxDagValidatorRegistry registry_, uint256 gsxDagChainId_) {
        require(address(registry_) != address(0), "GsxDagQuorumHeaderOracle: zero registry");
        require(gsxDagChainId_ != 0, "GsxDagQuorumHeaderOracle: zero chainId");
        registry = registry_;
        gsxDagChainId = gsxDagChainId_;
    }

    /// @notice Finalize `stateRoot` for `blockNumber`, proven by a >2/3-stake quorum
    ///         of the validator set at `epoch` (must be the registry's current epoch)
    ///         ML-DSA-signing the header attestation. Idempotent for an identical
    ///         root; reverts on a conflicting root for a finalized block.
    /// @param pubkeys/sigs validator full pubkeys + ML-DSA sigs, ordered by
    ///        strictly-increasing keccak(pubkey).
    function submitHeader(
        uint256 blockNumber,
        bytes32 stateRoot,
        uint256 epoch,
        bytes[] calldata pubkeys,
        bytes[] calldata sigs
    ) external {
        if (stateRoot == bytes32(0)) revert ZeroStateRoot();

        bytes32 existing = _stateRoots[blockNumber];
        if (existing != bytes32(0)) {
            if (existing != stateRoot) revert HeaderConflict(blockNumber);
            return; // already finalized with the same root
        }

        uint256 cur = registry.currentEpoch();
        if (epoch != cur) revert StaleEpoch(epoch, cur);

        bytes32 digest = _blake3(
            abi.encodePacked(
                HEADER_DOMAIN, registry.networkId(), address(this), blockNumber, stateRoot
            )
        );

        uint256 sigStake = registry.verifyQuorum(epoch, digest, pubkeys, sigs);
        uint256 needed = registry.quorumThreshold(epoch);
        if (sigStake < needed) revert BelowQuorum(sigStake, needed);

        _stateRoots[blockNumber] = stateRoot;
        emit HeaderFinalized(blockNumber, stateRoot, epoch, sigStake);
    }

    /// @inheritdoc ISourceHeaderOracle
    function headerStateRoot(uint256 chainId, uint256 blockNumber)
        external
        view
        override
        returns (bytes32)
    {
        if (chainId != gsxDagChainId) return bytes32(0);
        return _stateRoots[blockNumber];
    }

    /// @notice The header-attestation digest validators must ML-DSA-sign.
    function headerDigest(uint256 blockNumber, bytes32 stateRoot) external view returns (bytes32) {
        return _blake3(
            abi.encodePacked(
                HEADER_DOMAIN, registry.networkId(), address(this), blockNumber, stateRoot
            )
        );
    }

    function _blake3(bytes memory data) internal view returns (bytes32) {
        (bool ok, bytes memory out) = BLAKE3.staticcall(data);
        if (!ok || out.length != 32) revert PrecompileFailed();
        return bytes32(out);
    }
}
