// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISourceHeaderOracle
/// @notice P10 header-trust seam (half A): exposes a source-chain `stateRoot` the
///         destination independently trusts for a given (chainId, blockNumber).
///         Implementations: an SP1-Helios ZK light client for EVM sources, a
///         GSX-DAG ML-DSA consensus light client for the home corridor, or a
///         Hashi-style N-of-M aggregator. The storage-proof verifier consumes ONLY
///         this interface, so the trust root can be swapped without re-auditing the
///         inclusion-proof half. See P10_SOURCE_EVENT_PROOF.md.
interface ISourceHeaderOracle {
    /// @return stateRoot The trusted state root for `blockNumber` on
    ///         `sourceChainId`, or bytes32(0) if not known/trusted.
    function headerStateRoot(uint256 sourceChainId, uint256 blockNumber)
        external
        view
        returns (bytes32 stateRoot);
}
