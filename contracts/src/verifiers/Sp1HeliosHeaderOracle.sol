// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceHeaderOracle} from "../interfaces/ISourceHeaderOracle.sol";

/// @notice Minimal view into a deployed SP1 Helios light-client contract
///         (succinctlabs/sp1-helios — an Ethereum sync-committee ZK light client,
///         OpenZeppelin-audited, live in Across V4). It stores execution-layer
///         state roots per beacon slot once a SNARK of consensus is verified.
interface ISP1Helios {
    /// @return The verified execution `stateRoot` for `slot`, or 0 if not proven.
    function executionStateRoots(uint256 slot) external view returns (bytes32);
}

/// @title Sp1HeliosHeaderOracle
/// @notice P10 Phase C header-trust root for EVM source chains: adapts a deployed
///         SP1 Helios ZK light client to ISourceHeaderOracle. It does NOT
///         re-implement the light client — it surfaces the state roots SP1 Helios
///         has already cryptographically proven from Ethereum consensus, so the
///         destination trusts a SNARK of source consensus, not a relayer.
///
/// @dev `blockNumber` in the ISourceHeaderOracle call is interpreted as the SP1
///      Helios beacon SLOT whose execution payload root is wanted (the prover and
///      the storage-proof submitter agree on this slot↔block correspondence).
///      Returns 0 for any chain other than the one this Helios instance tracks, or
///      for a slot not yet proven — so the storage-proof verifier rejects it.
///
///      Honest caveat (P5b §3): SP1 proofs are STARK-internally but wrap to a
///      Groth16/BN254 SNARK for the ~280k-gas on-chain verify → Shor-broken → this
///      EVM-source path is NOT post-quantum end-to-end. Only the GSX-DAG corridor
///      (CommitteeHeaderOracle with ML-DSA sigs) is PQ. See P10_SOURCE_EVENT_PROOF.md.
contract Sp1HeliosHeaderOracle is ISourceHeaderOracle {
    ISP1Helios public immutable helios;
    uint256 public immutable sourceChainId;

    constructor(ISP1Helios _helios, uint256 _sourceChainId) {
        require(address(_helios) != address(0), "Sp1HeliosHeaderOracle: zero helios");
        require(_sourceChainId != 0, "Sp1HeliosHeaderOracle: zero chainId");
        helios = _helios;
        sourceChainId = _sourceChainId;
    }

    /// @inheritdoc ISourceHeaderOracle
    function headerStateRoot(uint256 chainId, uint256 slot)
        external
        view
        override
        returns (bytes32)
    {
        if (chainId != sourceChainId) return bytes32(0);
        return helios.executionStateRoots(slot);
    }
}
