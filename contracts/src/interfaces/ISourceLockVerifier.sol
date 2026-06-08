// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice The exact source-chain lock a destination mint claims to be backed by.
///         Every field is bound by `commitId` (the source Vault derives
///         commitId = keccak256(sourceChainId, vault, nonce, from, token, amount,
///         destChainId, destRecipient)), so a verifier need only prove that the
///         canonical `sourceVault` on `sourceChainId` recorded this commit as
///         LOCKED — see docs/security/audits/suwappu/P10_SOURCE_EVENT_PROOF.md.
struct LockClaim {
    uint256 sourceChainId; // chain the lock happened on
    address sourceVault; // canonical SuwappuVault on sourceChainId (governance-pinned)
    bytes32 commitId; // the lock commitment id
    address destRecipient; // recipient on the destination
    uint256 amount; // net locked amount
    uint256 destChainId; // must equal block.chainid on the destination
}

/// @title ISourceLockVerifier
/// @notice P10 trust-minimization seam: proves, cryptographically and without
///         relayer trust, that a source-chain `Locked` commitment is real before
///         a destination mint is allowed. Implementations range from a mock
///         (tests), to a Merkle-Patricia storage proof of `commits[commitId]`
///         against a source `stateRoot` from a trusted header oracle
///         (StorageProofSourceLockVerifier), to a consensus-signature light
///         client. The MintAdapter depends ONLY on this interface, so the proof
///         backend can be swapped via governance without touching custody.
interface ISourceLockVerifier {
    /// @param claim The mint-bound lock claim to verify.
    /// @param proof Opaque proof bytes (e.g. abi.encode(blockNumber, accountProof,
    ///        storageProof) for the storage-proof verifier).
    /// @return ok True iff `proof` shows `sourceVault.commits[commitId].status ==
    ///         LOCKED` on `sourceChainId` under a source state root this verifier
    ///         trusts, AND the claim fields are consistent.
    function verifyLock(LockClaim calldata claim, bytes calldata proof)
        external
        view
        returns (bool ok);
}
