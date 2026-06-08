// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceLockVerifier, LockClaim} from "../interfaces/ISourceLockVerifier.sol";
import {ISourceHeaderOracle} from "../interfaces/ISourceHeaderOracle.sol";
import {RLPReader} from "../vendor/RLPReader.sol";
import {StateProofVerifier} from "../vendor/StateProofVerifier.sol";

/// @title StorageProofSourceLockVerifier
/// @notice P10 Phase B (inclusion proof): proves a source `Locked` commitment is
///         real by a Merkle-Patricia STORAGE proof that the canonical source Vault
///         recorded it — `commits[commitId].status == LOCKED`, with the stored
///         `destRecipient` and `amount` matching the claim — against a source
///         `stateRoot` from a trusted ISourceHeaderOracle. No relayer trust.
///
/// @dev Binds ALL claim-relevant fields, not just status: proving only status
///      would let a relayer mint a different amount/recipient than the source
///      lock specified (commitId alone does not constrain the caller-supplied
///      claim fields on-chain). So three slots are proven.
///
///      Storage layout of SuwappuVault.commits (verified via forge inspect):
///        base slot 7; struct for commitId at keccak256(abi.encode(commitId, 7));
///        destRecipient @ +2, amount @ +3, (lockedAt|status) packed @ +6 with
///        status at byte offset 8 => uint8(word >> 64).
///      This layout is a STABILITY PROMISE of any source Vault proven against.
///
///      Proof bytes = abi.encode(uint256 blockNumber, bytes accountProof,
///        bytes recipientProof, bytes amountProof, bytes statusProof) where each
///        *Proof is the RLP encoding of the list of MPT nodes (eth_getProof).
///      Reverts on a forged/malformed proof (the MPT verifier require()s the node
///      hashes chain to the root); returns false on a valid proof whose values do
///      not match the claim.
contract StorageProofSourceLockVerifier is ISourceLockVerifier {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    ISourceHeaderOracle public immutable headerOracle;

    /// SuwappuVault storage layout (pinned).
    uint256 internal constant COMMITS_BASE_SLOT = 7;
    uint256 internal constant OFFSET_DESTRECIPIENT = 2;
    uint256 internal constant OFFSET_AMOUNT = 3;
    uint256 internal constant OFFSET_STATUS = 6;
    uint256 internal constant STATUS_BYTE_SHIFT = 64; // status packed after lockedAt(uint64)
    uint8 internal constant LOCK_STATUS_LOCKED = 1; // LockStatus.LOCKED

    constructor(ISourceHeaderOracle _headerOracle) {
        headerOracle = _headerOracle;
    }

    /// @inheritdoc ISourceLockVerifier
    function verifyLock(LockClaim calldata claim, bytes calldata proof)
        external
        view
        override
        returns (bool)
    {
        if (claim.destChainId != block.chainid) return false;

        (
            uint256 blockNumber,
            bytes memory accountProof,
            bytes memory recipientProof,
            bytes memory amountProof,
            bytes memory statusProof
        ) = abi.decode(proof, (uint256, bytes, bytes, bytes, bytes));

        bytes32 stateRoot = headerOracle.headerStateRoot(claim.sourceChainId, blockNumber);
        if (stateRoot == bytes32(0)) return false;

        // 1. Account proof: source Vault -> its storageRoot, under the state root.
        StateProofVerifier.Account memory account = StateProofVerifier.extractAccountFromProof(
            keccak256(abi.encodePacked(claim.sourceVault)),
            stateRoot,
            accountProof.toRlpItem().toList()
        );
        if (!account.exists) return false;
        bytes32 storageRoot = account.storageRoot;

        bytes32 structSlot = keccak256(abi.encode(claim.commitId, COMMITS_BASE_SLOT));

        // 2. destRecipient slot must equal the claim recipient.
        StateProofVerifier.SlotValue memory rv =
            _slot(uint256(structSlot) + OFFSET_DESTRECIPIENT, storageRoot, recipientProof);
        if (!rv.exists || address(uint160(rv.value)) != claim.destRecipient) return false;

        // 3. amount slot must equal the claim amount.
        StateProofVerifier.SlotValue memory av =
            _slot(uint256(structSlot) + OFFSET_AMOUNT, storageRoot, amountProof);
        if (!av.exists || av.value != claim.amount) return false;

        // 4. status slot (packed lockedAt|status) must read LOCKED.
        StateProofVerifier.SlotValue memory sv =
            _slot(uint256(structSlot) + OFFSET_STATUS, storageRoot, statusProof);
        if (!sv.exists || uint8(sv.value >> STATUS_BYTE_SHIFT) != LOCK_STATUS_LOCKED) return false;

        return true;
    }

    function _slot(uint256 slot, bytes32 storageRoot, bytes memory slotProof)
        internal
        pure
        returns (StateProofVerifier.SlotValue memory)
    {
        return StateProofVerifier.extractSlotValueFromProof(
            keccak256(abi.encodePacked(bytes32(slot))), storageRoot, slotProof.toRlpItem().toList()
        );
    }
}
