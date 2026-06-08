// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StorageProofSourceLockVerifier} from "../src/verifiers/StorageProofSourceLockVerifier.sol";
import {ISourceHeaderOracle} from "../src/interfaces/ISourceHeaderOracle.sol";
import {ISourceLockVerifier, LockClaim} from "../src/interfaces/ISourceLockVerifier.sol";

/// @notice Trivial header oracle for tests: returns a pinned state root.
contract MockHeaderOracle is ISourceHeaderOracle {
    mapping(uint256 => mapping(uint256 => bytes32)) public roots;

    function set(uint256 chainId, uint256 blockNumber, bytes32 root) external {
        roots[chainId][blockNumber] = root;
    }

    function headerStateRoot(uint256 chainId, uint256 blockNumber) external view returns (bytes32) {
        return roots[chainId][blockNumber];
    }
}

/// @notice P10 Phase B: validates StorageProofSourceLockVerifier against a REAL
///         eth_getProof fixture captured from a SuwappuVault lock (generated on a
///         local anvil — genuine Ethereum MPT proofs, reproducible). The fixture
///         proves commits[commitId] {destRecipient, amount, status==LOCKED} under a
///         real state root. See test/fixtures/p10_storage_proof.json.
contract StorageProofSourceLockVerifierTest is Test {
    StorageProofSourceLockVerifier verifier;
    MockHeaderOracle oracle;

    // loaded from fixture
    uint256 srcChainId;
    uint256 blockNumber;
    bytes32 stateRoot;
    address sourceVault;
    bytes32 commitId;
    address destRecipient;
    uint256 amount;
    bytes accountProof;
    bytes recipientProof;
    bytes amountProof;
    bytes statusProof;
    bytes proofBytes;

    function setUp() public {
        string memory j = vm.readFile("test/fixtures/p10_storage_proof.json");
        srcChainId = vm.parseJsonUint(j, ".sourceChainId");
        blockNumber = vm.parseJsonUint(j, ".blockNumber");
        stateRoot = vm.parseJsonBytes32(j, ".stateRoot");
        sourceVault = vm.parseJsonAddress(j, ".sourceVault");
        commitId = vm.parseJsonBytes32(j, ".commitId");
        destRecipient = vm.parseJsonAddress(j, ".destRecipient");
        amount = vm.parseUint(vm.parseJsonString(j, ".amount"));

        accountProof = vm.parseJsonBytes(j, ".accountProof");
        recipientProof = vm.parseJsonBytes(j, ".recipientProof");
        amountProof = vm.parseJsonBytes(j, ".amountProof");
        statusProof = vm.parseJsonBytes(j, ".statusProof");
        proofBytes = _proof(blockNumber);

        oracle = new MockHeaderOracle();
        oracle.set(srcChainId, blockNumber, stateRoot);
        verifier = new StorageProofSourceLockVerifier(ISourceHeaderOracle(address(oracle)));

        // The fixture chain == this test chain; destChainId must equal block.chainid.
        vm.chainId(srcChainId);
    }

    function _claim() internal view returns (LockClaim memory) {
        return LockClaim({
            sourceChainId: srcChainId,
            sourceVault: sourceVault,
            commitId: commitId,
            destRecipient: destRecipient,
            amount: amount,
            destChainId: block.chainid
        });
    }

    /// The headline: a REAL storage proof of a real lock verifies true.
    function test_RealFixture_VerifiesLock() public view {
        assertTrue(verifier.verifyLock(_claim(), proofBytes), "real source-lock proof must verify");
    }

    function test_WrongAmount_Rejected() public view {
        LockClaim memory c = _claim();
        c.amount = amount + 1;
        assertFalse(verifier.verifyLock(c, proofBytes));
    }

    function test_WrongRecipient_Rejected() public view {
        LockClaim memory c = _claim();
        c.destRecipient = address(0xdead);
        assertFalse(verifier.verifyLock(c, proofBytes));
    }

    function test_WrongCommitId_Rejected() public view {
        LockClaim memory c = _claim();
        c.commitId = keccak256("not-the-real-commit"); // different slot => exclusion / mismatch
        // a valid proof for a different slot path is not supplied, so the MPT verifier
        // reverts (forged path) — wrap to assert it does not verify.
        try verifier.verifyLock(c, proofBytes) returns (bool ok) {
            assertFalse(ok);
        } catch {
            // revert on a path that doesn't match the proof is acceptable (not a true claim)
        }
    }

    function test_UnknownBlock_Rejected() public view {
        // header oracle has no root for a different block => stateRoot 0 => false
        assertFalse(verifier.verifyLock(_claim(), _proof(blockNumber + 999)));
    }

    function test_WrongStateRoot_Reverts() public {
        // a header oracle that returns a bogus (non-zero) root => the MPT account
        // proof cannot chain to it => the verifier reverts (cannot forge a proof).
        MockHeaderOracle bad = new MockHeaderOracle();
        bad.set(srcChainId, blockNumber, keccak256("bogus-root"));
        StorageProofSourceLockVerifier v2 =
            new StorageProofSourceLockVerifier(ISourceHeaderOracle(address(bad)));
        vm.expectRevert();
        v2.verifyLock(_claim(), proofBytes);
    }

    function test_DestChainMismatch_Rejected() public {
        LockClaim memory c = _claim();
        c.destChainId = block.chainid + 1;
        assertFalse(verifier.verifyLock(c, proofBytes));
    }

    function _proof(uint256 blockNum) internal view returns (bytes memory) {
        return abi.encode(blockNum, accountProof, recipientProof, amountProof, statusProof);
    }
}
