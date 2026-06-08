// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CommitteeHeaderOracle} from "../src/verifiers/CommitteeHeaderOracle.sol";
import {Sp1HeliosHeaderOracle, ISP1Helios} from "../src/verifiers/Sp1HeliosHeaderOracle.sol";
import {StorageProofSourceLockVerifier} from "../src/verifiers/StorageProofSourceLockVerifier.sol";
import {ISourceHeaderOracle} from "../src/interfaces/ISourceHeaderOracle.sol";
import {ISourceLockVerifier, LockClaim} from "../src/interfaces/ISourceLockVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MockSP1Helios is ISP1Helios {
    mapping(uint256 => bytes32) public roots;

    function setRoot(uint256 slot, bytes32 root) external {
        roots[slot] = root;
    }

    function executionStateRoots(uint256 slot) external view returns (bytes32) {
        return roots[slot];
    }
}

/// @notice P10 Phase C: header-trust oracles + the END-TO-END capstone (committee
///         finalizes a header, storage proof verifies the real lock against it).
contract P10HeaderOracleTest is Test {
    CommitteeHeaderOracle committee;
    address admin = makeAddr("admin");

    uint256 constant SRC = 84_532;
    uint256 constant BLK = 100;
    bytes32 constant ROOT = keccak256("source-state-root");

    // 3 validators; keys chosen so we can sort by address.
    uint256[] vpk;
    address[] vaddr;

    function setUp() public {
        committee = new CommitteeHeaderOracle(admin);
        for (uint256 i = 0; i < 3; i++) {
            uint256 pk = uint256(keccak256(abi.encode("validator", i)));
            vpk.push(pk);
            vaddr.push(vm.addr(pk));
        }
        vm.startPrank(admin);
        for (uint256 i = 0; i < 3; i++) {
            committee.setValidator(SRC, vaddr[i], true);
        }
        committee.setThreshold(SRC, 2); // 2-of-3
        vm.stopPrank();
    }

    /// Build `n` signatures over the header digest, in strictly-increasing signer
    /// address order (as submitHeader requires).
    function _sigs(uint256 srcChain, uint256 blk, bytes32 root, uint256 n)
        internal
        view
        returns (bytes[] memory)
    {
        // sort validator pks by address
        uint256[] memory pks = vpk;
        for (uint256 i = 0; i < pks.length; i++) {
            for (uint256 j = i + 1; j < pks.length; j++) {
                if (vm.addr(pks[j]) < vm.addr(pks[i])) {
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
        bytes32 ethHash =
            MessageHashUtils.toEthSignedMessageHash(committee.headerDigest(srcChain, blk, root));
        bytes[] memory out = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], ethHash);
            out[i] = abi.encodePacked(r, s, v);
        }
        return out;
    }

    // ---- CommitteeHeaderOracle ----

    function test_Quorum_FinalizesHeader() public {
        committee.submitHeader(SRC, BLK, ROOT, _sigs(SRC, BLK, ROOT, 2));
        assertEq(committee.headerStateRoot(SRC, BLK), ROOT);
    }

    function test_BelowQuorum_Reverts() public {
        bytes[] memory sigs = _sigs(SRC, BLK, ROOT, 1);
        vm.expectRevert(abi.encodeWithSelector(CommitteeHeaderOracle.BelowQuorum.selector, 1, 2));
        committee.submitHeader(SRC, BLK, ROOT, sigs);
    }

    function test_Equivocation_Reverts() public {
        committee.submitHeader(SRC, BLK, ROOT, _sigs(SRC, BLK, ROOT, 2));
        bytes32 other = keccak256("different-root");
        bytes[] memory sigs = _sigs(SRC, BLK, other, 2);
        vm.expectRevert(
            abi.encodeWithSelector(CommitteeHeaderOracle.HeaderConflict.selector, SRC, BLK)
        );
        committee.submitHeader(SRC, BLK, other, sigs);
    }

    function test_IdenticalResubmit_NoOp() public {
        committee.submitHeader(SRC, BLK, ROOT, _sigs(SRC, BLK, ROOT, 2));
        committee.submitHeader(SRC, BLK, ROOT, _sigs(SRC, BLK, ROOT, 2)); // no revert
        assertEq(committee.headerStateRoot(SRC, BLK), ROOT);
    }

    function test_UnauthorizedSigner_DoesNotCount() public {
        // sign with a non-validator key in addition; only 1 real validator => below quorum
        uint256 rogue = uint256(keccak256("rogue"));
        bytes32 ethHash =
            MessageHashUtils.toEthSignedMessageHash(committee.headerDigest(SRC, BLK, ROOT));
        // one real validator + one rogue, sorted
        uint256 real = vpk[0];
        uint256[] memory two = new uint256[](2);
        two[0] = real;
        two[1] = rogue;
        if (vm.addr(two[1]) < vm.addr(two[0])) (two[0], two[1]) = (two[1], two[0]);
        bytes[] memory sigs = new bytes[](2);
        for (uint256 i = 0; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(two[i], ethHash);
            sigs[i] = abi.encodePacked(r, s, v);
        }
        vm.expectRevert(abi.encodeWithSelector(CommitteeHeaderOracle.BelowQuorum.selector, 1, 2));
        committee.submitHeader(SRC, BLK, ROOT, sigs);
    }

    function test_DigestBindsInstance() public {
        // a signature for THIS oracle must not finalize on a DIFFERENT oracle instance
        CommitteeHeaderOracle other = new CommitteeHeaderOracle(admin);
        vm.startPrank(admin);
        for (uint256 i = 0; i < 3; i++) {
            other.setValidator(SRC, vaddr[i], true);
        }
        other.setThreshold(SRC, 2);
        vm.stopPrank();
        // sigs are over `committee`'s digest (binds address(committee)); replayed on
        // `other` they recover to non-validators (and/or out of order) => rejected
        // (BelowQuorum or BadSignature — either way the replay cannot finalize).
        bytes[] memory sigs = _sigs(SRC, BLK, ROOT, 2);
        vm.expectRevert();
        other.submitHeader(SRC, BLK, ROOT, sigs);
        assertEq(other.headerStateRoot(SRC, BLK), bytes32(0), "replay must not finalize");
    }

    function test_Governance_RemovalBelowQuorumReverts() public {
        vm.prank(admin);
        // N=3, K=2; removing one => N=2 ok; removing a second => N=1 < K=2 revert
        committee.setValidator(SRC, vaddr[0], false);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(CommitteeHeaderOracle.InvalidThreshold.selector, 2, 1)
        );
        committee.setValidator(SRC, vaddr[1], false);
    }

    // ---- Sp1HeliosHeaderOracle ----

    function test_Sp1Helios_SurfacesProvenRoot() public {
        MockSP1Helios helios = new MockSP1Helios();
        helios.setRoot(BLK, ROOT);
        Sp1HeliosHeaderOracle oracle = new Sp1HeliosHeaderOracle(ISP1Helios(address(helios)), SRC);
        assertEq(oracle.headerStateRoot(SRC, BLK), ROOT);
        assertEq(oracle.headerStateRoot(SRC + 1, BLK), bytes32(0)); // wrong chain
        assertEq(oracle.headerStateRoot(SRC, BLK + 1), bytes32(0)); // unproven slot
    }

    // ---- INTEGRATION: header oracle composes with the storage-proof verifier ----

    /// Integration test: a committee-finalized header root is consumed by the
    /// storage-proof verifier to prove the REAL fixture lock. The MPT inclusion
    /// proof is real and trust-minimized; the HEADER trust under this oracle is an
    /// M-of-N committee (NOT minimized — see CommitteeHeaderOracle). This proves
    /// the two halves compose; genuine header trust-minimization needs
    /// Sp1HeliosHeaderOracle (or a true consensus client) as the root.
    function test_Integration_CommitteeHeader_Then_StorageProof() public {
        string memory j = vm.readFile("test/fixtures/p10_storage_proof.json");
        uint256 srcChainId = vm.parseJsonUint(j, ".sourceChainId");
        uint256 blockNumber = vm.parseJsonUint(j, ".blockNumber");
        bytes32 stateRoot = vm.parseJsonBytes32(j, ".stateRoot");
        address sourceVault = vm.parseJsonAddress(j, ".sourceVault");
        bytes32 commitId = vm.parseJsonBytes32(j, ".commitId");
        address destRecipient = vm.parseJsonAddress(j, ".destRecipient");
        uint256 amount = vm.parseUint(vm.parseJsonString(j, ".amount"));
        bytes memory proof = abi.encode(
            blockNumber,
            vm.parseJsonBytes(j, ".accountProof"),
            vm.parseJsonBytes(j, ".recipientProof"),
            vm.parseJsonBytes(j, ".amountProof"),
            vm.parseJsonBytes(j, ".statusProof")
        );

        // committee for the fixture's source chain
        CommitteeHeaderOracle oracle = new CommitteeHeaderOracle(admin);
        vm.startPrank(admin);
        for (uint256 i = 0; i < 3; i++) {
            oracle.setValidator(srcChainId, vaddr[i], true);
        }
        oracle.setThreshold(srcChainId, 2);
        vm.stopPrank();

        // 2-of-3 validators attest the real state root
        bytes32 eh = MessageHashUtils.toEthSignedMessageHash(
            oracle.headerDigest(srcChainId, blockNumber, stateRoot)
        );
        uint256[] memory pks = vpk;
        for (uint256 i = 0; i < pks.length; i++) {
            for (uint256 k = i + 1; k < pks.length; k++) {
                if (vm.addr(pks[k]) < vm.addr(pks[i])) (pks[i], pks[k]) = (pks[k], pks[i]);
            }
        }
        bytes[] memory sigs = new bytes[](2);
        for (uint256 i = 0; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], eh);
            sigs[i] = abi.encodePacked(r, s, v);
        }
        oracle.submitHeader(srcChainId, blockNumber, stateRoot, sigs);

        // now the storage-proof verifier trusts that committee-finalized root
        StorageProofSourceLockVerifier verifier =
            new StorageProofSourceLockVerifier(ISourceHeaderOracle(address(oracle)));

        vm.chainId(srcChainId); // fixture chain == this chain; destChainId must equal block.chainid
        LockClaim memory claim = LockClaim({
            sourceChainId: srcChainId,
            sourceVault: sourceVault,
            commitId: commitId,
            destRecipient: destRecipient,
            amount: amount,
            destChainId: block.chainid
        });
        assertTrue(
            verifier.verifyLock(claim, proof),
            "inclusion verifier must compose with the committee-finalized header"
        );
    }
}
