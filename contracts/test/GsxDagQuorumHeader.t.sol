// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GsxDagValidatorRegistry} from "../src/verifiers/GsxDagValidatorRegistry.sol";
import {GsxDagQuorumHeaderOracle} from "../src/verifiers/GsxDagQuorumHeaderOracle.sol";

/// @notice Mock BLAKE3 precompile (0x0102): returns keccak256(input) as the 32-byte
///         "hash". A deterministic stand-in so the registry/oracle logic is tested
///         without the native precompile (whose real BLAKE3 is verified in gsx-revm).
contract MockBlake3 {
    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encodePacked(keccak256(input));
    }
}

/// @notice Mock ML-DSA precompile (0x0101): input = pubkey(32)||sig(32)||digest(32);
///         "valid" iff sig == keccak256("MOCK_MLDSA" || pubkey || digest). The test
///         "signs" with that convention. Returns a 32-byte word (last byte 1/0).
contract MockMldsa {
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 96) return abi.encodePacked(bytes32(0));
        bytes32 pk = bytes32(input[0:32]);
        bytes32 sig = bytes32(input[32:64]);
        bytes32 digest = bytes32(input[64:96]);
        bytes32 expected = keccak256(abi.encodePacked("MOCK_MLDSA", pk, digest));
        return abi.encodePacked(sig == expected ? bytes32(uint256(1)) : bytes32(0));
    }
}

contract GsxDagQuorumTest is Test {
    GsxDagValidatorRegistry registry;
    GsxDagQuorumHeaderOracle oracle;

    address admin = makeAddr("admin");
    uint256 constant NETWORK_ID = 7777;
    uint256 constant GSXDAG_CHAIN = 909090;

    // epoch 0: 4 validators, 25 stake each (total 100; quorum = 2/3*100+1 = 67)
    bytes[] pk; // 32-byte mock pubkeys
    bytes32[] pkHash;
    uint256[] stake;

    function setUp() public {
        // mock precompiles
        vm.etch(address(0x0102), address(new MockBlake3()).code);
        vm.etch(address(0x0101), address(new MockMldsa()).code);

        registry = new GsxDagValidatorRegistry(admin, NETWORK_ID);
        oracle = new GsxDagQuorumHeaderOracle(registry, GSXDAG_CHAIN);

        // build 4 validators sorted by keccak(pubkey)
        (pk, pkHash, stake) = _buildSet(4, 25);
        vm.prank(admin);
        registry.bootstrapEpoch0(pkHash, stake);
    }

    // ---- helpers ----

    function _buildSet(uint256 n, uint256 perStake)
        internal
        pure
        returns (bytes[] memory pks, bytes32[] memory hashes, uint256[] memory stakes)
    {
        pks = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = abi.encodePacked(keccak256(abi.encodePacked("validator", i)));
        }
        // sort by keccak(pubkey)
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (keccak256(pks[j]) < keccak256(pks[i])) {
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
        hashes = new bytes32[](n);
        stakes = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            hashes[i] = keccak256(pks[i]);
            stakes[i] = perStake;
        }
    }

    /// Sign `digest` with the first `k` validators of `pubkeys` (already sorted).
    function _quorum(bytes[] memory pubkeys, bytes32 digest, uint256 k)
        internal
        pure
        returns (bytes[] memory subPk, bytes[] memory sigs)
    {
        subPk = new bytes[](k);
        sigs = new bytes[](k);
        for (uint256 i = 0; i < k; i++) {
            subPk[i] = pubkeys[i];
            bytes32 sig = keccak256(abi.encodePacked("MOCK_MLDSA", bytes32(pubkeys[i]), digest));
            sigs[i] = abi.encodePacked(sig);
        }
    }

    function _headerDigest(uint256 blockNumber, bytes32 stateRoot) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                oracle.HEADER_DOMAIN(), NETWORK_ID, address(oracle), blockNumber, stateRoot
            )
        );
    }

    // ---- header oracle ----

    function test_QuorumFinalizesHeader() public {
        bytes32 root = keccak256("state-root-1");
        bytes32 d = _headerDigest(100, root);
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, d, 3); // 3*25=75 >= 67
        oracle.submitHeader(100, root, 0, sp, sg);

        assertEq(oracle.headerStateRoot(GSXDAG_CHAIN, 100), root);
        assertEq(oracle.headerStateRoot(GSXDAG_CHAIN + 1, 100), bytes32(0)); // wrong chain
    }

    function test_BelowQuorum_Reverts() public {
        bytes32 root = keccak256("state-root-1");
        bytes32 d = _headerDigest(100, root);
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, d, 2); // 2*25=50 < 67
        vm.expectRevert(
            abi.encodeWithSelector(GsxDagQuorumHeaderOracle.BelowQuorum.selector, 50, 67)
        );
        oracle.submitHeader(100, root, 0, sp, sg);
    }

    function test_TamperedRoot_NotSigned_BelowQuorum() public {
        bytes32 root = keccak256("state-root-1");
        bytes32 d = _headerDigest(100, root);
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, d, 3);
        // submit with a DIFFERENT root than the one signed -> sigs don't match digest
        bytes32 other = keccak256("evil-root");
        vm.expectRevert(
            abi.encodeWithSelector(GsxDagQuorumHeaderOracle.BelowQuorum.selector, 0, 67)
        );
        oracle.submitHeader(100, other, 0, sp, sg);
    }

    function test_Equivocation_Reverts() public {
        bytes32 root = keccak256("state-root-1");
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, _headerDigest(100, root), 3);
        oracle.submitHeader(100, root, 0, sp, sg);

        bytes32 other = keccak256("state-root-2");
        (bytes[] memory sp2, bytes[] memory sg2) = _quorum(pk, _headerDigest(100, other), 3);
        vm.expectRevert(
            abi.encodeWithSelector(GsxDagQuorumHeaderOracle.HeaderConflict.selector, 100)
        );
        oracle.submitHeader(100, other, 0, sp2, sg2);
    }

    function test_StaleEpoch_Reverts() public {
        bytes32 root = keccak256("state-root-1");
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, _headerDigest(100, root), 3);
        vm.expectRevert(
            abi.encodeWithSelector(GsxDagQuorumHeaderOracle.StaleEpoch.selector, 1, 0)
        );
        oracle.submitHeader(100, root, 1, sp, sg);
    }

    // ---- epoch transitions ----

    function _epochDigest(uint256 newEpoch, bytes32[] memory nh, uint256[] memory ns)
        internal
        view
        returns (bytes32)
    {
        bytes32 setHash = keccak256(abi.encode(newEpoch, nh, ns));
        return keccak256(
            abi.encodePacked(
                registry.EPOCH_DOMAIN(), NETWORK_ID, address(registry), newEpoch, setHash
            )
        );
    }

    function test_EpochTransition_ThenNewSetSignsHeader() public {
        // new epoch-1 set: 3 different validators, 40 stake each (total 120)
        (bytes[] memory npk, bytes32[] memory nh, uint256[] memory ns) = _buildSetSeeded(3, 40, 100);

        bytes32 d = _epochDigest(1, nh, ns);
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, d, 3); // 75 >= 67 of epoch-0
        registry.transitionEpoch(1, nh, ns, sp, sg);
        assertEq(registry.currentEpoch(), 1);
        assertEq(registry.totalStake(1), 120);

        // epoch-0 validators can no longer finalize headers (epoch must be current=1)
        bytes32 root = keccak256("root-after-transition");
        (bytes[] memory osp, bytes[] memory osg) = _quorum(pk, _headerDigest(200, root), 3);
        vm.expectRevert(); // StaleEpoch(0,1)
        oracle.submitHeader(200, root, 0, osp, osg);

        // the NEW set finalizes it (quorum of epoch 1 = 2/3*120+1 = 81; 3*40=120 >= 81)
        (bytes[] memory nsp, bytes[] memory nsg) = _quorum(npk, _headerDigest(200, root), 3);
        oracle.submitHeader(200, root, 1, nsp, nsg);
        assertEq(oracle.headerStateRoot(GSXDAG_CHAIN, 200), root);
    }

    function test_EpochTransition_BelowQuorum_Reverts() public {
        (, bytes32[] memory nh, uint256[] memory ns) = _buildSetSeeded(3, 40, 100);
        bytes32 d = _epochDigest(1, nh, ns);
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, d, 2); // 50 < 67
        vm.expectRevert(
            abi.encodeWithSelector(GsxDagValidatorRegistry.QuorumNotMet.selector, 50, 67)
        );
        registry.transitionEpoch(1, nh, ns, sp, sg);
    }

    function test_UnsortedSigners_Reverts() public {
        bytes32 root = keccak256("state-root-1");
        bytes32 d = _headerDigest(100, root);
        (bytes[] memory sp, bytes[] memory sg) = _quorum(pk, d, 3);
        // swap two signers out of order
        (sp[0], sp[1]) = (sp[1], sp[0]);
        (sg[0], sg[1]) = (sg[1], sg[0]);
        vm.expectRevert(GsxDagValidatorRegistry.UnsortedOrDuplicate.selector);
        oracle.submitHeader(100, root, 0, sp, sg);
    }

    function test_NonValidatorSigner_DoesNotCount() public {
        // a quorum of 2 real validators + 1 non-validator (valid mock sig) = 50 < 67
        bytes32 root = keccak256("state-root-1");
        bytes32 d = _headerDigest(100, root);
        bytes memory rogue = abi.encodePacked(keccak256("rogue-validator"));
        // build [v0, v1, rogue] sorted by pkHash, all with valid mock sigs
        bytes[] memory three = new bytes[](3);
        three[0] = pk[0];
        three[1] = pk[1];
        three[2] = rogue;
        // sort
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (keccak256(three[j]) < keccak256(three[i])) {
                    (three[i], three[j]) = (three[j], three[i]);
                }
            }
        }
        bytes[] memory sigs = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            sigs[i] =
                abi.encodePacked(keccak256(abi.encodePacked("MOCK_MLDSA", bytes32(three[i]), d)));
        }
        vm.expectRevert(
            abi.encodeWithSelector(GsxDagQuorumHeaderOracle.BelowQuorum.selector, 50, 67)
        );
        oracle.submitHeader(100, root, 0, three, sigs);
    }

    // a second seeded set whose pubkeys differ from the genesis set
    function _buildSetSeeded(uint256 n, uint256 perStake, uint256 seed)
        internal
        pure
        returns (bytes[] memory pks, bytes32[] memory hashes, uint256[] memory stakes)
    {
        pks = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = abi.encodePacked(keccak256(abi.encodePacked("validator", seed + i)));
        }
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (keccak256(pks[j]) < keccak256(pks[i])) (pks[i], pks[j]) = (pks[j], pks[i]);
            }
        }
        hashes = new bytes32[](n);
        stakes = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            hashes[i] = keccak256(pks[i]);
            stakes[i] = perStake;
        }
    }
}
