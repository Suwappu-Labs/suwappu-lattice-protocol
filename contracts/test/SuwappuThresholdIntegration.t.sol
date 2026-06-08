// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuVault} from "../src/SuwappuVault.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";
import {SuwappuThresholdMintVerifier} from "../src/verifiers/SuwappuThresholdMintVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SuwappuThresholdIntegrationTest
/// @notice End-to-end wiring of the k-of-N threshold verifier as the bridge's
///         trust root: Vault + MintAdapter + WrappedToken, with the SAME
///         threshold verifier gating BOTH adapter.mint and vault.claimRefund.
///         Asserts that exactly K authorized signatures authorize a mint and a
///         refund, while K-1 signatures are rejected on both paths.
contract SuwappuThresholdIntegrationTest is Test {
    SuwappuVault internal vault;
    SuwappuMintAdapter internal adapter;
    SuwappuWrappedToken internal wrapped;
    SuwappuThresholdMintVerifier internal verifier;

    address internal constant ADMIN = address(0xA1);
    address internal constant MINTER_MANAGER = address(0xA2); // P3-3: distinct from admin
    address internal constant ETH = address(0);
    address internal constant USER = address(0xBEEF);
    address internal constant RELAYER = address(0xCAFE);

    uint256 internal constant DEST = 8453; // nominal destination chain

    uint256 internal constant THRESHOLD = 2; // K
    uint256[] internal operatorPks; // N = 3

    function setUp() public {
        // Three operators, K = 2.
        operatorPks.push(0xA11CE);
        operatorPks.push(0xB0B);
        operatorPks.push(0xCA710);

        vault = new SuwappuVault(ADMIN, ADMIN, 0); // feeBps = 0 → net == gross

        wrapped = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether",
            "swETH",
            18,
            block.chainid,
            ETH,
            ADMIN,
            MINTER_MANAGER // P3-3 guard: admin != minterManager
        );

        adapter = new SuwappuMintAdapter(ADMIN, address(wrapped));

        verifier = new SuwappuThresholdMintVerifier(ADMIN, THRESHOLD);

        vm.startPrank(MINTER_MANAGER);
        wrapped.grantRole(wrapped.MINTER_ROLE(), address(adapter));
        wrapped.grantRole(wrapped.BURNER_ROLE(), address(adapter));
        vm.stopPrank();

        vm.startPrank(ADMIN);
        adapter.addRelayer(RELAYER);
        adapter.setVerifier(address(verifier));
        vault.setRefundVerifier(address(verifier)); // same trust root gates refunds
        verifier.setOperator(vm.addr(operatorPks[0]), true);
        verifier.setOperator(vm.addr(operatorPks[1]), true);
        verifier.setOperator(vm.addr(operatorPks[2]), true);
        vm.stopPrank();
    }

    // ---- sig helpers ----

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _sortByAddress(uint256[] memory pks) internal pure {
        for (uint256 i = 0; i < pks.length; i++) {
            for (uint256 j = i + 1; j < pks.length; j++) {
                if (vm.addr(pks[j]) < vm.addr(pks[i])) {
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
            }
        }
    }

    /// @dev abi.encode(bytes[] sigs) over `digest` from the first `n` operator
    ///      keys, ordered by ascending signer address.
    function _attest(uint256 n, bytes32 digest) internal view returns (bytes memory) {
        uint256[] memory pks = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            pks[i] = operatorPks[i];
        }
        _sortByAddress(pks);
        bytes[] memory sigs = new bytes[](n);
        for (uint256 i = 0; i < n; i++) {
            sigs[i] = _sign(pks[i], digest);
        }
        return abi.encode(sigs);
    }

    // ---- mint path ----

    function test_Mint_WithKofN_Succeeds() public {
        bytes32 commitId = keccak256("commit-1");
        uint256 amount = 5 ether;
        bytes32 digest = adapter.mintDigest(commitId, USER, amount, block.chainid);

        vm.prank(RELAYER);
        adapter.mint(commitId, USER, amount, block.chainid, _attest(THRESHOLD, digest));

        assertEq(wrapped.balanceOf(USER), amount);
        assertTrue(adapter.isMinted(commitId));
    }

    function test_Mint_WithKminus1_Reverts() public {
        bytes32 commitId = keccak256("commit-2");
        uint256 amount = 3 ether;
        bytes32 digest = adapter.mintDigest(commitId, USER, amount, block.chainid);

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuMintAdapter.InvalidAttestation.selector, digest)
        );
        adapter.mint(commitId, USER, amount, block.chainid, _attest(THRESHOLD - 1, digest));

        assertFalse(adapter.isMinted(commitId));
        assertEq(wrapped.balanceOf(USER), 0);
    }

    // ---- refund path ----

    function test_Refund_WithKofN_Succeeds() public {
        // User locks ETH on the source chain.
        vm.deal(USER, 10 ether);
        vm.prank(USER);
        bytes32 commitId = vault.lockETH{value: 4 ether}(DEST, USER);

        // Refund only becomes claimable after the timeout.
        vm.warp(block.timestamp + vault.refundTimeout() + 1);

        bytes32 digest = vault.refundDigest(commitId);
        uint256 balBefore = USER.balance;

        vault.claimRefund(commitId, _attest(THRESHOLD, digest));

        assertEq(USER.balance, balBefore + 4 ether);
        assertEq(vault.totalLocked(ETH), 0);
    }

    function test_Refund_WithKminus1_Reverts() public {
        vm.deal(USER, 10 ether);
        vm.prank(USER);
        bytes32 commitId = vault.lockETH{value: 4 ether}(DEST, USER);

        vm.warp(block.timestamp + vault.refundTimeout() + 1);

        bytes32 digest = vault.refundDigest(commitId);
        vm.expectRevert(abi.encodeWithSelector(SuwappuVault.RefundNotAuthorized.selector, digest));
        vault.claimRefund(commitId, _attest(THRESHOLD - 1, digest));

        // Funds remain locked.
        assertEq(vault.totalLocked(ETH), 4 ether);
    }
}
