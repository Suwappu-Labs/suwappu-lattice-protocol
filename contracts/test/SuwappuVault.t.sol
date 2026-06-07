// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {SuwappuVault} from "../src/SuwappuVault.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MockERC20 {
    string public name = "Mock USDC";
    string public symbol = "USDC";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "MockERC20: insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract SuwappuVaultTest is Test {
    SuwappuVault vault;
    MockERC20 usdc;

    address admin    = makeAddr("admin");
    address relayer  = makeAddr("relayer");
    address alice    = makeAddr("alice");
    address bob      = makeAddr("bob");
    address treasury = makeAddr("treasury");

    uint256 constant DEST_CHAIN = 8453; // Base
    uint256 constant FEE_BPS    = 50;   // 0.50%

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    SuwappuEcdsaMintVerifier refundVerifier;
    uint256 constant OPERATOR_PK = 0xA110CE;
    address operator;

    function setUp() public {
        vault = new SuwappuVault(admin, treasury, FEE_BPS);
        usdc  = new MockERC20();
        refundVerifier = new SuwappuEcdsaMintVerifier(admin);
        operator = vm.addr(OPERATOR_PK);

        vm.startPrank(admin);
        vault.addUnlocker(relayer);
        vault.setRefundVerifier(address(refundVerifier));
        refundVerifier.setOperator(operator, true);
        vault.setTVLCap(address(0),         5_000 ether);  // ETH cap
        vault.setTVLCap(address(usdc),      5_000_000e6);  // USDC cap
        vault.setDailyCap(address(0),       1_000 ether);
        vault.setDailyCap(address(usdc),    2_000_000e6);
        vm.stopPrank();

        // Fund test accounts
        vm.deal(alice, 10 ether);
        usdc.mint(alice, 1_000_000e6);
    }

    /// Operator refund-eligibility attestation for a commit (C2 gate).
    function _refundAtt(bytes32 commitId) internal view returns (bytes memory) {
        bytes32 digest = vault.refundDigest(commitId);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPERATOR_PK, ethHash);
        return abi.encodePacked(r, s, v);
    }

    // -----------------------------------------------------------------------
    // lockETH
    // -----------------------------------------------------------------------

    function test_lockETH_emitsLocked() public {
        // topics: [selector, commitId, token, from]
        // Use expectEmit to match indexed commitId/token/from
        vm.prank(alice);
        vm.recordLogs();
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // topics[1] = commitId (first indexed)
        assertEq(logs[0].topics[1], commitId, "commitId indexed topic");
        // topics[2] = token = address(0) for ETH
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(address(0)))), "token=ETH");
        // topics[3] = from = alice
        assertEq(logs[0].topics[3], bytes32(uint256(uint160(alice))), "from=alice");

        assertTrue(commitId != bytes32(0), "commitId non-zero");
    }

    function test_lockETH_storesCommit() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        SuwappuVault.CommitData memory c = vault.getCommit(commitId);
        assertEq(c.token,         address(0));
        assertEq(c.from,          alice);
        assertEq(c.destRecipient, bob);
        assertEq(c.destChainId,   DEST_CHAIN);
        // net = 1 ether - 0.5% fee = 1 ether - 5e15
        uint256 expectedNet = 1 ether - (1 ether * FEE_BPS / 10_000);
        assertEq(c.amount, expectedNet);
        assertEq(uint8(c.status), uint8(SuwappuVault.LockStatus.LOCKED));
    }

    function test_lockETH_accumulatesTotalLocked() public {
        vm.prank(alice);
        vault.lockETH{value: 2 ether}(DEST_CHAIN, bob);
        uint256 expected = 2 ether - (2 ether * FEE_BPS / 10_000);
        assertEq(vault.totalLocked(address(0)), expected);
    }

    function test_lockETH_reverts_zeroValue() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuVault.ZeroAmount.selector);
        vault.lockETH{value: 0}(DEST_CHAIN, bob);
    }

    function test_lockETH_reverts_zeroDestRecipient() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuVault.ZeroAddress.selector);
        vault.lockETH{value: 1 ether}(DEST_CHAIN, address(0));
    }

    function test_lockETH_reverts_tvlCapExceeded() public {
        // Cap is 5_000 ether; alice only has 10 — set a tiny cap to trigger
        vm.prank(admin);
        vault.setTVLCap(address(0), 0.5 ether);

        vm.prank(alice);
        vm.expectRevert();
        vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);
    }

    function test_lockETH_reverts_dailyCapExceeded() public {
        vm.prank(admin);
        vault.setDailyCap(address(0), 0.5 ether);

        vm.prank(alice);
        vm.expectRevert();
        vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);
    }

    function test_lockETH_uniqueCommitIds() public {
        vm.startPrank(alice);
        bytes32 a = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);
        bytes32 b = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);
        vm.stopPrank();
        assertTrue(a != b, "commitIds must be unique");
    }

    // -----------------------------------------------------------------------
    // lockERC20
    // -----------------------------------------------------------------------

    function test_lockERC20_transfers_and_storesCommit() public {
        uint256 amount = 1_000e6;
        vm.startPrank(alice);
        usdc.approve(address(vault), amount);
        bytes32 commitId = vault.lockERC20(address(usdc), amount, DEST_CHAIN, bob);
        vm.stopPrank();

        // Vault holds the full amount
        assertEq(usdc.balanceOf(address(vault)), amount);
        // Net amount = amount - fee
        uint256 expectedNet = amount - (amount * FEE_BPS / 10_000);
        assertEq(vault.getCommit(commitId).amount, expectedNet);
        assertEq(vault.totalLocked(address(usdc)), expectedNet);
    }

    function test_lockERC20_reverts_zeroToken() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuVault.ZeroAddress.selector);
        vault.lockERC20(address(0), 1e6, DEST_CHAIN, bob);
    }

    function test_lockERC20_reverts_zeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuVault.ZeroAmount.selector);
        vault.lockERC20(address(usdc), 0, DEST_CHAIN, bob);
    }

    // -----------------------------------------------------------------------
    // unlock
    // -----------------------------------------------------------------------

    function test_unlock_releasesETH() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        uint256 netAmount = vault.getCommit(commitId).amount;
        uint256 bobBefore = bob.balance;

        vm.prank(relayer);
        vault.unlock(commitId, bob);

        assertEq(bob.balance, bobBefore + netAmount);
        assertEq(uint8(vault.getCommit(commitId).status), uint8(SuwappuVault.LockStatus.UNLOCKED));
        assertEq(vault.totalLocked(address(0)), 0);
    }

    function test_unlock_releasesERC20() public {
        uint256 gross = 1_000e6;
        vm.startPrank(alice);
        usdc.approve(address(vault), gross);
        bytes32 commitId = vault.lockERC20(address(usdc), gross, DEST_CHAIN, bob);
        vm.stopPrank();

        uint256 netAmount = vault.getCommit(commitId).amount;
        vm.prank(relayer);
        vault.unlock(commitId, bob);

        assertEq(usdc.balanceOf(bob), netAmount);
        assertEq(uint8(vault.getCommit(commitId).status), uint8(SuwappuVault.LockStatus.UNLOCKED));
    }

    function test_unlock_reverts_notUnlocker() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        vm.prank(alice); // not a relayer
        vm.expectRevert(SuwappuVault.Unauthorized.selector);
        vault.unlock(commitId, bob);
    }

    function test_unlock_reverts_doubleUnlock() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        vm.startPrank(relayer);
        vault.unlock(commitId, bob);
        vm.expectRevert(); // CommitNotLocked
        vault.unlock(commitId, bob);
        vm.stopPrank();
    }

    function test_unlock_reverts_unknownCommitId() public {
        vm.prank(relayer);
        vm.expectRevert();
        vault.unlock(bytes32(uint256(0xdeadbeef)), bob);
    }

    // -----------------------------------------------------------------------
    // claimRefund
    // -----------------------------------------------------------------------

    function test_claimRefund_returnsETH_afterTimeout() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        uint256 netAmount = vault.getCommit(commitId).amount;
        uint256 aliceBefore = alice.balance;

        // Advance past refund timeout
        vm.warp(block.timestamp + vault.refundTimeout() + 1);
        vault.claimRefund(commitId, _refundAtt(commitId));

        assertEq(alice.balance, aliceBefore + netAmount);
        assertEq(uint8(vault.getCommit(commitId).status), uint8(SuwappuVault.LockStatus.REFUNDED));
        assertEq(vault.totalLocked(address(0)), 0);
    }

    function test_claimRefund_reverts_beforeTimeout() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        vm.expectRevert();
        vault.claimRefund(commitId, "");
    }

    function test_claimRefund_reverts_afterUnlock() public {
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        vm.prank(relayer);
        vault.unlock(commitId, bob);

        vm.warp(block.timestamp + vault.refundTimeout() + 1);
        vm.expectRevert();
        vault.claimRefund(commitId, ""); // already UNLOCKED
    }

    // -----------------------------------------------------------------------
    // Fees
    // -----------------------------------------------------------------------

    function test_sweepFees_collectsETHFee() public {
        vm.prank(alice);
        vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        uint256 expectedFee = 1 ether * FEE_BPS / 10_000;
        assertEq(vault.pendingFees(address(0)), expectedFee);

        uint256 treasuryBefore = treasury.balance;
        vm.prank(admin);
        vault.sweepFees(address(0));
        assertEq(treasury.balance, treasuryBefore + expectedFee);
        assertEq(vault.pendingFees(address(0)), 0);
    }

    function test_sweepFees_onlyAdmin() public {
        vm.prank(alice);
        vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);

        vm.prank(alice);
        vm.expectRevert(SuwappuVault.Unauthorized.selector);
        vault.sweepFees(address(0));
    }

    function test_feeBpsCannotExceedMax() public {
        vm.prank(admin);
        vm.expectRevert();
        vault.setFeeBps(101); // MAX is 100 bps (1%)
    }

    // -----------------------------------------------------------------------
    // Admin: two-step transfer
    // -----------------------------------------------------------------------

    function test_twoStep_adminTransfer() public {
        address newAdmin = makeAddr("newAdmin");

        vm.prank(admin);
        vault.transferAdmin(newAdmin);
        // Not yet transferred
        assertEq(vault.admin(), admin);

        vm.prank(newAdmin);
        vault.acceptAdmin();
        assertEq(vault.admin(), newAdmin);
        assertEq(vault.pendingAdmin(), address(0));
    }

    function test_acceptAdmin_reverts_ifNotPending() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuVault.Unauthorized.selector);
        vault.acceptAdmin();
    }

    // -----------------------------------------------------------------------
    // Invariant sanity: totalLocked never exceeds vault balance
    // -----------------------------------------------------------------------

    function test_invariant_lockedNeverExceedsBalance() public {
        vm.startPrank(alice);
        bytes32 c1 = vault.lockETH{value: 1 ether}(DEST_CHAIN, bob);
        bytes32 c2 = vault.lockETH{value: 2 ether}(DEST_CHAIN, bob);
        vm.stopPrank();

        // totalLocked ≤ vault ETH balance (difference is fees)
        assertLe(vault.totalLocked(address(0)), address(vault).balance);

        vm.prank(relayer);
        vault.unlock(c1, bob);

        assertLe(vault.totalLocked(address(0)), address(vault).balance);

        vm.warp(block.timestamp + vault.refundTimeout() + 1);
        vault.claimRefund(c2, _refundAtt(c2));

        assertLe(vault.totalLocked(address(0)), address(vault).balance);
        // Only fees remain
        assertEq(address(vault).balance, vault.pendingFees(address(0)));
    }
}
