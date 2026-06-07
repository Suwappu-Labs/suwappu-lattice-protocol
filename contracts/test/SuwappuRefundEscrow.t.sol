// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuRefundEscrow} from "../src/SuwappuRefundEscrow.sol";

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount; return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount; balanceOf[to] += amount; return true;
    }
}

contract SuwappuRefundEscrowTest is Test {
    SuwappuRefundEscrow escrow;
    MockERC20 usdc;

    address admin    = makeAddr("admin");
    address treasury = makeAddr("treasury");
    address alice    = makeAddr("alice");
    address bob      = makeAddr("bob");
    address carol    = makeAddr("carol");

    // -----------------------------------------------------------------------
    // Helpers — build a 3-leaf merkle tree manually
    // -----------------------------------------------------------------------

    /// @dev Build a 3-leaf balanced tree and return root + proofs.
    ///      Leaves: (alice, ETH, 1 ether), (bob, ETH, 0.5 ether), (carol, usdc, 500e6)
    function _buildTree(uint256 roundId)
        internal
        view
        returns (
            bytes32 root,
            bytes32[] memory proofAlice,
            bytes32[] memory proofBob,
            bytes32[] memory proofCarol
        )
    {
        bytes32 leafAlice = keccak256(abi.encodePacked(alice, address(0),    uint256(1 ether),  roundId));
        bytes32 leafBob   = keccak256(abi.encodePacked(bob,   address(0),    uint256(0.5 ether),roundId));
        bytes32 leafCarol = keccak256(abi.encodePacked(carol, address(usdc), uint256(500e6),    roundId));

        // Sort pairs for OZ-compatible merkle tree (pairs are sorted before hashing)
        bytes32 node01 = _hashPair(leafAlice, leafBob);
        bytes32 node23 = _hashPair(leafCarol, leafCarol); // odd leaf duplicated

        root = _hashPair(node01, node23);

        // Proof for alice: [leafBob, node23]
        proofAlice = new bytes32[](2);
        proofAlice[0] = leafBob;
        proofAlice[1] = node23;

        // Proof for bob: [leafAlice, node23]
        proofBob = new bytes32[](2);
        proofBob[0] = leafAlice;
        proofBob[1] = node23;

        // Proof for carol: [leafCarol, node01]  (duplicate of self at same level)
        proofCarol = new bytes32[](2);
        proofCarol[0] = leafCarol;
        proofCarol[1] = node01;
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        // OZ MerkleProof sorts pairs before hashing
        return a < b
            ? keccak256(abi.encodePacked(a, b))
            : keccak256(abi.encodePacked(b, a));
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        escrow = new SuwappuRefundEscrow(admin, treasury);
        usdc   = new MockERC20();

        // Fund escrow reserve
        vm.deal(address(escrow), 10 ether);
        usdc.mint(address(escrow), 10_000e6);
    }

    // -----------------------------------------------------------------------
    // openRound
    // -----------------------------------------------------------------------

    function test_openRound_stores_metadata() public {
        (bytes32 root,,,) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "Test incident");

        assertEq(rid, 1);
        SuwappuRefundEscrow.Round memory r = escrow.getRound(rid);
        assertEq(r.root, root);
        assertTrue(r.exists);
        assertGt(r.closesAt, block.timestamp);
    }

    function test_openRound_reverts_emptyRoot() public {
        vm.prank(admin);
        vm.expectRevert("SuwappuRefundEscrow: empty root");
        escrow.openRound(bytes32(0), "empty");
    }

    function test_openRound_reverts_notAdmin() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuRefundEscrow.Unauthorized.selector);
        escrow.openRound(bytes32(uint256(1)), "unauth");
    }

    function test_roundCount_increments() public {
        (bytes32 root,,,) = _buildTree(1);
        vm.prank(admin);
        escrow.openRound(root, "round 1");

        (bytes32 root2,,,) = _buildTree(2);
        vm.prank(admin);
        escrow.openRound(root2, "round 2");

        assertEq(escrow.roundCount(), 2);
    }

    // -----------------------------------------------------------------------
    // claim — ETH
    // -----------------------------------------------------------------------

    function test_claim_eth_alice() public {
        (bytes32 root, bytes32[] memory proof,, ) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        escrow.claim(rid, address(0), 1 ether, proof);

        assertEq(alice.balance, aliceBefore + 1 ether);
        assertTrue(escrow.claimed(rid, alice));
    }

    function test_claim_eth_bob() public {
        (bytes32 root, , bytes32[] memory proof, ) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        escrow.claim(rid, address(0), 0.5 ether, proof);

        assertEq(bob.balance, bobBefore + 0.5 ether);
    }

    // -----------------------------------------------------------------------
    // claim — ERC-20
    // -----------------------------------------------------------------------

    function test_claim_erc20_carol() public {
        (bytes32 root, , , bytes32[] memory proof) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        vm.prank(carol);
        escrow.claim(rid, address(usdc), 500e6, proof);

        assertEq(usdc.balanceOf(carol), 500e6);
    }

    // -----------------------------------------------------------------------
    // Double-claim prevention
    // -----------------------------------------------------------------------

    function test_claim_reverts_doubleClaim() public {
        (bytes32 root, bytes32[] memory proof,, ) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        vm.prank(alice);
        escrow.claim(rid, address(0), 1 ether, proof);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuRefundEscrow.AlreadyClaimed.selector, rid, alice)
        );
        escrow.claim(rid, address(0), 1 ether, proof);
    }

    // -----------------------------------------------------------------------
    // Invalid proof
    // -----------------------------------------------------------------------

    function test_claim_reverts_invalidProof() public {
        (bytes32 root, bytes32[] memory proof,, ) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        // Bob tries to use alice's proof — different leaf, proof won't match
        vm.prank(bob);
        vm.expectRevert(SuwappuRefundEscrow.InvalidProof.selector);
        escrow.claim(rid, address(0), 1 ether, proof); // amount is alice's (1 ether), not bob's
    }

    // -----------------------------------------------------------------------
    // Claim after window closes
    // -----------------------------------------------------------------------

    function test_claim_reverts_afterWindow() public {
        (bytes32 root, bytes32[] memory proof,, ) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        vm.warp(block.timestamp + escrow.claimWindow() + 1);

        vm.prank(alice);
        vm.expectRevert();
        escrow.claim(rid, address(0), 1 ether, proof);
    }

    // -----------------------------------------------------------------------
    // sweepUnclaimed
    // -----------------------------------------------------------------------

    function test_sweepUnclaimed_afterWindow() public {
        (bytes32 root,,,) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        // Window closes
        vm.warp(block.timestamp + escrow.claimWindow() + 1);

        uint256 balance    = address(escrow).balance;
        uint256 treasBefore = treasury.balance;

        vm.prank(admin);
        escrow.sweepUnclaimed(rid, address(0));

        assertEq(treasury.balance, treasBefore + balance);
    }

    function test_sweepUnclaimed_reverts_windowStillOpen() public {
        (bytes32 root,,,) = _buildTree(1);

        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "incident 1");

        vm.prank(admin);
        vm.expectRevert();
        escrow.sweepUnclaimed(rid, address(0));
    }

    // -----------------------------------------------------------------------
    // leafHash helper
    // -----------------------------------------------------------------------

    function test_leafHash_matches_manual_computation() public view {
        bytes32 expected = keccak256(abi.encodePacked(alice, address(0), uint256(1 ether), uint256(1)));
        assertEq(escrow.leafHash(alice, address(0), 1 ether, 1), expected);
    }

    // -----------------------------------------------------------------------
    // Two-step admin transfer
    // -----------------------------------------------------------------------

    function test_twoStep_adminTransfer() public {
        address newAdmin = makeAddr("newAdmin");

        vm.prank(admin);
        escrow.transferAdmin(newAdmin);
        assertEq(escrow.admin(), admin); // not yet

        vm.prank(newAdmin);
        escrow.acceptAdmin();
        assertEq(escrow.admin(), newAdmin);
    }

    // -----------------------------------------------------------------------
    // Deposit
    // -----------------------------------------------------------------------

    function test_depositETH() public {
        uint256 before = address(escrow).balance;
        escrow.depositETH{value: 1 ether}();
        assertEq(address(escrow).balance, before + 1 ether);
    }

    function test_depositERC20() public {
        usdc.mint(alice, 1_000e6);
        vm.prank(alice);
        usdc.approve(address(escrow), 1_000e6);

        uint256 before = usdc.balanceOf(address(escrow));
        vm.prank(alice);
        escrow.depositERC20(address(usdc), 1_000e6);
        assertEq(usdc.balanceOf(address(escrow)), before + 1_000e6);
    }

    // -----------------------------------------------------------------------
    // isRoundOpen
    // -----------------------------------------------------------------------

    function test_isRoundOpen_true_within_window() public {
        (bytes32 root,,,) = _buildTree(1);
        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "test");
        assertTrue(escrow.isRoundOpen(rid));
    }

    function test_isRoundOpen_false_after_window() public {
        (bytes32 root,,,) = _buildTree(1);
        vm.prank(admin);
        uint256 rid = escrow.openRound(root, "test");
        vm.warp(block.timestamp + escrow.claimWindow() + 1);
        assertFalse(escrow.isRoundOpen(rid));
    }

    function test_isRoundOpen_false_unknown_round() public view {
        assertFalse(escrow.isRoundOpen(999));
    }
}
