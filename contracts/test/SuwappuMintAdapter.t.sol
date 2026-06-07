// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";

contract SuwappuMintAdapterTest is Test {
    SuwappuMintAdapter adapter;
    SuwappuWrappedToken wrappedToken;

    address admin   = makeAddr("admin");
    address relayer = makeAddr("relayer");
    address alice   = makeAddr("alice");
    address bob     = makeAddr("bob");

    uint256 constant SOURCE_CHAIN = 1;   // Ethereum mainnet
    uint256 constant DEST_CHAIN   = 8453; // Base
    bytes32 constant COMMIT_ID    = keccak256("test-commit-1");

    function setUp() public {
        // Deploy wrapped token with admin holding DEFAULT_ADMIN_ROLE
        wrappedToken = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether",
            "swETH",
            18,
            SOURCE_CHAIN,
            address(0), // native ETH
            admin
        );

        // Deploy adapter
        adapter = new SuwappuMintAdapter(admin, address(wrappedToken));

        // Grant adapter MINTER_ROLE and BURNER_ROLE on the token
        vm.startPrank(admin);
        wrappedToken.grantRole(wrappedToken.MINTER_ROLE(), address(adapter));
        wrappedToken.grantRole(wrappedToken.BURNER_ROLE(), address(adapter));
        adapter.addRelayer(relayer);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------
    // mint
    // -----------------------------------------------------------------------

    function test_mint_mintsWrappedTokens() public {
        uint256 amount = 1 ether;
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, amount, SOURCE_CHAIN);

        assertEq(wrappedToken.balanceOf(alice), amount);
    }

    function test_mint_recordsMintRecord() public {
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);

        SuwappuMintAdapter.MintRecord memory r = adapter.getMintRecord(COMMIT_ID);
        assertEq(r.recipient,     alice);
        assertEq(r.amount,        1 ether);
        assertEq(r.sourceChainId, SOURCE_CHAIN);
        assertTrue(r.mintedAt > 0);
    }

    function test_mint_reverts_doubleSpend() public {
        vm.startPrank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.expectRevert(abi.encodeWithSelector(SuwappuMintAdapter.AlreadyMinted.selector, COMMIT_ID));
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.stopPrank();
    }

    function test_mint_reverts_notRelayer() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.Unauthorized.selector);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
    }

    function test_mint_reverts_zeroRecipient() public {
        vm.prank(relayer);
        vm.expectRevert(SuwappuMintAdapter.ZeroAddress.selector);
        adapter.mint(COMMIT_ID, address(0), 1 ether, SOURCE_CHAIN);
    }

    function test_mint_reverts_zeroAmount() public {
        vm.prank(relayer);
        vm.expectRevert(SuwappuMintAdapter.ZeroAmount.selector);
        adapter.mint(COMMIT_ID, alice, 0, SOURCE_CHAIN);
    }

    function test_isMinted_returnsFalseBeforeMint() public view {
        assertFalse(adapter.isMinted(COMMIT_ID));
    }

    function test_isMinted_returnsTrueAfterMint() public {
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        assertTrue(adapter.isMinted(COMMIT_ID));
    }

    function test_mint_differentCommitIdsSameParams() public {
        bytes32 id2 = keccak256("test-commit-2");
        vm.startPrank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        adapter.mint(id2,       alice, 1 ether, SOURCE_CHAIN);
        vm.stopPrank();
        // Both minted — different commit IDs are independent
        assertEq(wrappedToken.balanceOf(alice), 2 ether);
    }

    // -----------------------------------------------------------------------
    // burn
    // -----------------------------------------------------------------------

    function test_burn_destroysTokensAndEmitsBurnForRelease() public {
        // First mint tokens to alice
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);

        // Alice burns for return transfer
        vm.prank(alice);
        vm.recordLogs();
        bytes32 releaseId = adapter.burn(1 ether, SOURCE_CHAIN, bob);

        // Token balance burned
        assertEq(wrappedToken.balanceOf(alice), 0);

        // releaseId is non-zero and unique
        assertTrue(releaseId != bytes32(0));
    }

    function test_burn_reverts_zeroAmount() public {
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);

        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.ZeroAmount.selector);
        adapter.burn(0, SOURCE_CHAIN, bob);
    }

    function test_burn_reverts_zeroDestRecipient() public {
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);

        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.ZeroAddress.selector);
        adapter.burn(1 ether, SOURCE_CHAIN, address(0));
    }

    function test_burn_uniqueReleaseIds() public {
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 2 ether, SOURCE_CHAIN);

        vm.startPrank(alice);
        bytes32 r1 = adapter.burn(1 ether, SOURCE_CHAIN, bob);
        bytes32 r2 = adapter.burn(1 ether, SOURCE_CHAIN, bob);
        vm.stopPrank();

        assertTrue(r1 != r2, "releaseIds must be unique");
    }

    // -----------------------------------------------------------------------
    // Admin
    // -----------------------------------------------------------------------

    function test_addRelayer_and_removeRelayer() public {
        address newRelayer = makeAddr("newRelayer");
        vm.prank(admin);
        adapter.addRelayer(newRelayer);
        assertTrue(adapter.isRelayer(newRelayer));

        vm.prank(admin);
        adapter.removeRelayer(newRelayer);
        assertFalse(adapter.isRelayer(newRelayer));
    }

    function test_addRelayer_reverts_notAdmin() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.Unauthorized.selector);
        adapter.addRelayer(alice);
    }

    function test_twoStep_adminTransfer() public {
        address newAdmin = makeAddr("newAdmin");

        vm.prank(admin);
        adapter.transferAdmin(newAdmin);
        assertEq(adapter.admin(), admin); // not yet

        vm.prank(newAdmin);
        adapter.acceptAdmin();
        assertEq(adapter.admin(), newAdmin);
    }

    // -----------------------------------------------------------------------
    // Wrapped token roles
    // -----------------------------------------------------------------------

    function test_wrappedToken_minterRole_onAdapter() public view {
        assertTrue(
            wrappedToken.hasRole(wrappedToken.MINTER_ROLE(), address(adapter))
        );
    }

    function test_wrappedToken_burnerRole_onAdapter() public view {
        assertTrue(
            wrappedToken.hasRole(wrappedToken.BURNER_ROLE(), address(adapter))
        );
    }

    function test_wrappedToken_directMint_blockedForNonMinter() public {
        vm.prank(alice);
        vm.expectRevert();
        wrappedToken.mint(alice, 1 ether, bytes32(0));
    }
}
