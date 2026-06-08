// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title SuwappuWrappedToken unit tests
/// @notice Closes Suwappu gate criterion #5 (dedicated WrappedToken test file).
///         Headline coverage is the P3-3 privilege-separation property: the
///         DEFAULT_ADMIN_ROLE holder must NOT be able to escalate to mint
///         authority — only the separate MINTER_ADMIN_ROLE (the Timelock in
///         production) can grant MINTER_ROLE / BURNER_ROLE.
contract SuwappuWrappedTokenTest is Test {
    SuwappuWrappedToken token;

    address admin = makeAddr("admin"); // DEFAULT_ADMIN_ROLE (Gnosis Safe)
    address minterManager = makeAddr("minterManager"); // MINTER_ADMIN_ROLE (Timelock)
    address minter = makeAddr("minter"); // gets MINTER_ROLE (the adapter)
    address burner = makeAddr("burner"); // gets BURNER_ROLE (the adapter)
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    uint256 constant SOURCE_CHAIN = 1; // Ethereum mainnet
    address constant SOURCE_TOKEN = address(0); // native ETH
    bytes32 constant COMMIT_ID = keccak256("commit-1");
    bytes32 constant RELEASE_ID = keccak256("release-1");

    // Role IDs cached so we never make a staticcall to `token` while a prank or
    // expectRevert is armed (an inline `MINTER_ROLE` would consume the
    // prank / be mistaken for "the next call").
    bytes32 DEFAULT_ADMIN_ROLE;
    bytes32 MINTER_ROLE;
    bytes32 BURNER_ROLE;
    bytes32 MINTER_ADMIN_ROLE;

    event Minted(address indexed to, uint256 amount, bytes32 indexed commitId);
    event Burned(address indexed from, uint256 amount, bytes32 indexed releaseId);

    function setUp() public {
        token = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether", "swETH", 18, SOURCE_CHAIN, SOURCE_TOKEN, admin, minterManager
        );
        DEFAULT_ADMIN_ROLE = token.DEFAULT_ADMIN_ROLE();
        MINTER_ROLE = token.MINTER_ROLE();
        BURNER_ROLE = token.BURNER_ROLE();
        MINTER_ADMIN_ROLE = token.MINTER_ADMIN_ROLE();

        // The minter-manager (Timelock) is the only principal that can hand out
        // mint/burn authority. Mirror the production grant to the adapter.
        vm.startPrank(minterManager);
        token.grantRole(MINTER_ROLE, minter);
        token.grantRole(BURNER_ROLE, burner);
        vm.stopPrank();
    }

    function _unauthorized(address account, bytes32 role) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            IAccessControl.AccessControlUnauthorizedAccount.selector, account, role
        );
    }

    // -----------------------------------------------------------------------
    // Constructor / metadata
    // -----------------------------------------------------------------------

    function test_Constructor_SetsMetadata() public view {
        assertEq(token.name(), "Suwappu Wrapped Ether");
        assertEq(token.symbol(), "swETH");
        assertEq(token.decimals(), 18);
        assertEq(token.sourceChainId(), SOURCE_CHAIN);
        assertEq(token.sourceToken(), SOURCE_TOKEN);
        assertEq(token.totalSupply(), 0);
    }

    function test_Constructor_HonorsNonDefaultDecimals() public {
        SuwappuWrappedToken usdc = new SuwappuWrappedToken(
            "Suwappu Wrapped USDC",
            "swUSDC",
            6,
            SOURCE_CHAIN,
            makeAddr("usdc"),
            admin,
            minterManager
        );
        assertEq(usdc.decimals(), 6);
    }

    function test_Constructor_RevertsOnZeroAdmin() public {
        vm.expectRevert(bytes("SuwappuWrappedToken: zero admin"));
        new SuwappuWrappedToken("n", "s", 18, SOURCE_CHAIN, SOURCE_TOKEN, address(0), minterManager);
    }

    function test_Constructor_RevertsOnZeroMinterManager() public {
        vm.expectRevert(bytes("SuwappuWrappedToken: zero minter manager"));
        new SuwappuWrappedToken("n", "s", 18, SOURCE_CHAIN, SOURCE_TOKEN, admin, address(0));
    }

    // -----------------------------------------------------------------------
    // Role wiring (P3-3 privilege separation)
    // -----------------------------------------------------------------------

    function test_Roles_InitialGrants() public view {
        assertTrue(token.hasRole(DEFAULT_ADMIN_ROLE, admin));
        assertTrue(token.hasRole(MINTER_ADMIN_ROLE, minterManager));
        assertFalse(token.hasRole(MINTER_ADMIN_ROLE, admin));
        assertFalse(token.hasRole(DEFAULT_ADMIN_ROLE, minterManager));
    }

    function test_Roles_MinterAdminIsAdminOfMintBurn() public view {
        assertEq(token.getRoleAdmin(MINTER_ROLE), MINTER_ADMIN_ROLE);
        assertEq(token.getRoleAdmin(BURNER_ROLE), MINTER_ADMIN_ROLE);
        // self-administered so DEFAULT_ADMIN can never become the minter-admin
        assertEq(token.getRoleAdmin(MINTER_ADMIN_ROLE), MINTER_ADMIN_ROLE);
    }

    /// HEADLINE: the DEFAULT_ADMIN holder cannot grant itself (or anyone) mint
    /// authority. This is the whole point of the P3-3 fix.
    function test_P3_3_DefaultAdminCannotGrantMinter() public {
        vm.prank(admin);
        vm.expectRevert(_unauthorized(admin, MINTER_ADMIN_ROLE));
        token.grantRole(MINTER_ROLE, admin);
    }

    function test_P3_3_DefaultAdminCannotGrantBurner() public {
        vm.prank(admin);
        vm.expectRevert(_unauthorized(admin, MINTER_ADMIN_ROLE));
        token.grantRole(BURNER_ROLE, admin);
    }

    function test_P3_3_DefaultAdminCannotSeizeMinterAdmin() public {
        vm.prank(admin);
        vm.expectRevert(_unauthorized(admin, MINTER_ADMIN_ROLE));
        token.grantRole(MINTER_ADMIN_ROLE, admin);
    }

    function test_MinterManager_CanRotateMinter() public {
        address newMinter = makeAddr("newMinter");
        vm.startPrank(minterManager);
        token.revokeRole(MINTER_ROLE, minter);
        token.grantRole(MINTER_ROLE, newMinter);
        vm.stopPrank();

        assertFalse(token.hasRole(MINTER_ROLE, minter));
        assertTrue(token.hasRole(MINTER_ROLE, newMinter));

        // old minter can no longer mint; new one can
        vm.prank(minter);
        vm.expectRevert(_unauthorized(minter, MINTER_ROLE));
        token.mint(alice, 1 ether, COMMIT_ID);

        vm.prank(newMinter);
        token.mint(alice, 1 ether, COMMIT_ID);
        assertEq(token.balanceOf(alice), 1 ether);
    }

    // -----------------------------------------------------------------------
    // mint()
    // -----------------------------------------------------------------------

    function test_Mint_HappyPath() public {
        vm.expectEmit(true, true, true, true, address(token));
        emit Minted(alice, 5 ether, COMMIT_ID);
        vm.prank(minter);
        token.mint(alice, 5 ether, COMMIT_ID);

        assertEq(token.balanceOf(alice), 5 ether);
        assertEq(token.totalSupply(), 5 ether);
    }

    function test_Mint_OnlyMinterRole() public {
        vm.prank(alice);
        vm.expectRevert(_unauthorized(alice, MINTER_ROLE));
        token.mint(alice, 1 ether, COMMIT_ID);
    }

    function test_Mint_RevertsOnZeroRecipient() public {
        vm.prank(minter);
        vm.expectRevert(bytes("SuwappuWrappedToken: zero recipient"));
        token.mint(address(0), 1 ether, COMMIT_ID);
    }

    function test_Mint_RevertsOnZeroAmount() public {
        vm.prank(minter);
        vm.expectRevert(bytes("SuwappuWrappedToken: zero amount"));
        token.mint(alice, 0, COMMIT_ID);
    }

    // -----------------------------------------------------------------------
    // burn()
    // -----------------------------------------------------------------------

    function test_Burn_HappyPath() public {
        vm.prank(minter);
        token.mint(alice, 5 ether, COMMIT_ID);

        vm.expectEmit(true, true, true, true, address(token));
        emit Burned(alice, 2 ether, RELEASE_ID);
        vm.prank(burner);
        token.burn(alice, 2 ether, RELEASE_ID);

        assertEq(token.balanceOf(alice), 3 ether);
        assertEq(token.totalSupply(), 3 ether);
    }

    function test_Burn_OnlyBurnerRole() public {
        vm.prank(minter);
        token.mint(alice, 5 ether, COMMIT_ID);

        // even the MINTER_ROLE holder cannot burn
        vm.prank(minter);
        vm.expectRevert(_unauthorized(minter, BURNER_ROLE));
        token.burn(alice, 1 ether, RELEASE_ID);
    }

    function test_Burn_RevertsOnZeroAmount() public {
        vm.prank(burner);
        vm.expectRevert(bytes("SuwappuWrappedToken: zero amount"));
        token.burn(alice, 0, RELEASE_ID);
    }

    function test_Burn_RevertsWhenExceedingBalance() public {
        vm.prank(minter);
        token.mint(alice, 1 ether, COMMIT_ID);

        vm.prank(burner);
        vm.expectRevert(); // ERC20InsufficientBalance
        token.burn(alice, 2 ether, RELEASE_ID);
    }

    // -----------------------------------------------------------------------
    // Mint/burn supply conservation (fuzz)
    // -----------------------------------------------------------------------

    function testFuzz_MintBurn_ConservesSupply(uint128 mintAmt, uint128 burnAmt) public {
        mintAmt = uint128(bound(mintAmt, 1, type(uint128).max));
        burnAmt = uint128(bound(burnAmt, 0, mintAmt));

        vm.prank(minter);
        token.mint(alice, mintAmt, COMMIT_ID);
        assertEq(token.totalSupply(), mintAmt);

        if (burnAmt > 0) {
            vm.prank(burner);
            token.burn(alice, burnAmt, RELEASE_ID);
        }
        assertEq(token.balanceOf(alice), uint256(mintAmt) - burnAmt);
        assertEq(token.totalSupply(), uint256(mintAmt) - burnAmt);
    }

    // -----------------------------------------------------------------------
    // Standard ERC-20 behavior still works
    // -----------------------------------------------------------------------

    function test_ERC20_Transfer() public {
        vm.prank(minter);
        token.mint(alice, 10 ether, COMMIT_ID);

        vm.prank(alice);
        token.transfer(bob, 4 ether);

        assertEq(token.balanceOf(alice), 6 ether);
        assertEq(token.balanceOf(bob), 4 ether);
    }

    function test_ERC20_ApproveTransferFrom() public {
        vm.prank(minter);
        token.mint(alice, 10 ether, COMMIT_ID);

        vm.prank(alice);
        token.approve(bob, 3 ether);

        vm.prank(bob);
        token.transferFrom(alice, bob, 3 ether);

        assertEq(token.balanceOf(bob), 3 ether);
        assertEq(token.allowance(alice, bob), 0);
    }
}
