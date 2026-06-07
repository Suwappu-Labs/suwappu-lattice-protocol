// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SuwappuMintAdapterTest is Test {
    SuwappuMintAdapter adapter;
    SuwappuWrappedToken wrappedToken;
    SuwappuEcdsaMintVerifier verifier;

    address admin   = makeAddr("admin");
    address relayer = makeAddr("relayer");
    address alice   = makeAddr("alice");
    address bob     = makeAddr("bob");

    uint256 constant OPERATOR_PK = 0xA110CE;
    address operator;

    uint256 constant SOURCE_CHAIN = 1;   // Ethereum mainnet
    uint256 constant DEST_CHAIN   = 8453; // Base
    bytes32 constant COMMIT_ID    = keccak256("test-commit-1");

    function setUp() public {
        wrappedToken = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether", "swETH", 18, SOURCE_CHAIN, address(0), admin, admin
        );
        adapter = new SuwappuMintAdapter(admin, address(wrappedToken));
        verifier = new SuwappuEcdsaMintVerifier(admin);
        operator = vm.addr(OPERATOR_PK);

        vm.startPrank(admin);
        wrappedToken.grantRole(wrappedToken.MINTER_ROLE(), address(adapter));
        wrappedToken.grantRole(wrappedToken.BURNER_ROLE(), address(adapter));
        adapter.addRelayer(relayer);
        adapter.setVerifier(address(verifier));
        verifier.setOperator(operator, true);
        vm.stopPrank();
    }

    /// Valid attestation by the authorized operator over the bound mint digest.
    function _att(bytes32 commitId, address recipient, uint256 amount, uint256 src)
        internal view returns (bytes memory)
    {
        bytes32 digest = adapter.mintDigest(commitId, recipient, amount, src);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPERATOR_PK, ethHash);
        return abi.encodePacked(r, s, v);
    }

    // ----- mint -----

    function test_mint_mintsWrappedTokens() public {
        bytes memory att = _att(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, att);
        assertEq(wrappedToken.balanceOf(alice), 1 ether);
    }

    function test_mint_recordsMintRecord() public {
        bytes memory att = _att(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, att);
        SuwappuMintAdapter.MintRecord memory r = adapter.getMintRecord(COMMIT_ID);
        assertEq(r.recipient, alice);
        assertEq(r.amount, 1 ether);
        assertEq(r.sourceChainId, SOURCE_CHAIN);
        assertTrue(r.mintedAt > 0);
    }

    function test_mint_reverts_doubleSpend() public {
        bytes memory att = _att(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.startPrank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, att);
        vm.expectRevert(abi.encodeWithSelector(SuwappuMintAdapter.AlreadyMinted.selector, COMMIT_ID));
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, att);
        vm.stopPrank();
    }

    function test_mint_reverts_notRelayer() public {
        bytes memory att = _att(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.Unauthorized.selector);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, att);
    }

    function test_mint_reverts_zeroRecipient() public {
        vm.prank(relayer);
        vm.expectRevert(SuwappuMintAdapter.ZeroAddress.selector);
        adapter.mint(COMMIT_ID, address(0), 1 ether, SOURCE_CHAIN, "");
    }

    function test_mint_reverts_zeroAmount() public {
        vm.prank(relayer);
        vm.expectRevert(SuwappuMintAdapter.ZeroAmount.selector);
        adapter.mint(COMMIT_ID, alice, 0, SOURCE_CHAIN, "");
    }

    // ----- attestation gate (C1 / P3-1) -----

    function test_mint_reverts_noAttestation() public {
        // relayer alone is NOT enough — a junk attestation is rejected (C1).
        vm.prank(relayer);
        vm.expectRevert(); // InvalidAttestation
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, hex"deadbeef");
    }

    function test_mint_reverts_unauthorizedOperator() public {
        // A valid signature by an UNAUTHORIZED key is rejected (P3-1).
        uint256 roguePk = 0xBADBAD;
        bytes32 digest = adapter.mintDigest(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(roguePk, ethHash);
        bytes memory rogueAtt = abi.encodePacked(r, s, v);
        vm.prank(relayer);
        vm.expectRevert();
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, rogueAtt);
    }

    function test_isMinted_returnsFalseBeforeMint() public view {
        assertFalse(adapter.isMinted(COMMIT_ID));
    }

    function test_isMinted_returnsTrueAfterMint() public {
        bytes memory att = _att(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, att);
        assertTrue(adapter.isMinted(COMMIT_ID));
    }

    function test_mint_differentCommitIdsSameParams() public {
        bytes32 id2 = keccak256("test-commit-2");
        bytes memory a1 = _att(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN);
        bytes memory a2 = _att(id2, alice, 1 ether, SOURCE_CHAIN);
        vm.startPrank(relayer);
        adapter.mint(COMMIT_ID, alice, 1 ether, SOURCE_CHAIN, a1);
        adapter.mint(id2, alice, 1 ether, SOURCE_CHAIN, a2);
        vm.stopPrank();
        assertEq(wrappedToken.balanceOf(alice), 2 ether);
    }

    // ----- burn -----

    function _mintTo(address to, uint256 amount) internal {
        bytes memory att = _att(COMMIT_ID, to, amount, SOURCE_CHAIN);
        vm.prank(relayer);
        adapter.mint(COMMIT_ID, to, amount, SOURCE_CHAIN, att);
    }

    function test_burn_destroysTokensAndEmitsBurnForRelease() public {
        _mintTo(alice, 1 ether);
        vm.prank(alice);
        bytes32 releaseId = adapter.burn(1 ether, SOURCE_CHAIN, bob);
        assertEq(wrappedToken.balanceOf(alice), 0);
        assertTrue(releaseId != bytes32(0));
    }

    function test_burn_reverts_zeroAmount() public {
        _mintTo(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.ZeroAmount.selector);
        adapter.burn(0, SOURCE_CHAIN, bob);
    }

    function test_burn_reverts_zeroDestRecipient() public {
        _mintTo(alice, 1 ether);
        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.ZeroAddress.selector);
        adapter.burn(1 ether, SOURCE_CHAIN, address(0));
    }

    function test_burn_uniqueReleaseIds() public {
        _mintTo(alice, 2 ether);
        vm.startPrank(alice);
        bytes32 r1 = adapter.burn(1 ether, SOURCE_CHAIN, bob);
        bytes32 r2 = adapter.burn(1 ether, SOURCE_CHAIN, bob);
        vm.stopPrank();
        assertTrue(r1 != r2, "releaseIds must be unique");
    }

    // ----- admin -----

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
        assertEq(adapter.admin(), admin);
        vm.prank(newAdmin);
        adapter.acceptAdmin();
        assertEq(adapter.admin(), newAdmin);
    }

    // ----- wrapped token roles -----

    function test_wrappedToken_minterRole_onAdapter() public view {
        assertTrue(wrappedToken.hasRole(wrappedToken.MINTER_ROLE(), address(adapter)));
    }

    function test_wrappedToken_burnerRole_onAdapter() public view {
        assertTrue(wrappedToken.hasRole(wrappedToken.BURNER_ROLE(), address(adapter)));
    }

    function test_wrappedToken_directMint_blockedForNonMinter() public {
        vm.prank(alice);
        vm.expectRevert();
        wrappedToken.mint(alice, 1 ether, bytes32(0));
    }
}
