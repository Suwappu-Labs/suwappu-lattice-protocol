// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SuwappuVault} from "../../src/SuwappuVault.sol";
import {SuwappuMintAdapter} from "../../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../../src/SuwappuWrappedToken.sol";
import {SuwappuEcdsaMintVerifier} from "../../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SuwappuP3Findings.security.t.sol
/// @notice Empirical confirmation of the NEW P3 (attack-class review) findings.
///         These tests demonstrate the vulnerability EXISTS on current code
///         (they pass by reaching the unsafe state), per the audit plan's
///         "reproduce >=High findings before treating as confirmed".

contract SuwappuP3FindingsTest is Test {
    address internal constant ADMIN = address(0xA1);
    address internal attacker = makeAddr("attacker");
    address internal relayer  = makeAddr("relayer");
    address internal alice    = makeAddr("alice");

    // ---- P3-3 [CRITICAL] — FIXED: the token DEFAULT_ADMIN can no longer grant
    //      mint authority; only the separate minter-manager (Timelock) can. ----
    function test_P3_3_admin_cannot_grant_mint() public {
        address manager = makeAddr("timelockManager"); // MINTER_ADMIN_ROLE holder
        SuwappuWrappedToken wt = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether", "swETH", 18, 1, address(0), ADMIN, manager
        );
        bytes32 minterRole = wt.MINTER_ROLE();
        bytes32 minterAdminRole = wt.MINTER_ADMIN_ROLE();

        // SECURE PROPERTY: the token admin (DEFAULT_ADMIN_ROLE) is NOT the admin
        // of MINTER_ROLE, so it cannot grant mint authority to itself or anyone.
        vm.prank(ADMIN);
        vm.expectRevert(); // AccessControlUnauthorizedAccount(ADMIN, MINTER_ADMIN_ROLE)
        wt.grantRole(minterRole, attacker);

        // And it cannot escalate by granting itself the manager role either.
        vm.prank(ADMIN);
        vm.expectRevert();
        wt.grantRole(minterAdminRole, ADMIN);

        // Only the manager can set the minter set (governed, timelocked in prod).
        vm.prank(manager);
        wt.grantRole(minterRole, address(0xADA));
        assertTrue(wt.hasRole(minterRole, address(0xADA)));
        assertFalse(wt.hasRole(minterRole, attacker), "P3-3 fixed: admin minted nothing");
    }

    // ---- P3-5 [HIGH] — FIXED: an attestation is bound to one adapter instance;
    //      it cannot be replayed onto another instance (address(this) in digest). ----
    uint256 constant OPERATOR_PK = 0xA110CE;

    function test_P3_5_cross_instance_replay_blocked() public {
        SuwappuVault vault = new SuwappuVault(ADMIN, ADMIN, 0);
        SuwappuWrappedToken wt1 = new SuwappuWrappedToken("swETH-1","swETH1",18,1,address(0),ADMIN,ADMIN);
        SuwappuWrappedToken wt2 = new SuwappuWrappedToken("swETH-2","swETH2",18,1,address(0),ADMIN,ADMIN);
        SuwappuMintAdapter a1 = new SuwappuMintAdapter(ADMIN, address(wt1));
        SuwappuMintAdapter a2 = new SuwappuMintAdapter(ADMIN, address(wt2));
        SuwappuEcdsaMintVerifier verifier = new SuwappuEcdsaMintVerifier(ADMIN);
        address operator = vm.addr(OPERATOR_PK);

        vm.startPrank(ADMIN);
        wt1.grantRole(wt1.MINTER_ROLE(), address(a1));
        wt2.grantRole(wt2.MINTER_ROLE(), address(a2));
        a1.addRelayer(relayer); a2.addRelayer(relayer);
        a1.setVerifier(address(verifier)); a2.setVerifier(address(verifier));
        verifier.setOperator(operator, true);
        vm.stopPrank();

        vm.deal(alice, 10 ether);
        vm.prank(alice);
        bytes32 commitId = vault.lockETH{value: 10 ether}(8453, alice);

        // Operator attests the mint FOR a1 (digest binds a1's address).
        bytes32 d1 = a1.mintDigest(commitId, alice, 10 ether, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OPERATOR_PK, MessageHashUtils.toEthSignedMessageHash(d1));
        bytes memory att1 = abi.encodePacked(r, s, v);

        vm.startPrank(relayer);
        a1.mint(commitId, alice, 10 ether, 1, att1); // succeeds on a1

        // SECURE PROPERTY: replaying a1's attestation on a2 must REVERT (digest binds a2's address now).
        vm.expectRevert(); // InvalidAttestation
        a2.mint(commitId, alice, 10 ether, 1, att1);
        vm.stopPrank();

        assertEq(wt1.totalSupply(), 10 ether);
        assertEq(wt2.totalSupply(), 0, "P3-5 fixed: cross-instance attestation replay blocked");
    }
}
