// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeploySuwappuMainnet} from "../../script/DeploySuwappuMainnet.s.sol";

/// @notice Verifies the production deploy wires custody safely (P9 blocker #1):
///         minterManager is the Timelock (not an EOA, not the Safe), the token
///         admin can never reach mint authority, and the P3-4 release cap ships
///         configured. These asserts are the regression guard against the
///         "single-key re-collapses P3-3" footgun.
///
/// @dev The test INHERITS the script so `_deploy` executes in this contract's
///      frame; the test contract is therefore the TEMP admin every config call is
///      authorized against (mirrors run(), where the deployer EOA plays that role
///      under broadcast).
contract DeploySuwappuMainnetTest is Test, DeploySuwappuMainnet {
    address tempAdmin; // = address(this), the temp admin during _deploy
    address safe = makeAddr("safe");
    address guardian = makeAddr("guardian");
    address operator = makeAddr("operator");
    address relayer = makeAddr("relayer");
    uint256 constant ETH_CAP = 100 ether;

    function setUp() public {
        tempAdmin = address(this);
    }

    // External self-call so reverts surface to vm.expectRevert; config calls
    // inside still come from this contract (== tempAdmin).
    function _run() internal returns (DeploySuwappuMainnet.Deployed memory d) {
        d = this._deploy(tempAdmin, safe, guardian, operator, relayer, ETH_CAP, 0);
    }

    function test_MinterManagerIsTimelock_NotEoaNotSafe() public {
        DeploySuwappuMainnet.Deployed memory d = _run();
        bytes32 minterAdmin = d.token.MINTER_ADMIN_ROLE();
        assertTrue(d.token.hasRole(minterAdmin, address(d.timelock)), "timelock holds MINTER_ADMIN");
        assertFalse(d.token.hasRole(minterAdmin, safe), "safe must NOT hold MINTER_ADMIN");
        assertFalse(d.token.hasRole(minterAdmin, tempAdmin), "deployer must NOT hold MINTER_ADMIN");
        assertEq(d.token.getRoleAdmin(d.token.MINTER_ROLE()), minterAdmin);
        assertEq(d.token.getRoleAdmin(d.token.BURNER_ROLE()), minterAdmin);
    }

    function test_TokenAdminHandedToSafe_DeployerRenounced() public {
        DeploySuwappuMainnet.Deployed memory d = _run();
        bytes32 defaultAdmin = d.token.DEFAULT_ADMIN_ROLE();
        assertTrue(d.token.hasRole(defaultAdmin, safe), "safe is token admin");
        assertFalse(d.token.hasRole(defaultAdmin, tempAdmin), "deployer renounced token admin");
        // Even as token admin, the Safe cannot grant itself mint authority.
        bytes32 minterRole = d.token.MINTER_ROLE();
        vm.prank(safe);
        vm.expectRevert(); // AccessControlUnauthorizedAccount(safe, MINTER_ADMIN_ROLE)
        d.token.grantRole(minterRole, safe);
    }

    function test_AdminHandoffIsPending_TwoStep() public {
        DeploySuwappuMainnet.Deployed memory d = _run();
        assertEq(d.vault.admin(), tempAdmin, "vault admin still temp until Safe accepts");
        assertEq(d.vault.pendingAdmin(), safe, "vault pendingAdmin = Safe");
        assertEq(d.adapter.pendingAdmin(), safe, "adapter pendingAdmin = Safe");
        assertEq(d.verifier.pendingAdmin(), safe, "verifier pendingAdmin = Safe");
    }

    function test_ReleaseCapAndRefundVerifierConfigured() public {
        DeploySuwappuMainnet.Deployed memory d = _run();
        assertEq(d.vault.dailyReleaseCap(address(0)), ETH_CAP, "ETH release cap set (P3-4)");
        assertTrue(address(d.vault.refundVerifier()) != address(0), "refund verifier wired (C2)");
        assertEq(d.vault.guardian(), guardian, "guardian set");
        assertTrue(d.vault.isUnlocker(relayer), "relayer is unlocker");
    }

    function test_Reverts_WhenSafeEqualsAdmin() public {
        vm.expectRevert(bytes("SAFE must be set and != deployer"));
        this._deploy(tempAdmin, tempAdmin, guardian, operator, relayer, ETH_CAP, 0);
    }

    function test_Reverts_WhenReleaseCapZero() public {
        vm.expectRevert(bytes("ETH release cap must be > 0 (P3-4)"));
        this._deploy(tempAdmin, safe, guardian, operator, relayer, 0, 0);
    }
}
