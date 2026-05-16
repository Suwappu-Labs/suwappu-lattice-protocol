// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_003_Poly_KeeperEscalation.invariant
/// @notice Stateful invariant suite for SCN-003 (Poly Network-class
///         privilege-boundary pattern).
///
/// Properties pinned across any reachable handler call sequence:
///
///   K1 (admin-monopoly-on-signers):
///     `authorizedSigners[vk]` flips from false to true ONLY if a call
///     by the current admin to `registerSigner(vk)` or
///     `rotateSigner(_, vk)` succeeded. The handler asserts this
///     transitively by only registering via the admin path.
///
///   K2 (admin-never-rotated-by-attacker):
///     `reg.admin()` only changes when the prior admin successfully
///     called `transferAdmin`. The handler exposes a non-admin call
///     surface that should never alter admin.
contract SCN003_Invariant is Test {
    LTPAnchorRegistry internal reg;
    SCN003_Handler internal handler;

    address internal constant ADMIN = address(0xA11CE);

    function setUp() public {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        handler = new SCN003_Handler(reg, ADMIN);
        targetContract(address(handler));
    }

    /// K1: every signer the handler observed authorized has a matching
    ///     admin-path registration in the handler's mirror.
    function invariant_admin_monopoly_on_signers() public view {
        for (uint256 i = 0; i < handler.observedAuthorizedCount(); ++i) {
            bytes32 vk = handler.observedAuthorized(i);
            // If the contract says authorized, the handler must have
            // registered via the admin path.
            if (reg.authorizedSigners(vk)) {
                assertTrue(handler.registeredViaAdmin(vk),
                           "signer authorized without admin-path register");
            }
        }
    }

    /// K2: admin never changes through a non-admin call.
    function invariant_admin_never_silently_changes() public view {
        // The handler tracks the LAST observed admin after every call.
        // Across the campaign, if no admin-path transferAdmin happened,
        // the admin stays equal to ADMIN.
        if (!handler.adminEverTransferred()) {
            assertEq(reg.admin(), ADMIN);
        }
    }
}

contract SCN003_Handler is Test {
    LTPAnchorRegistry public reg;
    address public immutable adminAddr;

    bytes32[] public observedAuthorized;
    mapping(bytes32 => bool) public seenAuthorized;
    mapping(bytes32 => bool) public registeredViaAdmin;

    bool public adminEverTransferred;

    constructor(LTPAnchorRegistry _reg, address _admin) {
        reg = _reg;
        adminAddr = _admin;
    }

    function observedAuthorizedCount() external view returns (uint256) {
        return observedAuthorized.length;
    }

    // ----- Admin-path register (legitimate) -----
    function adminRegister(bytes32 vk) external {
        if (vk == bytes32(0)) return;
        vm.prank(adminAddr);
        try reg.registerSigner(vk) {
            if (!seenAuthorized[vk]) {
                seenAuthorized[vk] = true;
                observedAuthorized.push(vk);
            }
            registeredViaAdmin[vk] = true;
        } catch {}
    }

    // ----- Admin-path rotate -----
    function adminRotate(bytes32 oldVk, bytes32 newVk) external {
        if (newVk == bytes32(0) || oldVk == bytes32(0)) return;
        vm.prank(adminAddr);
        try reg.rotateSigner(oldVk, newVk) {
            if (!seenAuthorized[newVk]) {
                seenAuthorized[newVk] = true;
                observedAuthorized.push(newVk);
            }
            registeredViaAdmin[newVk] = true;
        } catch {}
    }

    // ----- Admin-path transferAdmin -----
    function adminTransfer(address newAdmin) external {
        if (newAdmin == address(0)) return;
        vm.prank(adminAddr);
        try reg.transferAdmin(newAdmin) {
            adminEverTransferred = true;
        } catch {}
    }

    // ----- Attacker attempts: must NEVER advance state -----
    function attackerTryRegister(address attacker, bytes32 vk) external {
        if (attacker == adminAddr || attacker == address(0)) return;
        vm.prank(attacker);
        try reg.registerSigner(vk) {
            // If this succeeds, the invariant K1 is violated.
            if (!seenAuthorized[vk]) {
                seenAuthorized[vk] = true;
                observedAuthorized.push(vk);
            }
            // NOTE: registeredViaAdmin[vk] is intentionally NOT set
            // here. The invariant checks reg.authorizedSigners(vk)
            // implies registeredViaAdmin[vk] — if this catch falls
            // through, K1 fails.
        } catch {}
    }

    function attackerTryTransferAdmin(address attacker, address newAdmin) external {
        if (attacker == adminAddr || attacker == address(0)) return;
        vm.prank(attacker);
        try reg.transferAdmin(newAdmin) {} catch {}
    }

    function attackerTryRotate(address attacker, bytes32 oldVk, bytes32 newVk) external {
        if (attacker == adminAddr || attacker == address(0)) return;
        vm.prank(attacker);
        try reg.rotateSigner(oldVk, newVk) {} catch {}
    }

    function attackerTryPause(address attacker) external {
        if (attacker == adminAddr) return;
        vm.prank(attacker);
        try reg.pause() {} catch {}
    }
}
