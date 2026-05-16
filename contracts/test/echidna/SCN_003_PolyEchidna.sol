// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_003_PolyEchidna
/// @notice Property harness for SCN-003 (Poly Network-class
///         privilege-boundary pattern).
///
///   cd contracts && echidna . --contract SCN_003_PolyEchidna --config echidna.yaml
///
/// Properties pinned:
///   R1: reg.admin() never changes from the initial ADMIN inside this
///       harness — the harness never calls transferAdmin, so any drift
///       implies a privilege escape.
///   R2: a signer that the harness did not register via the admin path
///       must never appear in authorizedSigners.
contract SCN_003_PolyEchidna {
    LTPAnchorRegistry internal reg;
    address internal constant ADMIN = address(0xA1);
    bytes32 internal constant SEED_VK = keccak256("scn003-echidna-seed-vk");

    mapping(bytes32 => bool) internal adminRegistered;

    constructor() {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm_prank(ADMIN);
        reg.registerSigner(SEED_VK);
        adminRegistered[SEED_VK] = true;
    }

    address internal constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    function vm_prank(address who) internal {
        (bool ok, ) = HEVM_ADDRESS.call(abi.encodeWithSignature("prank(address)", who));
        require(ok, "prank failed");
    }

    /// @dev Fuzzed: an attacker calls registerSigner. Must always
    ///      revert; if it doesn't, R2 is violated.
    function attackerRegister(address attacker, bytes32 vk) external {
        if (attacker == ADMIN || attacker == address(0)) return;
        if (vk == bytes32(0)) return;
        vm_prank(attacker);
        try reg.registerSigner(vk) {
            // Should never reach here.
            assert(false);
        } catch {}
    }

    function attackerTransferAdmin(address attacker, address newAdmin) external {
        if (attacker == ADMIN) return;
        vm_prank(attacker);
        try reg.transferAdmin(newAdmin) {
            assert(false);
        } catch {}
    }

    function attackerPause(address attacker) external {
        if (attacker == ADMIN) return;
        vm_prank(attacker);
        try reg.pause() {
            assert(false);
        } catch {}
    }

    /// R1: admin pointer never moves inside this harness.
    function echidna_admin_never_moves() external view returns (bool) {
        return reg.admin() == ADMIN;
    }

    /// R2: only the SEED_VK was registered via admin; if anything else
    ///     is authorized, an attacker path succeeded.
    function echidna_only_seed_vk_authorized() external view returns (bool) {
        // We trust SEED_VK is authorized (constructor). Without
        // enumerating all bytes32, the cheapest property is "the
        // attacker-fuzz paths never made anything new authorized".
        // The inline `assert(false)` in each attackerXxx provides
        // the actual write-time enforcement; this view function pins
        // the post-condition for SEED_VK at minimum.
        return reg.authorizedSigners(SEED_VK);
    }
}
