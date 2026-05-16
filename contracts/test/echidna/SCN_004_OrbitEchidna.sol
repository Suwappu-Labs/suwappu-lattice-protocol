// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LTPMultiSig} from "../../src/LTPMultiSig.sol";

/// @title SCN_004_OrbitEchidna
/// @notice Property harness for SCN-004 (Orbit Chain-class multisig
///         subversion pattern).
///
///   cd contracts && echidna . --contract SCN_004_OrbitEchidna --config echidna.yaml
///
/// Properties pinned:
///   S1: ms.threshold() never drifts from the constructor value.
///   S2: ms.isOwner(SEED_OWNER_*) stays true for the original three
///       owners.
///   S3: inline assertion at every successful `attackerExecute` —
///       any caller outside the original owner set must never
///       complete `executeTransaction`.
contract SCN_004_OrbitEchidna {
    LTPMultiSig internal ms;

    address internal constant SEED_OWNER_1 = address(0xA1);
    address internal constant SEED_OWNER_2 = address(0xB2);
    address internal constant SEED_OWNER_3 = address(0xC3);
    uint256 internal constant SEED_THRESHOLD = 2;

    constructor() {
        address[] memory owners = new address[](3);
        owners[0] = SEED_OWNER_1;
        owners[1] = SEED_OWNER_2;
        owners[2] = SEED_OWNER_3;
        ms = new LTPMultiSig(owners, SEED_THRESHOLD);
    }

    address internal constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    function vm_prank(address who) internal {
        (bool ok, ) = HEVM_ADDRESS.call(abi.encodeWithSignature("prank(address)", who));
        require(ok, "prank failed");
    }

    function attackerSubmit(address attacker, address target, bytes calldata data) external {
        if (attacker == SEED_OWNER_1 || attacker == SEED_OWNER_2 || attacker == SEED_OWNER_3) return;
        vm_prank(attacker);
        try ms.submitTransaction(target, 0, data) {
            assert(false); // non-owner submit must always revert
        } catch {}
    }

    function attackerConfirm(address attacker, uint256 txId) external {
        if (attacker == SEED_OWNER_1 || attacker == SEED_OWNER_2 || attacker == SEED_OWNER_3) return;
        vm_prank(attacker);
        try ms.confirmTransaction(txId) {
            assert(false);
        } catch {}
    }

    function attackerExecute(address attacker, uint256 txId) external {
        if (attacker == SEED_OWNER_1 || attacker == SEED_OWNER_2 || attacker == SEED_OWNER_3) return;
        vm_prank(attacker);
        try ms.executeTransaction(txId) {
            assert(false);
        } catch {}
    }

    /// S1: threshold never drifts.
    function echidna_threshold_never_drifts() external view returns (bool) {
        return ms.threshold() == SEED_THRESHOLD;
    }

    /// S2: owner set stays as constructor.
    function echidna_owner_set_stable() external view returns (bool) {
        return ms.isOwner(SEED_OWNER_1)
            && ms.isOwner(SEED_OWNER_2)
            && ms.isOwner(SEED_OWNER_3);
    }
}
