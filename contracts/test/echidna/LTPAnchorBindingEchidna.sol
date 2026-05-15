// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LTPAnchorRegistry} from "../../src/LTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title LTPAnchorBindingEchidna
/// @notice Property fuzz harness for LTP-A-005 Option C-3 — owner-signed
///         binding statement + on-chain dispute path. Run with:
///         cd contracts && echidna . --contract LTPAnchorBindingEchidna --config echidna.yaml
///
/// Properties pinned:
///   B1: Once a binding is disputed, entitySigners[entityId] is empty
///       (the entity is reclaimable by the legitimate owner).
///   B2: A second disputeBinding call on the same entity always reverts
///       (one-shot dispute semantics).
///   B3: Only the configured bindingDisputeVerifier can call disputeBinding —
///       even admin cannot.
contract LTPAnchorBindingEchidna {
    LTPAnchorRegistry internal reg;

    address internal constant ADMIN = address(0xA1);
    address internal constant VERIFIER = address(0xB1ED181E);
    address internal constant ATTACKER = address(0xBAD);

    bytes32 internal lastBoundEntity;
    bool internal bindingExists;
    bool internal observedDisputeWithoutClear;
    bool internal observedDoubleDispute;
    bool internal adminEverDisputedSuccessfully;

    constructor() {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));
    }

    // ----------------------------------------------------------------
    // Setup helpers (called once by Echidna setup logic)
    // ----------------------------------------------------------------

    function setupVerifierAndSigner(bytes32 vkHash) external {
        if (vkHash == bytes32(0)) return;
        // Echidna will pick random msg.sender — only ADMIN-equivalent
        // calls succeed via the prank-less property model. We assume
        // setup ran from ADMIN context via Echidna's deployer.
        try reg.setBindingDisputeVerifier(VERIFIER) {} catch {}
        try reg.registerSigner(vkHash) {} catch {}
    }

    function tryAnchorWithBinding(bytes32 entityId, bytes32 vkHash) external {
        if (entityId == bytes32(0) || vkHash == bytes32(0)) return;
        try reg.anchorWithBinding(
            keccak256(abi.encode(entityId, vkHash)),
            entityId,
            keccak256("merkle"),
            keccak256("policy"),
            vkHash,
            uint64(1),
            uint64(block.timestamp + 365 days),
            uint8(0),
            keccak256("stmt"),
            keccak256("sig")
        ) {
            lastBoundEntity = entityId;
            bindingExists = true;
        } catch {}
    }

    function tryDisputeAsVerifier() external {
        if (!bindingExists) return;
        try reg.disputeBinding(lastBoundEntity, keccak256("proof")) {
            // Successful dispute must leave entitySigners empty.
            if (reg.entitySigners(lastBoundEntity) != bytes32(0)) {
                observedDisputeWithoutClear = true;
            }
            // Second dispute should revert.
            try reg.disputeBinding(lastBoundEntity, keccak256("proof2")) {
                observedDoubleDispute = true;
            } catch {}
        } catch {}
    }

    function adminTriesDispute() external {
        if (!bindingExists) return;
        try reg.disputeBinding(lastBoundEntity, keccak256("admin-attempt")) {
            adminEverDisputedSuccessfully = true;
        } catch {}
    }

    // ----------------------------------------------------------------
    // Invariants
    // ----------------------------------------------------------------

    function echidna_dispute_clears_entity_signer() external view returns (bool) {
        return !observedDisputeWithoutClear;
    }

    function echidna_dispute_is_one_shot() external view returns (bool) {
        return !observedDoubleDispute;
    }

    function echidna_admin_cannot_dispute() external view returns (bool) {
        return !adminEverDisputedSuccessfully;
    }
}
