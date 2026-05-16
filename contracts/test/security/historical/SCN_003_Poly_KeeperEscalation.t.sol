// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_003_Poly_KeeperEscalation
/// @notice Red-team scenario SCN-003 — Poly Network-class "cross-chain
///         message handler executes a privileged function on caller's
///         behalf" pattern. See
///         docs/security/campaigns/SCN-003-poly-keeper-escalation/.
///
/// Historical incident: Poly Network bridge, Aug 2021, $611M. The
/// `EthCrossChainManager.verifyHeaderAndExecuteTx` forwarded a call
/// to a caller-supplied `(toContract, methodSig, args)` triple. The
/// attacker crafted a cross-chain message that targeted
/// `EthCrossChainManager` itself, calling
/// `putCurEpochConPubKeyBytes()` — a function that rotated the keeper
/// set. The keeper set is the trusted-signer registry; replacing it
/// with attacker-controlled keys gave the attacker full bridge
/// authority. Fix: privilege boundary moves into the manager
/// contract; cross-chain handlers cannot target privileged functions.
///
/// LTP analogue: unlike Poly Network, LTP has NO generic
/// `verifyHeaderAndExecuteTx`-style forwarder. Every privileged
/// function in `LTPAnchorRegistry` is gated by `msg.sender` against a
/// concrete role (`onlyAdmin` or `bindingDisputeVerifier`). The
/// equivalent attacks therefore reduce to "can an unprivileged caller
/// invoke a privileged function?" — and every defense must reject.
///
///   (P1)  registerSigner: onlyAdmin → revert NotAdmin
///   (P2)  revokeSigner:   onlyAdmin → revert NotAdmin
///   (P3)  rotateSigner:   onlyAdmin → revert NotAdmin
///   (P4)  rotateSignerWithGrace: onlyAdmin → revert NotAdmin
///   (P5)  reassignEntitySigner:  onlyAdmin → revert NotAdmin
///   (P6)  setBindingDisputeVerifier: onlyAdmin → revert NotAdmin
///   (P7)  disputeBinding: bindingDisputeVerifier-only
///                         → revert NotBindingDisputeVerifier
///   (P8)  transferAdmin:  onlyAdmin → revert NotAdmin
///   (P9)  pause / unpause: onlyAdmin → revert NotAdmin
///   (P10) anchor() does NOT register a new signer as a side effect
///         — only succeeds for signers already in authorizedSigners.
contract SCN003_Poly_KeeperEscalation is Test {
    LTPAnchorRegistry internal reg;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant ATTACKER = address(0xBADC0DE);
    address internal constant DISPUTE_VERIFIER = address(0xD15997E);

    bytes32 internal constant LEGIT_VK = keccak256("scn003-legit-vk");
    bytes32 internal constant ATTACKER_VK = keccak256("scn003-attacker-vk");

    function setUp() public {
        LTPAnchorRegistry impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm.prank(ADMIN);
        reg.registerSigner(LEGIT_VK);

        vm.prank(ADMIN);
        reg.setBindingDisputeVerifier(DISPUTE_VERIFIER);
    }

    // -----------------------------------------------------------------------
    // P1-P9 — privileged functions reject the attacker
    // -----------------------------------------------------------------------

    function test_P1_registerSigner_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.registerSigner(ATTACKER_VK);
    }

    function test_P2_revokeSigner_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.revokeSigner(LEGIT_VK);
    }

    function test_P3_rotateSigner_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.rotateSigner(LEGIT_VK, ATTACKER_VK);
    }

    function test_P4_rotateSignerWithGrace_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.rotateSignerWithGrace(LEGIT_VK, ATTACKER_VK, uint64(1 days));
    }

    function test_P5_reassignEntitySigner_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.reassignEntitySigner(keccak256("victim-entity"), ATTACKER_VK);
    }

    function test_P6_setBindingDisputeVerifier_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.setBindingDisputeVerifier(ATTACKER);
    }

    function test_P7_disputeBinding_rejects_non_verifier() public {
        // Even ADMIN cannot call disputeBinding — that path is
        // reserved for the configured verifier.
        vm.prank(ADMIN);
        vm.expectRevert(); // NotBindingDisputeVerifier
        reg.disputeBinding(keccak256("any-entity"), keccak256("fp"));

        // Attacker also cannot.
        vm.prank(ATTACKER);
        vm.expectRevert();
        reg.disputeBinding(keccak256("any-entity"), keccak256("fp"));
    }

    function test_P8_transferAdmin_rejects_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.transferAdmin(ATTACKER);
    }

    function test_P9_pause_unpause_reject_attacker() public {
        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.pause();

        vm.prank(ATTACKER);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, ATTACKER));
        reg.unpause();
    }

    // -----------------------------------------------------------------------
    // P10 — anchor() does not register a signer as a side effect
    // -----------------------------------------------------------------------

    /// @dev Poly Network's mistake was that a "normal" cross-chain
    ///      data path indirectly triggered keeper rotation. The LTP
    ///      analogue: confirm calling anchor() with an unregistered
    ///      signer does NOT add the signer to authorizedSigners.
    function test_P10_anchor_with_unregistered_signer_does_not_register_it() public {
        bool authBefore = reg.authorizedSigners(ATTACKER_VK);
        assertFalse(authBefore, "precondition: attacker VK not registered");

        // anchor() reverts because the signer is unauthorized.
        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.UnauthorizedSigner.selector, ATTACKER_VK
        ));
        reg.anchor(
            keccak256("d"), keccak256("e"), keccak256("r"),
            bytes32(0), ATTACKER_VK,
            uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );

        // Critically: authorization state is unchanged.
        bool authAfter = reg.authorizedSigners(ATTACKER_VK);
        assertFalse(authAfter, "anchor() must not register a new signer as a side effect");
    }

    // -----------------------------------------------------------------------
    // Fuzz — every privileged function rejects every non-privileged caller
    // -----------------------------------------------------------------------

    /// @dev Property: for any non-privileged caller, every privileged
    ///      function reverts. Encodes the Poly-Network claim that the
    ///      privilege boundary is in `msg.sender`, not in any
    ///      caller-supplied data.
    function testFuzz_arbitrary_caller_cannot_invoke_admin_functions(
        address caller,
        bytes32 vkA,
        bytes32 vkB,
        bytes32 entity,
        address victim
    ) public {
        vm.assume(caller != ADMIN);
        vm.assume(caller != address(0));
        vm.assume(vkA != bytes32(0));
        vm.assume(vkB != bytes32(0));
        vm.assume(entity != bytes32(0));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.registerSigner(vkA);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.revokeSigner(vkA);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.rotateSigner(vkA, vkB);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.reassignEntitySigner(entity, vkA);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.setBindingDisputeVerifier(victim);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.transferAdmin(victim);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, caller));
        reg.pause();
    }

    /// @dev Property: any caller other than the configured
    ///      bindingDisputeVerifier (including ADMIN) cannot call
    ///      disputeBinding.
    function testFuzz_arbitrary_caller_cannot_dispute_binding(
        address caller,
        bytes32 entity,
        bytes32 fpHash
    ) public {
        vm.assume(caller != DISPUTE_VERIFIER);
        vm.assume(caller != address(0));
        vm.assume(entity != bytes32(0));

        vm.prank(caller);
        vm.expectRevert(); // NotBindingDisputeVerifier(caller)
        reg.disputeBinding(entity, fpHash);
    }
}
