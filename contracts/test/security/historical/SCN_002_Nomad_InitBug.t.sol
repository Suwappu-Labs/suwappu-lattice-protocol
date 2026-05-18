// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {LTPAnchorRegistry} from "../../../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../../../src/interfaces/ILTPAnchorRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title SCN_002_Nomad_InitBug
/// @notice Red-team scenario SCN-002 — Nomad-class "init sets a
///         default trust value that whitelists any input" pattern. See
///         docs/security/audits/threat-intel/SCN-002-nomad-init-bug/.
///
/// Historical incident: Nomad bridge, Aug 2022, $190M. The Replica
/// contract's `initialize()` set `confirmedRoots[bytes32(0)] = 1`,
/// making the zero-hash a "trusted root". Combined with `prove()`
/// defaulting unverified messages to root `bytes32(0)`, any message
/// could be processed as if pre-verified. The fix was to never
/// pre-trust the zero sentinel.
///
/// LTP analogue: `LTPAnchorRegistry._anchor()` is built so that every
/// zero-valued primary input is rejected at the boundary
/// (LTP-A-003 — `INFO` severity in the audit because the defenses
/// listed below already block the Nomad-class flow). This scenario
/// pins those defenses.
///
///   (Z1) `anchorDigest == bytes32(0)` → revert ZeroDigest
///   (Z2) `entityIdHash == bytes32(0)` → revert ZeroEntityId
///   (Z3) `merkleRoot == bytes32(0)` → revert ZeroMerkleRoot
///   (Z4) `signerVkHash == bytes32(0)` → revert ZeroSignerVk
///   (Z5) `policyHash == bytes32(0)` is intentionally accepted as a
///        "no on-chain policy enforced" sentinel; it must NOT bypass
///        any other check.
///   (Z6) `initialize()` can only be called once on the proxy and
///        cannot be called on the implementation (constructor
///        `_disableInitializers()` at LTPAnchorRegistry.sol:97).
///   (Z7) Post-init, `_anchors[bytes32(0)].anchoredAt` is always 0 —
///        no record is ever stored under the zero digest, mirroring
///        the "never pre-trust the sentinel" fix Nomad shipped.
contract SCN002_Nomad_InitBug is Test {
    LTPAnchorRegistry internal impl;
    LTPAnchorRegistry internal reg;

    address internal constant ADMIN = address(0xA11CE);
    bytes32 internal constant LEGIT_VK = keccak256("legit-vk-002");

    function setUp() public {
        impl = new LTPAnchorRegistry();
        bytes memory initData = abi.encodeCall(LTPAnchorRegistry.initialize, (ADMIN));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        reg = LTPAnchorRegistry(address(proxy));

        vm.prank(ADMIN);
        reg.registerSigner(LEGIT_VK);
    }

    // -----------------------------------------------------------------------
    // Z1 — Zero anchor digest rejected
    // -----------------------------------------------------------------------

    function test_Z1_zero_anchor_digest_rejected() public {
        vm.expectRevert(ILTPAnchorRegistry.ZeroDigest.selector);
        reg.anchor(
            bytes32(0),                            // ← Nomad-style zero sentinel
            keccak256("entity"), keccak256("root"),
            bytes32(0), LEGIT_VK,
            uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Z2 — Zero entity id rejected
    // -----------------------------------------------------------------------

    function test_Z2_zero_entity_id_rejected() public {
        vm.expectRevert(ILTPAnchorRegistry.ZeroEntityId.selector);
        reg.anchor(
            keccak256("digest"),
            bytes32(0),                            // ← zero entity
            keccak256("root"),
            bytes32(0), LEGIT_VK,
            uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Z3 — Zero merkle root rejected
    // -----------------------------------------------------------------------

    function test_Z3_zero_merkle_root_rejected() public {
        vm.expectRevert(ILTPAnchorRegistry.ZeroMerkleRoot.selector);
        reg.anchor(
            keccak256("digest"), keccak256("entity"),
            bytes32(0),                            // ← zero root
            bytes32(0), LEGIT_VK,
            uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Z4 — Zero signer VK hash rejected
    // -----------------------------------------------------------------------

    function test_Z4_zero_signer_vk_rejected() public {
        vm.expectRevert(ILTPAnchorRegistry.ZeroSignerVk.selector);
        reg.anchor(
            keccak256("digest"), keccak256("entity"), keccak256("root"),
            bytes32(0),
            bytes32(0),                            // ← zero VK
            uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Z5 — Zero policy hash is INTENTIONALLY accepted (sentinel)
    // -----------------------------------------------------------------------

    /// @dev policyHash == bytes32(0) is the documented sentinel for
    ///      "no policy enforced on-chain" (LTPAnchorRegistry.sol:528).
    ///      Verify it does NOT short-circuit the rest of the chain.
    function test_Z5_zero_policy_hash_accepted_but_other_defenses_still_run() public {
        bytes32 digest = keccak256("ok-digest");
        bytes32 entity = keccak256("ok-entity");

        // policyHash=0 should anchor successfully.
        reg.anchor(
            digest, entity, keccak256("root"),
            bytes32(0),                            // ← intentional sentinel
            LEGIT_VK,
            uint64(1), uint64(block.timestamp + 1 days), uint8(0)
        );
        ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(digest);
        assertEq(rec.merkleRoot, keccak256("root"));
        assertEq(rec.policyHash, bytes32(0));

        // But policyHash=0 must NOT bypass replay rejection.
        vm.expectRevert(abi.encodeWithSelector(
            ILTPAnchorRegistry.AlreadyAnchored.selector, digest
        ));
        reg.anchor(
            digest, entity, keccak256("root"),
            bytes32(0),
            LEGIT_VK,
            uint64(2), uint64(block.timestamp + 1 days), uint8(0)
        );
    }

    // -----------------------------------------------------------------------
    // Z6 — Initializer cannot be re-called
    // -----------------------------------------------------------------------

    function test_Z6_initializer_cannot_be_recalled_on_proxy() public {
        vm.expectRevert(); // OZ Initializable: InvalidInitialization
        reg.initialize(address(0xBEEF));
    }

    function test_Z6_initializer_cannot_be_called_on_implementation() public {
        // The implementation contract's constructor calls
        // `_disableInitializers()`. Any direct initialize() on the
        // implementation must revert.
        vm.expectRevert();
        impl.initialize(ADMIN);
    }

    // -----------------------------------------------------------------------
    // Z7 — Sentinel safety: no record ever lives under bytes32(0)
    // -----------------------------------------------------------------------

    function test_Z7_zero_digest_record_never_populated() public {
        ILTPAnchorRegistry.AnchorRecord memory rec = reg.getAnchorRecord(bytes32(0));
        assertEq(uint256(rec.anchoredAt), 0);
        assertEq(rec.merkleRoot, bytes32(0));
        assertEq(rec.signerVkHash, bytes32(0));
    }

    // -----------------------------------------------------------------------
    // Fuzz — any zero among the four primary inputs always reverts
    // -----------------------------------------------------------------------

    /// @dev Property: if ANY of {anchorDigest, entityIdHash,
    ///      merkleRoot, signerVkHash} is bytes32(0), the call must
    ///      revert — regardless of the other inputs.
    function testFuzz_any_zero_primary_input_reverts(
        bool zeroDigest,
        bool zeroEntity,
        bool zeroRoot,
        bool zeroVk,
        bytes32 saltDigest,
        bytes32 saltEntity,
        bytes32 saltRoot,
        bytes32 saltVk,
        uint64  sequence,
        uint64  validUntilOffset
    ) public {
        // At least one zero, otherwise the call is well-formed and the
        // property doesn't apply.
        vm.assume(zeroDigest || zeroEntity || zeroRoot || zeroVk);

        // Non-zero defaults for whichever isn't zeroed.
        vm.assume(saltDigest != bytes32(0));
        vm.assume(saltEntity != bytes32(0));
        vm.assume(saltRoot != bytes32(0));
        vm.assume(saltVk != bytes32(0));

        bytes32 digest = zeroDigest ? bytes32(0) : saltDigest;
        bytes32 entity = zeroEntity ? bytes32(0) : saltEntity;
        bytes32 root   = zeroRoot   ? bytes32(0) : saltRoot;
        bytes32 vk     = zeroVk     ? bytes32(0) : saltVk;

        uint64 validUntil = uint64(block.timestamp) +
            uint64(bound(uint256(validUntilOffset), 1, 365 days));

        vm.expectRevert();
        reg.anchor(digest, entity, root, bytes32(0), vk, sequence, validUntil, uint8(0));
    }
}
