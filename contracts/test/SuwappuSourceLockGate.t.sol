// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SuwappuMintAdapter} from "../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../src/SuwappuWrappedToken.sol";
import {SuwappuEcdsaMintVerifier} from "../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {ISourceLockVerifier, LockClaim} from "../src/interfaces/ISourceLockVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice Configurable mock source-lock verifier. `verifyLock` is view, so to
///         assert the adapter passes the CORRECT claim we run in MatchClaim mode:
///         it returns true only if the claim hashes to a pre-registered value.
contract MockSourceLockVerifier is ISourceLockVerifier {
    enum Mode {
        AcceptAny,
        RejectAll,
        MatchClaim
    }

    Mode public mode;
    bytes32 public expectedClaimHash;
    bytes32 public expectedProofHash;
    bool public checkProof;

    function setMode(Mode m) external {
        mode = m;
    }

    function setExpectedClaim(LockClaim calldata c) external {
        expectedClaimHash = keccak256(abi.encode(c));
    }

    function setExpectedProof(bytes calldata p) external {
        expectedProofHash = keccak256(p);
        checkProof = true;
    }

    function verifyLock(LockClaim calldata claim, bytes calldata proof)
        external
        view
        returns (bool)
    {
        if (mode == Mode.RejectAll) return false;
        if (checkProof && keccak256(proof) != expectedProofHash) return false;
        if (mode == Mode.MatchClaim) return keccak256(abi.encode(claim)) == expectedClaimHash;
        return true; // AcceptAny
    }
}

/// @notice P10 Phase A: the source-lock proof gate on SuwappuMintAdapter.mint.
///         Verifies the flag engages/bypasses correctly and that the adapter
///         builds the LockClaim from the exact mint params (binding).
contract SuwappuSourceLockGateTest is Test {
    SuwappuMintAdapter adapter;
    SuwappuWrappedToken token;
    SuwappuEcdsaMintVerifier legacyVerifier;
    MockSourceLockVerifier sourceVerifier;

    address admin = makeAddr("admin");
    address minterManager = makeAddr("minterManager");
    address relayer = makeAddr("relayer");
    address alice = makeAddr("alice");
    address constant SRC_VAULT = address(0x5A0FCE); // pinned source Vault (placeholder)

    uint256 constant OPERATOR_PK = 0xA110CE;
    address operator;
    uint256 constant SRC_CHAIN = 84_532; // Base Sepolia
    bytes32 constant COMMIT = keccak256("commit-1");

    function setUp() public {
        token = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether", "swETH", 18, SRC_CHAIN, address(0), admin, minterManager
        );
        adapter = new SuwappuMintAdapter(admin, address(token));
        legacyVerifier = new SuwappuEcdsaMintVerifier(admin);
        sourceVerifier = new MockSourceLockVerifier();
        operator = vm.addr(OPERATOR_PK);

        bytes32 minterRole = token.MINTER_ROLE();
        vm.prank(minterManager);
        token.grantRole(minterRole, address(adapter));

        vm.startPrank(admin);
        adapter.addRelayer(relayer);
        adapter.setVerifier(address(legacyVerifier));
        legacyVerifier.setOperator(operator, true);
        vm.stopPrank();
    }

    function _legacyAtt(bytes32 commitId, address recipient, uint256 amount, uint256 src)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = adapter.mintDigest(commitId, recipient, amount, src);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(OPERATOR_PK, MessageHashUtils.toEthSignedMessageHash(digest));
        return abi.encodePacked(r, s, v);
    }

    function _enableP10() internal {
        vm.startPrank(admin);
        adapter.setSourceLockVerifier(address(sourceVerifier));
        adapter.setSourceVault(SRC_CHAIN, SRC_VAULT);
        vm.stopPrank();
    }

    // ----- legacy path (flag unset) -----

    function test_LegacyPath_UsesAttestation_WhenVerifierUnset() public {
        bytes memory att = _legacyAtt(COMMIT, alice, 1 ether, SRC_CHAIN);
        vm.prank(relayer);
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, att);
        assertEq(token.balanceOf(alice), 1 ether);
    }

    // ----- P10 path (flag set) -----

    function test_P10Path_MintsWhenProofAccepted() public {
        _enableP10();
        sourceVerifier.setMode(MockSourceLockVerifier.Mode.AcceptAny);
        vm.prank(relayer);
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, hex"c0ffee");
        assertEq(token.balanceOf(alice), 1 ether);
        assertTrue(adapter.isMinted(COMMIT));
    }

    function test_P10Path_RevertsWhenProofRejected() public {
        _enableP10();
        sourceVerifier.setMode(MockSourceLockVerifier.Mode.RejectAll);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuMintAdapter.SourceLockNotProven.selector, COMMIT)
        );
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, hex"c0ffee");
    }

    function test_P10Path_RevertsWhenSourceVaultUnset() public {
        vm.prank(admin);
        adapter.setSourceLockVerifier(address(sourceVerifier)); // verifier set, vault NOT pinned
        sourceVerifier.setMode(MockSourceLockVerifier.Mode.AcceptAny);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuMintAdapter.SourceVaultNotSet.selector, SRC_CHAIN)
        );
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, hex"c0ffee");
    }

    /// The adapter must build the claim from the EXACT mint params + pinned vault +
    /// block.chainid. MatchClaim returns true only for that precise claim.
    function test_P10Path_BindsClaimToMintParams() public {
        _enableP10();
        sourceVerifier.setMode(MockSourceLockVerifier.Mode.MatchClaim);
        LockClaim memory expected = LockClaim({
            sourceChainId: SRC_CHAIN,
            sourceVault: SRC_VAULT,
            commitId: COMMIT,
            destRecipient: alice,
            amount: 1 ether,
            destChainId: block.chainid
        });
        sourceVerifier.setExpectedClaim(expected);

        // exact claim → accepted
        vm.prank(relayer);
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, hex"01");
        assertEq(token.balanceOf(alice), 1 ether);

        // a different amount produces a different claim → rejected
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                SuwappuMintAdapter.SourceLockNotProven.selector, keccak256("commit-2")
            )
        );
        adapter.mint(keccak256("commit-2"), alice, 2 ether, SRC_CHAIN, hex"01");
    }

    function test_P10Path_ChecksProofBytes() public {
        _enableP10();
        sourceVerifier.setMode(MockSourceLockVerifier.Mode.AcceptAny);
        sourceVerifier.setExpectedProof(hex"deadbeef");

        // wrong proof → rejected
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(SuwappuMintAdapter.SourceLockNotProven.selector, COMMIT)
        );
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, hex"00");

        // correct proof → minted
        vm.prank(relayer);
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, hex"deadbeef");
        assertEq(token.balanceOf(alice), 1 ether);
    }

    function test_ClearingVerifier_FallsBackToLegacy() public {
        _enableP10();
        vm.prank(admin);
        adapter.setSourceLockVerifier(address(0)); // clear
        // now the legacy attestation path is required again
        bytes memory att = _legacyAtt(COMMIT, alice, 1 ether, SRC_CHAIN);
        vm.prank(relayer);
        adapter.mint(COMMIT, alice, 1 ether, SRC_CHAIN, att);
        assertEq(token.balanceOf(alice), 1 ether);
    }

    function test_Setters_OnlyAdmin() public {
        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.Unauthorized.selector);
        adapter.setSourceLockVerifier(address(sourceVerifier));

        vm.prank(alice);
        vm.expectRevert(SuwappuMintAdapter.Unauthorized.selector);
        adapter.setSourceVault(SRC_CHAIN, SRC_VAULT);
    }
}
