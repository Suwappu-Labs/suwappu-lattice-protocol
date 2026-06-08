// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SuwappuVault} from "../../src/SuwappuVault.sol";
import {SuwappuMintAdapter} from "../../src/SuwappuMintAdapter.sol";
import {SuwappuWrappedToken} from "../../src/SuwappuWrappedToken.sol";
import {SuwappuEcdsaMintVerifier} from "../../src/verifiers/SuwappuEcdsaMintVerifier.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SuwappuSupplyInvariantTest
/// @notice Cross-domain stateful invariant suite for the Suwappu lock-and-mint
///         custody layer. This is the centerpiece harness called for in the
///         audit program (P1): it deploys the SOURCE-chain Vault together with
///         the DEST-chain MintAdapter + WrappedToken in one EVM and models the
///         RELAYER as the adversary — the actual trust boundary of the bridge.
///
/// The relayer can act honestly (mint exactly what was locked, using the
/// vault's own commitId) OR adversarially (mint with an arbitrary commitId /
/// amount, or reclaim a refund on a commit it already minted against). Because
/// `SuwappuMintAdapter.mint` never recomputes the commitId and `claimRefund`
/// has no cross-chain mint signal, BOTH of the following canonical bridge
/// invariants are expected to be VIOLATED on the current code:
///
///   INV-SUPPLY : wrapped.totalSupply() <= vault.totalLocked(asset)
///                (wrapped tokens must always be backed by locked collateral)
///   INV-XOR    : each vault commitId ends in at most one terminal outcome of
///                {minted, unlocked, refunded}  (no double-spend)
///
/// A GREEN run only becomes meaningful AFTER the C1 (commitId binding) and
/// C2 (refund-vs-mint) fixes land; today these must be RED. The harness follows
/// the Handler + ghost-variable pattern established in
/// OptimisticBridgeChallenge.invariant.t.sol.
contract SuwappuSupplyInvariantTest is Test {
    SuwappuVault         internal vault;
    SuwappuMintAdapter   internal adapter;
    SuwappuWrappedToken  internal wrapped;
    SuwappuSupplyHandler internal handler;

    address internal constant ADMIN = address(0xA1);
    address internal constant ETH   = address(0); // native asset sentinel

    function setUp() public {
        // feeBps = 0 so netAmount == grossAmount: keeps the supply/collateral
        // accounting exact (fees are an orthogonal concern, covered by INV-FEE).
        vault = new SuwappuVault(ADMIN, ADMIN, 0);

        // Wrapped token represents native ETH bridged from THIS chain.
        wrapped = new SuwappuWrappedToken(
            "Suwappu Wrapped Ether",
            "swETH",
            18,
            block.chainid,
            ETH,
            ADMIN,
            ADMIN  // minterManager = admin for the harness
        );

        adapter = new SuwappuMintAdapter(ADMIN, address(wrapped));

        // On-chain attestation gate: only an AUTHORIZED operator's signature
        // over the bound mint digest lets mint() succeed (the C1/P3-1/P3-5 fix).
        SuwappuEcdsaMintVerifier verifier = new SuwappuEcdsaMintVerifier(ADMIN);
        uint256 operatorPk = 0xA110CE;
        address operator = vm.addr(operatorPk);

        handler = new SuwappuSupplyHandler(vault, adapter, wrapped, operatorPk);

        vm.startPrank(ADMIN);
        wrapped.grantRole(wrapped.MINTER_ROLE(), address(adapter));
        wrapped.grantRole(wrapped.BURNER_ROLE(), address(adapter));
        adapter.addRelayer(address(handler)); // relayer == adversary (now needs a valid attestation)
        adapter.setVerifier(address(verifier));
        vault.setRefundVerifier(address(verifier)); // same operator gates refunds (C2)
        verifier.setOperator(operator, true);
        vault.addUnlocker(address(handler));   // also the source-chain unlocker
        vm.stopPrank();

        targetContract(address(handler));
    }

    /// INV-SUPPLY: minted wrapped supply can never exceed locked collateral.
    function invariant_supply_le_collateral() public view {
        assertLe(
            wrapped.totalSupply(),
            vault.totalLocked(ETH),
            "INV-SUPPLY violated: wrapped supply exceeds locked collateral"
        );
    }

    /// INV-XOR: a commit is never BOTH bridged-forward (minted) AND refunded —
    /// the cross-domain double-spend (C2). (A forward mint followed by a
    /// burn+unlock return is legitimate and not a violation.)
    function invariant_one_commit_one_outcome() public view {
        assertFalse(
            handler.observedDoubleSpend(),
            "INV-XOR violated: a commitId was both minted and refunded (C2)"
        );
    }
}

/// @notice Bounds the fuzzer to legal (and adversarial-but-permitted) entry
///         points and tracks cross-domain ghost state.
contract SuwappuSupplyHandler is Test {
    SuwappuVault        public vault;
    SuwappuMintAdapter  public adapter;
    SuwappuWrappedToken public wrapped;

    address internal constant ETH  = address(0);
    uint256 internal constant DEST = 8453; // Base, the nominal destination chain

    bytes32[] public commits;
    mapping(bytes32 => uint256) public lockedNet; // commitId -> net locked
    mapping(bytes32 => bool) public minted;
    mapping(bytes32 => bool) public returned;  // forward mint later burned+unlocked
    mapping(bytes32 => bool) public refunded;

    bool public observedDoubleSpend;

    function _checkXor(bytes32 id) internal {
        // The only illegitimate combination: minted AND refunded (C2).
        if (minted[id] && refunded[id]) observedDoubleSpend = true;
    }

    uint256 internal operatorPk;   // authorized operator (honest attestations)
    uint256 internal constant ROGUE_PK = 0xBADBAD; // unauthorized (self-signed, P3-1)

    constructor(SuwappuVault _v, SuwappuMintAdapter _a, SuwappuWrappedToken _w, uint256 _operatorPk) {
        vault = _v;
        adapter = _a;
        wrapped = _w;
        operatorPk = _operatorPk;
        vm.deal(address(this), 10_000 ether);
    }

    receive() external payable {}

    /// Produce an ECDSA attestation over `digest` signed by `pk`.
    function _attest(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    // ---- User locks ETH on the source chain ----
    function lock(uint256 amt) external {
        amt = bound(amt, 1, 10 ether);
        if (address(this).balance < amt) return;
        try vault.lockETH{value: amt}(DEST, address(this)) returns (bytes32 id) {
            commits.push(id);
            lockedNet[id] = amt; // feeBps == 0 => net == gross
        } catch {}
    }

    // ---- Relayer mints HONESTLY: exactly the locked amount, with a VALID
    //      authorized-operator attestation over the bound digest. ----
    function honestMint(uint256 i) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        // Honest operator coordination: never attest a mint for a commit it has
        // already refunded (the cross-domain exactly-once invariant the operator
        // enforces; on-chain each side is one-shot, the operator binds them).
        if (minted[id] || refunded[id] || lockedNet[id] == 0) return;
        bytes32 digest = adapter.mintDigest(id, address(this), lockedNet[id], block.chainid);
        bytes memory att = _attest(operatorPk, digest);
        try adapter.mint(id, address(this), lockedNet[id], block.chainid, att) {
            minted[id] = true;
            _checkXor(id);
        } catch {}
    }

    // ---- Relayer mints ADVERSARIALLY: arbitrary commitId/amount, NO valid
    //      operator attestation (C1). Must always revert post-fix. ----
    function maliciousMint(bytes32 fakeId, uint256 amt, address to, bytes calldata junkAtt) external {
        amt = bound(amt, 1, 100 ether);
        if (to == address(0)) to = address(0xBAD);
        if (lockedNet[fakeId] != 0) return; // must be an id with NO backing lock
        try adapter.mint(fakeId, to, amt, block.chainid, junkAtt) {} catch {}
    }

    // ---- Attacker SELF-SIGNS with an unauthorized key (P3-1). Must revert. ----
    function selfSignedMint(bytes32 fakeId, uint256 amt, address to) external {
        amt = bound(amt, 1, 100 ether);
        if (to == address(0)) to = address(0xBAD);
        if (lockedNet[fakeId] != 0) return;
        bytes32 digest = adapter.mintDigest(fakeId, to, amt, block.chainid);
        bytes memory rogueAtt = _attest(ROGUE_PK, digest); // valid sig, wrong (unauthorized) key
        try adapter.mint(fakeId, to, amt, block.chainid, rogueAtt) {} catch {}
    }

    // ---- Legitimate RETURN path: burn wrapped (−supply) then unlock (−collateral).
    //      Only valid for a minted commit; supply and collateral move together. ----
    function returnPath(uint256 i) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        uint256 amt = lockedNet[id];
        if (!minted[id] || returned[id] || amt == 0) return;
        if (wrapped.balanceOf(address(this)) < amt) return;
        try adapter.burn(amt, block.chainid, address(this)) {
            try vault.unlock(id, address(this)) {
                returned[id] = true;
            } catch {}
        } catch {}
    }

    // ---- HONEST refund: only for a NON-minted commit, with an operator
    //      refund-eligibility attestation (operator won't sign for minted). ----
    function refund(uint256 i) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        if (minted[id] || refunded[id]) return; // honest operator: no refund att for minted
        bytes32 digest = vault.refundDigest(id);
        bytes memory att = _attest(operatorPk, digest);
        try vault.claimRefund(id, att) {
            refunded[id] = true;
            _checkXor(id);
        } catch {}
    }

    // ---- ADVERSARIAL refund-after-mint (C2): try to refund a MINTED commit.
    //      The operator never signs this, and a rogue sig is rejected -> reverts. ----
    function maliciousRefundAfterMint(uint256 i, bool useRogueSig) external {
        if (commits.length == 0) return;
        bytes32 id = commits[i % commits.length];
        if (!minted[id] || returned[id] || refunded[id]) return;
        bytes32 digest = vault.refundDigest(id);
        // Attacker can only forge with an unauthorized key (rejected) or junk.
        bytes memory att = useRogueSig ? _attest(ROGUE_PK, digest) : bytes("junk");
        try vault.claimRefund(id, att) {
            refunded[id] = true; // if this ever succeeds, INV-XOR catches it
            _checkXor(id);
        } catch {}
    }

    // ---- Advance time so refunds become claimable ----
    function warp(uint256 secs) external {
        secs = bound(secs, 0, 30 days);
        vm.warp(block.timestamp + secs);
    }
}
