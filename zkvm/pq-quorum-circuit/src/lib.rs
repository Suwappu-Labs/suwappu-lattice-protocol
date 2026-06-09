//! # pq-quorum-circuit — Track B Phase 1 skeleton
//!
//! Hash-based post-quantum quorum circuit for the Suwappu bridge.
//!
//! ## Honest framing
//!
//! This crate is a **scaffold** — structure, type definitions, reused logic,
//! and precise integration points.  The novel cryptographic pieces (leanXMSS
//! signature verification, leanMultisig aggregation, the Spartan-WHIR proof)
//! are stubbed with `todo!()` and doc comments pointing at the real work.
//!
//! The **quorum logic** (threshold arithmetic, strictly-increasing keccak(pubkey)
//! dedup, set-membership stake lookup) is **identical** to the ML-DSA path and
//! is **directly reused** from `quorum-core` — `quorum_threshold`,
//! `quorum_reached`, `keccak256`, and `Validator`.  The ONLY new piece is the
//! signature-verification gadget; this crate expresses that seam via
//! [`HashBasedSigVerify`].
//!
//! ## Post-quantum guarantee
//!
//! "PQ" is accurate *once this is built*: leanXMSS is hash-only (Merkle path +
//! W-OTS+ chains over Poseidon/KoalaBear), and Spartan-WHIR is hash-only.
//! **No elliptic curves anywhere** — no BN254, no secp256k1.  This is the
//! property that makes it resist Shor's algorithm, unlike the current
//! Groth16-wrapped ML-DSA path (which has a classical BN254 wrapper).
//!
//! ## Architecture (full pipeline, built → stub order)
//!
//! ```text
//! [BUILT] gsx-dag validators hold leanXMSS keypairs alongside ML-DSA.
//!           xmss_key_gen / xmss_sign — leanMultisig::xmss crate
//!                │
//! [STUB]  Off-chain aggregator calls aggregate_and_prove().
//!           aggregate_single_message_signatures() — leanMultisig::rec_aggregation
//!                │
//! [STUB]  leanMultisig outputs a WHIR proof (98–344 KiB).
//!           SingleMessageAggregateSignature / verify_single_message_aggregate
//!                │
//! [MISSING] Recursion / wrapping step — not yet built.
//!           A Spartan-WHIR circuit that takes the leanMultisig WHIR proof as its
//!           statement and produces a ~10 KB blob verifiable by sol-spartan-whir.
//!                │
//! [EXTERNAL] sol-spartan-whir EVM verifier (see §Integration map below).
//!           WhirBlobVerifier5::verify(expectedCommitment, blob) → bool
//!                │
//! [BUILT] On-chain binding seam — Sp1QuorumVerifier.sol's setVerifier() drop-in.
//!           Replace sp1Verifier.verifyProof(...) with whirVerifier.verify(...)
//! ```
//!
//! ## Integration map — exact file/function names
//!
//! ### leanMultisig  (pq-research/leanMultisig)
//! | Symbol | File | Notes |
//! |--------|------|-------|
//! | `xmss_key_gen(seed, start_slot, end_slot, false)` | `crates/xmss/src/xmss.rs` | Generate a validator leanXMSS keypair. |
//! | `xmss_sign(rng, &sk, &message, slot)` | `crates/xmss/src/xmss.rs` | Sign a bridge header digest (MESSAGE_LEN_FE = 8 KoalaBear field elements). |
//! | `xmss_verify(&pk, &message, &sig, slot)` | `crates/xmss/src/xmss.rs` | Verify one signature — the thing this crate stubs out. |
//! | `aggregate_single_message_signatures(&[], raws, msg, slot, log_inv_rate)` | `crates/rec_aggregation/src/lib.rs` | Aggregate N raw (pk, sig) pairs into a WHIR proof. |
//! | `verify_single_message_aggregate(&agg)` | `src/lib.rs` re-exported | Verify the WHIR proof natively. |
//! | `SingleMessageAggregateSignature::to_bytes()` | `crates/rec_aggregation` | Serialize the proof for transport. |
//! | `XmssPublicKey`, `XmssSecretKey`, `XmssSignature` | `crates/xmss/src/lib.rs` | Public types. |
//! | `MESSAGE_LEN_FE = 8` | `crates/xmss/src/lib.rs` | The signed message is 8 KoalaBear field elements (not raw bytes). |
//! | `setup_prover()` | `src/lib.rs` | Must be called once before proving (arena allocator + DFT twiddles). |
//!
//! ### sol-spartan-whir  (pq-research/sol-spartan-whir)
//! | Symbol | File | Notes |
//! |--------|------|-------|
//! | `WhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28` | `src/whir/k22_jb100_.../WhirBlobVerifier5_....sol` | The EVM entry-point: `verify(bytes32 expectedCommitment, bytes calldata blob) returns (bool)`. Measured: 5,454,992 gas (100-bit, quintic). |
//! | `WhirBlobVerifierNative4` (lir11) | `src/whir/.../WhirBlobVerifierNative4.sol` | Measured: 899,906 gas (80-bit, quartic). Development / Gate-1 target. |
//! | `WhirBlobCodec5.decode(blob)` | `src/whir/.../WhirBlobCodec5_....sol` | Deserializes the ~54 KB blob into (WhirStatement, WhirProof). |
//! | `WhirStructs.WhirStatement`, `WhirStructs.WhirProof` | `src/spartan/SpartanStructs.sol` | Types accepted by the verifier. |

// ---------------------------------------------------------------------------
// Re-exports from quorum-core (what we REUSE unchanged)
// ---------------------------------------------------------------------------

pub use quorum_core::{
    // The Validator type (pk_hash: [u8;32], stake: u128) — identical for PQ path.
    Validator,
    // Threshold arithmetic: (total_stake * 2) / 3 + 1 — reused verbatim.
    quorum_reached,
    quorum_threshold,
    // keccak256(pubkey) — the canonical validator ID on both paths.
    keccak256,
};

// ---------------------------------------------------------------------------
// Public-inputs and witness types
// ---------------------------------------------------------------------------

/// Public inputs committed by the Spartan-WHIR proof.
///
/// These are the values the EVM verifier (and the Solidity contract) binds.
/// Layout must be byte-identical to what the prover commits — TBD once the
/// outer recursion circuit is designed.
///
/// Mirrors `Sp1QuorumVerifier.sol`'s 128-byte public-values layout:
/// `networkId(32) || blockNumber(32) || stateRoot(32) || validatorSetRoot(32)`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicInputs {
    /// `registry.networkId()` — binds the proof to a specific chain.
    pub network_id: [u8; 32],
    /// The GSX-DAG block number being attested.
    pub block_number: u64,
    /// The EVM state root at that block.
    pub state_root: [u8; 32],
    /// `keccak256`-root of the validator set that signed.
    /// Must equal `registry.currentValidatorSetRoot()` on-chain.
    pub validator_set_root: [u8; 32],
}

/// One signer's raw contribution on the PQ path.
///
/// Unlike `quorum_core::SignerInput` (which holds raw ML-DSA bytes), this holds
/// leanXMSS types.  The pubkey is a leanXMSS Merkle root (not an ML-DSA
/// verifying key); the signature is a leanXMSS path + W-OTS+ chain.
///
/// In practice the prover takes `(XmssPublicKey, XmssSignature)` from leanMultisig;
/// this wrapper carries the serialised forms for transport.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PqSignerInput {
    /// Serialised leanXMSS public key (KoalaBear field elements, see
    /// `XmssPublicKey` in leanMultisig/crates/xmss/src/xmss.rs).
    /// PUB_KEY_FLAT_SIZE = XMSS_DIGEST_LEN + PUBLIC_PARAM_LEN_FE = 4 + 4 = 8 KoalaBear FEs.
    pub pubkey_bytes: Vec<u8>,
    /// Serialised leanXMSS signature (see `XmssSignature`).
    pub sig_bytes: Vec<u8>,
    /// The slot number the signature was produced at (leanXMSS is STATEFUL;
    /// slot advances with every signing operation and must not be reused).
    pub slot: u32,
}

/// The full witness for one quorum-proof.
///
/// The prover receives this struct, runs aggregation, and produces a WHIR proof.
#[derive(Clone, Debug)]
pub struct Witness {
    /// The registered validator set for this epoch (from the on-chain registry).
    pub validators: Vec<Validator>,
    /// The signers who participated, with their leanXMSS signatures.
    /// Must be in strictly-increasing order by `keccak256(pubkey_bytes)`.
    pub signers: Vec<PqSignerInput>,
    /// The header digest that was signed:
    /// `blake3(HEADER_DOMAIN || network_id || oracle || block_number || state_root)`.
    /// Encoded as `MESSAGE_LEN_FE = 8` KoalaBear field elements (see
    /// leanMultisig/crates/xmss/src/lib.rs).
    pub header_digest: [u8; 32],
}

// ---------------------------------------------------------------------------
// Signature-verification trait — the ONLY new primitive
// ---------------------------------------------------------------------------

/// Post-quantum signature verification gadget.
///
/// This trait is the single new piece that the PQ path adds.  All quorum
/// logic (dedup, membership, threshold) is unchanged from `quorum-core`.
///
/// # For Jacob (@Jacob-Strokus)
///
/// The production implementation is [`LeanXmssVerify`], which calls
/// `xmss_verify` from leanMultisig's `crates/xmss/src/xmss.rs`.  The
/// signature there is:
/// ```ignore
/// pub fn xmss_verify(
///     pub_key: &XmssPublicKey,
///     message: &[KoalaBear; MESSAGE_LEN_FE],
///     signature: &XmssSignature,
///     slot: u32,
/// ) -> Result<(), XmssError>
/// ```
///
/// The message is 8 KoalaBear field elements, NOT a raw byte slice.  The
/// bridge's `header_digest` (32 bytes) must be encoded into this format.
/// The encoding convention (byte → field element mapping) must be pinned
/// and documented here before Phase 1 Gate.
pub trait HashBasedSigVerify {
    /// Returns `true` iff the signature is valid.
    ///
    /// `pubkey`  — serialised leanXMSS public key bytes
    /// `sig`     — serialised leanXMSS signature bytes
    /// `message` — the header digest to verify against
    /// `slot`    — the XMSS slot this signature was produced at
    ///
    /// Must never panic; invalid/malformed inputs return `false`.
    fn verify(&self, pubkey: &[u8], sig: &[u8], message: &[u8; 32], slot: u32) -> bool;
}

/// Production implementation — calls leanMultisig's `xmss_verify`.
///
/// # STUB — `todo!()` inside
///
/// To implement:
/// 1. Add `lean_multisig` as a path-dep (it lives outside this workspace;
///    pull it in once the recursion step is designed and the dep story is clear).
/// 2. Deserialise `pubkey` → `XmssPublicKey` and `sig` → `XmssSignature`
///    using leanMultisig's `postcard` serde (see `crates/xmss/src/xmss.rs`).
/// 3. Encode `message: &[u8; 32]` → `[KoalaBear; MESSAGE_LEN_FE]`.
///    The encoding convention is NOT yet specified; pin it here.
/// 4. Call `xmss_verify(&pk, &encoded_message, &signature, slot)`.
///
/// See leanMultisig/tests/test_multisignatures.rs `test_xmss_signature` for
/// a working end-to-end example.
pub struct LeanXmssVerify;

impl HashBasedSigVerify for LeanXmssVerify {
    fn verify(&self, _pubkey: &[u8], _sig: &[u8], _message: &[u8; 32], _slot: u32) -> bool {
        todo!(
            "Phase 1 stub: call xmss_verify from leanMultisig/crates/xmss/src/xmss.rs. \
             See LeanXmssVerify doc comment for the 4 implementation steps."
        )
    }
}

// ---------------------------------------------------------------------------
// Core quorum-verification function (generic over sig scheme)
// ---------------------------------------------------------------------------

/// Error type for PQ quorum verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqQuorumError {
    /// Signer list is not strictly increasing by keccak256(pubkey_bytes).
    /// Mirrors `quorum_core::QuorumError::UnsortedOrDuplicate`.
    UnsortedOrDuplicate,
}

impl core::fmt::Display for PqQuorumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PQ signer list is not strictly increasing by keccak256(pubkey_bytes)"
        )
    }
}

/// Verify a PQ quorum: accumulate stake from valid, registered, sorted signers.
///
/// # What is REUSED from quorum-core
/// - [`keccak256`] — pkHash computation (identical).
/// - [`quorum_threshold`] — `(total * 2) / 3 + 1` (identical).
/// - [`quorum_reached`] — `sig_stake >= threshold` (identical).
/// - [`Validator`] — `(pk_hash, stake)` lookup table (identical).
/// - The sorting/dedup guard — strictly-increasing pkHash, same invariant as
///   `GsxDagValidatorRegistry._verifyQuorum`.
///
/// # What is DIFFERENT from quorum-core
/// - `quorum_core::verify_quorum_stake` hard-codes `mldsa_valid` in its loop.
///   We cannot call it directly; we re-express the same loop generically over
///   `V: HashBasedSigVerify`.  The loop invariant is identical; only the
///   signature-check call is swapped.
///
/// Returns `Ok(sig_stake)` if the signer list is sorted.
/// Returns `Err(PqQuorumError::UnsortedOrDuplicate)` otherwise.
pub fn verify_pq_quorum_stake<V: HashBasedSigVerify>(
    verifier: &V,
    header_digest: &[u8; 32],
    validators: &[Validator],
    signers: &[PqSignerInput],
) -> Result<u128, PqQuorumError> {
    let mut last = [0u8; 32];
    let mut sig_stake: u128 = 0;

    for signer in signers {
        let pk_hash = keccak256(&signer.pubkey_bytes);

        // Sorting guard — same invariant as quorum_core and the Solidity contract.
        if pk_hash <= last {
            return Err(PqQuorumError::UnsortedOrDuplicate);
        }
        last = pk_hash;

        // Stake lookup — reuses Validator type from quorum-core unchanged.
        let stake = validators
            .iter()
            .find(|v| v.pk_hash == pk_hash)
            .map(|v| v.stake)
            .unwrap_or(0);

        if stake == 0 {
            // Not registered this epoch — skip (no error), same as quorum-core.
            continue;
        }

        // Hash-based signature verification — THE ONLY NEW PIECE.
        // For the production path: verifier is LeanXmssVerify; it calls
        // xmss_verify from leanMultisig/crates/xmss/src/xmss.rs.
        if verifier.verify(&signer.pubkey_bytes, &signer.sig_bytes, header_digest, signer.slot) {
            sig_stake = sig_stake.saturating_add(stake);
        }
    }

    Ok(sig_stake)
}

// ---------------------------------------------------------------------------
// Aggregation and proving stubs
// ---------------------------------------------------------------------------

/// Opaque handle for a leanMultisig WHIR proof (98–344 KiB serialised).
///
/// The production type is `lean_multisig::SingleMessageAggregateSignature`
/// (leanMultisig/crates/rec_aggregation/src/lib.rs).  It serialises via
/// `to_bytes() / from_bytes()`.  We hold it as a byte blob here to avoid
/// pulling leanMultisig into this workspace.
#[derive(Clone, Debug)]
pub struct LeanMultisigProof {
    /// Serialised `SingleMessageAggregateSignature::to_bytes()`.
    pub bytes: Vec<u8>,
}

/// Opaque handle for a Spartan-WHIR blob (~10–54 KB).
///
/// The production type is the `bytes calldata blob` accepted by
/// `sol-spartan-whir`'s
/// `WhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28::verify(
///     bytes32 expectedCommitment, bytes calldata blob)`.
/// Decoded by `WhirBlobCodec5.decode(blob)` into
/// `(WhirStructs.WhirStatement, WhirStructs.WhirProof)`.
#[derive(Clone, Debug)]
pub struct SpartanWhirBlob {
    pub bytes: Vec<u8>,
}

/// Aggregate N leanXMSS signatures and produce a Spartan-WHIR proof blob.
///
/// # STUB — `todo!()` inside
///
/// ## Step 1: leanMultisig aggregation (YELLOW — recursion step missing)
/// Call `lean_multisig::aggregate_single_message_signatures(
///     &[],              // no sub-proofs to merge yet
///     raws,             // Vec<(XmssPublicKey, XmssSignature)>
///     message,          // [KoalaBear; MESSAGE_LEN_FE]
///     slot,             // u32
///     log_inv_rate,     // 1=fast/big, 4=slow/small
/// )` — leanMultisig/crates/rec_aggregation/src/lib.rs
///
/// This produces a `SingleMessageAggregateSignature` (WHIR proof, 98–344 KiB).
/// Verify natively with `lean_multisig::verify_single_message_aggregate(&agg)`.
///
/// ## Step 2: wrapping / recursion (RED — does not exist yet)
/// A Spartan-WHIR circuit that takes the leanMultisig WHIR proof as its witness
/// and produces a ~10 KB blob verifiable by the sol-spartan-whir EVM contract.
/// This is the "Unknown X" from PQ_PHASE0_ASSESSMENT.md §2 — the critical-path
/// item for Phase 1 → Phase 2 transition.  Estimated: 2–6 engineer-months.
///
/// The outer circuit statement: "I know a leanMultisig WHIR proof π such that
/// verify_single_message_aggregate(π) passes for (pubkeys ∈ validatorSetRoot,
/// stake ≥ threshold, all signed header_digest)."
///
/// ## Output
/// The serialised `SpartanWhirBlob` is what `PqQuorumVerifier.sol::submitProvenHeader`
/// will receive as `proofBytes`, replacing `Sp1QuorumVerifier`'s Groth16 bytes.
pub fn aggregate_and_prove(
    _public_inputs: &PublicInputs,
    _witness: &Witness,
    _log_inv_rate: usize,
) -> Result<(LeanMultisigProof, SpartanWhirBlob), AggregationError> {
    todo!(
        "Phase 1 stub — see doc comment for the two-step plan: \
         (1) aggregate_single_message_signatures (leanMultisig), \
         (2) recursion/wrapping to Spartan-WHIR blob (does not exist yet)."
    )
}

/// Errors from the aggregation + proving pipeline.
#[derive(Clone, Debug)]
pub enum AggregationError {
    /// leanMultisig returned an error.
    /// Wraps `lean_multisig::AggregationError` when that dep exists.
    LeanMultisigError(String),
    /// The wrapping/recursion step failed or has not been implemented.
    RecursionNotImplemented,
}

impl core::fmt::Display for AggregationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AggregationError::LeanMultisigError(e) => write!(f, "leanMultisig error: {e}"),
            AggregationError::RecursionNotImplemented => {
                write!(f, "Spartan-WHIR wrapping step not yet implemented (Phase 0 Unknown X)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — interface-pinning, logic-level correctness
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Deterministic stub verifier — used ONLY in tests.
    // A pubkey whose first byte is 0x01 is treated as "valid signature".
    // This lets us control which signers pass without touching the real crypto.
    // -----------------------------------------------------------------------

    struct StubVerify;

    impl HashBasedSigVerify for StubVerify {
        fn verify(&self, pubkey: &[u8], _sig: &[u8], _message: &[u8; 32], _slot: u32) -> bool {
            pubkey.first().copied() == Some(0x01)
        }
    }

    /// Build a validator from a raw pubkey seed byte.  The pubkey is a
    /// 32-byte slice with `seed` at position 0, rest zeros.
    fn make_validator(seed: u8) -> (Validator, PqSignerInput) {
        let mut pubkey = vec![0u8; 32];
        pubkey[0] = seed;
        let pk_hash = keccak256(&pubkey);
        let v = Validator { pk_hash, stake: 10 };
        let s = PqSignerInput {
            pubkey_bytes: pubkey,
            sig_bytes: vec![0u8; 8], // content irrelevant for StubVerify
            slot: 0,
        };
        (v, s)
    }

    // -----------------------------------------------------------------------
    // Happy path: 3-of-4 signers with equal stake → quorum reached
    // total_stake = 40, threshold = (40*2)/3+1 = 27, sig_stake (3×10) = 30 ≥ 27
    //
    // Pubkeys are 32 bytes: [0x01 or 0x02, distinguisher, 0, ...].
    // StubVerify checks pubkey[0] == 0x01, so three validators are "valid"
    // and one is "invalid".  The distinguisher byte in position 1 ensures all
    // pk_hashes are distinct.
    // -----------------------------------------------------------------------
    #[test]
    fn test_3_of_4_reaches_quorum() {
        // Three distinct valid validators: unique_id differs, StubVerify needs pubkey[0]==0x01.
        // Use multi-byte pubkeys: [0x01, distinguisher, 0, ...]
        let make_valid = |dist: u8| {
            let mut pubkey = vec![0u8; 32];
            pubkey[0] = 0x01; // StubVerify marks this valid
            pubkey[1] = dist; // distinct per-validator
            let pk_hash = keccak256(&pubkey);
            let v = Validator { pk_hash, stake: 10 };
            let s = PqSignerInput { pubkey_bytes: pubkey, sig_bytes: vec![0u8; 8], slot: 0 };
            (v, s)
        };
        let make_invalid = |dist: u8| {
            let mut pubkey = vec![0u8; 32];
            pubkey[0] = 0x02; // StubVerify → invalid
            pubkey[1] = dist;
            let pk_hash = keccak256(&pubkey);
            let v = Validator { pk_hash, stake: 10 };
            let s = PqSignerInput { pubkey_bytes: pubkey, sig_bytes: vec![0u8; 8], slot: 0 };
            (v, s)
        };

        let (v1, s1) = make_valid(0x01);
        let (v2, s2) = make_valid(0x02);
        let (v3, s3) = make_valid(0x03);
        let (v4, _s4) = make_invalid(0x01);

        // Sort signers into strictly-increasing pk_hash order.
        let mut validators = vec![v1.clone(), v2.clone(), v3.clone(), v4.clone()];
        let mut signers = vec![s1, s2, s3];

        // Verify all pk_hashes are distinct.
        assert!(
            validators.iter().map(|v| v.pk_hash).collect::<std::collections::HashSet<_>>().len() == 4,
            "test setup: all pk_hashes must be distinct"
        );

        signers.sort_by_key(|s| keccak256(&s.pubkey_bytes));
        validators.sort_by_key(|v| v.pk_hash);

        let total_stake: u128 = validators.iter().map(|v| v.stake).sum();
        assert_eq!(total_stake, 40);
        assert_eq!(quorum_threshold(total_stake), 27);

        let digest = [0xabu8; 32];
        let sig_stake =
            verify_pq_quorum_stake(&StubVerify, &digest, &validators, &signers).unwrap();
        assert_eq!(sig_stake, 30, "3 valid signers × stake 10 = 30");
        assert!(quorum_reached(sig_stake, total_stake), "30 >= 27 — quorum reached");
    }

    // -----------------------------------------------------------------------
    // Sub-quorum: only 1 valid signer out of 4 → quorum not reached
    // sig_stake = 10, threshold = 27 → fails
    // -----------------------------------------------------------------------
    #[test]
    fn test_sub_quorum_fails() {
        let (v1, s1) = make_validator(0x01); // valid
        let (v2, _s2) = make_validator(0x02); // invalid
        let (v3, _s3) = make_validator(0x03); // invalid
        let (v4, _s4) = make_validator(0x04); // invalid

        let mut validators = vec![v1.clone(), v2, v3, v4];
        validators.sort_by_key(|v| v.pk_hash);
        let total_stake: u128 = 40;
        let threshold = quorum_threshold(total_stake);
        assert_eq!(threshold, 27);

        let mut signers = vec![s1];
        signers.sort_by_key(|s| keccak256(&s.pubkey_bytes));

        let digest = [0xbcu8; 32];
        let sig_stake =
            verify_pq_quorum_stake(&StubVerify, &digest, &validators, &signers).unwrap();
        assert_eq!(sig_stake, 10);
        assert!(!quorum_reached(sig_stake, total_stake), "10 < 27 — sub-quorum");
    }

    // -----------------------------------------------------------------------
    // Sorted-duplicate guard: two signers with the same pk_hash → error
    // -----------------------------------------------------------------------
    #[test]
    fn test_duplicate_signer_rejected() {
        let (v1, s1) = make_validator(0x01);
        let validators = vec![v1];

        // Two identical signers.
        let signers = vec![s1.clone(), s1];

        let digest = [0x00u8; 32];
        let result = verify_pq_quorum_stake(&StubVerify, &digest, &validators, &signers);
        assert_eq!(result, Err(PqQuorumError::UnsortedOrDuplicate));
    }

    // -----------------------------------------------------------------------
    // Unregistered signer: valid sig but zero stake → contributes nothing
    // -----------------------------------------------------------------------
    #[test]
    fn test_unregistered_signer_contributes_nothing() {
        let (v1, s1) = make_validator(0x01); // registered, valid
        let (_, s_unregistered) = make_validator(0x05); // valid sig but NOT in registry

        let validators = vec![v1];

        // Sort: keccak(0x01...) vs keccak(0x05...) — order unknown, sort explicitly.
        let mut signers = vec![s1, s_unregistered];
        signers.sort_by_key(|s| keccak256(&s.pubkey_bytes));

        let digest = [0xcdu8; 32];
        let sig_stake =
            verify_pq_quorum_stake(&StubVerify, &digest, &validators, &signers).unwrap();
        // Only v1's stake (10) should be counted.
        assert_eq!(sig_stake, 10);
    }

    // -----------------------------------------------------------------------
    // Reused quorum_threshold correctness (same values as quorum-core tests,
    // confirming we call the original function not a local copy)
    // -----------------------------------------------------------------------
    #[test]
    fn test_reused_threshold_values() {
        assert_eq!(quorum_threshold(0), 1);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(100), 67);
    }

    // -----------------------------------------------------------------------
    // Overflow-safe threshold (regression: saturating math must not wrap)
    // -----------------------------------------------------------------------
    #[test]
    fn test_threshold_does_not_wrap() {
        let t = quorum_threshold(u128::MAX);
        assert!(t > u128::MAX / 4, "threshold must not wrap to a small value");
        assert!(!quorum_reached(1_000_000, u128::MAX));
    }
}
