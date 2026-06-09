//! # quorum-core — GSX-DAG validator-quorum verification (Path C, Slice 1)
//!
//! This crate implements the security-critical quorum-verification logic that the
//! SP1 Groth16 circuit will execute in-circuit (Slice 2).  Running it natively lets
//! the host verify proofs without an EVM precompile, and lets us write non-vacuous
//! ML-DSA-65 tests before touching the zkVM toolchain.
//!
//! ## Trust model
//!
//! Trust is **not** trustless: correctness relies on honest > 2/3-stake quorum
//! of registered GSX-DAG validators.  This is NOT a consensus light-client or
//! a ZK proof by itself.  It is the quorum-verification *logic* that a single
//! SP1 Groth16 proof will attest (once the SP1 guest wraps it in Slice 2), allowing
//! the on-chain `0x0101` ML-DSA precompile dependency to be replaced with a standard
//! EVM Groth16 verifier.
//!
//! ## What is NOT in this slice
//! - SP1 / RISC-V guest wrapping (Slice 2)
//! - BLAKE3 inclusion / Merkle proof (separate later slice)
//!
//! ## Relationship to the Solidity contract
//!
//! This mirrors `GsxDagValidatorRegistry._verifyQuorum` (lines 121-138) and
//! `submitHeader` (line 101) exactly, including:
//! - `pkHash = keccak256(pubkey)` — Keccak256, NOT SHA3-256
//! - Strictly-increasing pkHash order checked **unconditionally** for every signer
//!   (out-of-order unregistered signers still return `Err`; they are not skipped)
//! - `stakeOf[pkHash] == 0` → skip (0 contribution, no error)
//! - ML-DSA sig invalid → 0 contribution, no error
//! - `sigStake >= (totalStake * 2) / 3 + 1` (integer division, strictly > 2/3)

use sha3::{Digest, Keccak256};

// ml-dsa 0.1.1 re-exports Verifier from the `ml_dsa` crate root directly.
// (In rc.8, it was nested under `ml_dsa::signature::Verifier`.)
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A registered validator: (keccak256(pubkey), stake).
///
/// `pk_hash` is the canonical identifier used by the on-chain registry.
/// The raw public-key bytes are NOT stored here; they arrive per-signer in
/// [`SignerInput`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    /// `keccak256(raw_pubkey_bytes)` — matches `stakeOf[epoch][pkHash]` key.
    pub pk_hash: [u8; 32],
    /// Voting stake for this validator in this epoch.
    pub stake: u128,
}

/// One signer's raw contribution: the public key bytes and the ML-DSA-65
/// signature bytes, both in their encoded wire format.
#[derive(Clone, Debug)]
pub struct SignerInput {
    /// Raw ML-DSA-65 verifying-key bytes (1952 bytes for ML-DSA-65).
    pub pubkey: Vec<u8>,
    /// Raw ML-DSA-65 signature bytes (3309 bytes for ML-DSA-65).
    pub sig: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by [`verify_quorum_stake`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuorumError {
    /// Two consecutive signers had `pkHash[i] <= pkHash[i-1]`, i.e. the list
    /// is not strictly increasing.  This covers both out-of-order and duplicate
    /// signers, mirroring the Solidity `UnsortedOrDuplicate` revert.
    UnsortedOrDuplicate,
}

impl core::fmt::Display for QuorumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QuorumError::UnsortedOrDuplicate => {
                write!(
                    f,
                    "signer list is not strictly increasing by keccak256(pubkey)"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Compute `keccak256(data)` as a 32-byte array.
///
/// Matches Solidity `keccak256(abi.encodePacked(data))` when `data` is a
/// contiguous byte slice.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Verify ML-DSA-65 signature `sig_bytes` over `message` with `pubkey_bytes`.
///
/// Returns `false` for any error (malformed key, malformed sig, invalid sig).
/// Never panics, never returns `Err`.  Mirrors `_mldsaValid` in the contract.
fn mldsa_valid(pubkey_bytes: &[u8], sig_bytes: &[u8], message: &[u8]) -> bool {
    // Parse verifying key — wrong size → false
    let enc_vk = match EncodedVerifyingKey::<MlDsa65>::try_from(pubkey_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // `VerifyingKey::decode` is infallible on a correctly-sized input (no panic)
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);

    // Parse signature — wrong size → false
    let enc_sig = match EncodedSignature::<MlDsa65>::try_from(sig_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // `Signature::decode` returns None on malformed content
    let sig = match Signature::<MlDsa65>::decode(&enc_sig) {
        Some(s) => s,
        None => return false,
    };

    // `vk.verify` uses the standard ML-DSA.Verify with empty context string,
    // which is the same path as the SP1 guest and the Solidity precompile call.
    vk.verify(message, &sig).is_ok()
}

/// Stake contributed by valid, registered, sorted signers.
///
/// Returns `Ok(sig_stake)` when the signer list is strictly increasing by
/// `keccak256(pubkey)`.  Returns `Err(QuorumError::UnsortedOrDuplicate)` if
/// any two consecutive `pkHash` values satisfy `pkHash[i] <= pkHash[i-1]`,
/// regardless of whether the offending signer is registered.
///
/// This matches `GsxDagValidatorRegistry._verifyQuorum` line-by-line:
/// 1. Compute `pkHash = keccak256(pubkey)`.
/// 2. Require `pkHash > last` (byte-lexicographic; same as Solidity `bytes32 <=`
///    since Rust `[u8;32]` comparison is big-endian lexicographic).
/// 3. Look up `stake = stakeOf[pkHash]`; skip with 0 if absent.
/// 4. If registered AND ML-DSA sig valid over `digest`, add `stake` to total.
pub fn verify_quorum_stake(
    digest: &[u8; 32],
    validator_set: &[Validator],
    signers: &[SignerInput],
) -> Result<u128, QuorumError> {
    // `last` starts at the zero bytes32 — any legitimate pkHash is > 0 (in
    // practice) but the loop unconditionally checks before updating.
    let mut last = [0u8; 32];
    let mut sig_stake: u128 = 0;

    for signer in signers {
        let pk_hash = keccak256(&signer.pubkey);

        // ---- Sorting guard (unconditional, mirrors the contract's revert) ----
        // Byte-lexicographic comparison on [u8;32] == Solidity `bytes32 <=`.
        // Applied BEFORE any stake check so that an out-of-order unregistered
        // signer also triggers the error (not silently skipped).
        if pk_hash <= last {
            return Err(QuorumError::UnsortedOrDuplicate);
        }
        last = pk_hash;

        // ---- Stake lookup ----
        let stake = validator_set
            .iter()
            .find(|v| v.pk_hash == pk_hash)
            .map(|v| v.stake)
            .unwrap_or(0);

        if stake == 0 {
            // Not a registered validator this epoch — skip (no error).
            continue;
        }

        // ---- ML-DSA-65 signature verification ----
        // Invalid sig → 0 contribution, not an error (mirrors the contract).
        if mldsa_valid(&signer.pubkey, &signer.sig, digest) {
            sig_stake += stake;
        }
    }

    Ok(sig_stake)
}

/// Quorum threshold: the minimum `sig_stake` that counts as passing.
///
/// `(total_stake * 2) / 3 + 1` — integer division (floor), then +1.
/// This implements "strictly > 2/3" as the contract does.
pub fn quorum_threshold(total_stake: u128) -> u128 {
    (total_stake * 2) / 3 + 1
}

/// Returns `true` iff `sig_stake >= quorum_threshold(total_stake)`.
pub fn quorum_reached(sig_stake: u128, total_stake: u128) -> bool {
    sig_stake >= quorum_threshold(total_stake)
}

// ---------------------------------------------------------------------------
// Tests — REAL ML-DSA-65 keypairs (non-vacuous)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // ml-dsa 0.1.1 API note:
    //   - `SigningKey::<MlDsa65>::from_seed(&seed)` (the `KeyGen` trait and
    //     `MlDsa65::from_seed` from rc.8 are replaced by a direct inherent method).
    //   - `Keypair`, `Signer` are re-exported from `ml_dsa` root (not `ml_dsa::signature`).
    use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey, B32};

    // ---- Key-generation helpers -------------------------------------------

    /// Generate a real ML-DSA-65 keypair from a deterministic 32-byte seed,
    /// and return `(pubkey_bytes: Vec<u8>, sk)`.
    ///
    /// Uses `SigningKey::<MlDsa65>::from_seed` — deterministic, no RNG required,
    /// so tests are reproducible without a `getrandom` dependency.
    fn make_keypair(seed_byte: u8) -> (Vec<u8>, SigningKey<MlDsa65>) {
        let seed: B32 = [seed_byte; 32].into();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk_bytes = sk.verifying_key().encode().to_vec();
        (vk_bytes, sk)
    }

    /// Sign `digest` with `sk` (deterministic, empty context).
    /// Returns the 3309-byte encoded signature as `Vec<u8>`.
    fn sign(sk: &SigningKey<MlDsa65>, digest: &[u8; 32]) -> Vec<u8> {
        // `Signer::sign` uses the deterministic variant with empty context.
        let sig: ml_dsa::Signature<MlDsa65> = sk.sign(digest.as_slice());
        sig.encode().to_vec()
    }

    // ---- Validator-set builders -------------------------------------------

    /// Build a 4-validator set with equal stake 25 (total = 100, threshold = 67).
    ///
    /// Returns `(validators, [(pubkey, sk); 4])`.  The caller is responsible for
    /// choosing which signers to include and in which order.
    fn four_validators() -> (Vec<Validator>, Vec<(Vec<u8>, SigningKey<MlDsa65>)>) {
        let keys: Vec<_> = (1u8..=4).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(pk, _)| Validator {
                pk_hash: keccak256(pk),
                stake: 25,
            })
            .collect();
        (validators, keys)
    }

    // ---- Test 1: 3-of-4 reaches quorum ------------------------------------

    #[test]
    fn test_3_of_4_quorum_reached() {
        let digest = [0xABu8; 32];
        let (validators, keys) = four_validators();

        // Build signed inputs for all 4 validators
        let mut all_signers: Vec<SignerInput> = keys
            .iter()
            .map(|(pk, sk)| SignerInput {
                pubkey: pk.clone(),
                sig: sign(sk, &digest),
            })
            .collect();

        // Sort by keccak256(pubkey) — this is the REQUIRED order
        all_signers.sort_by_key(|s| keccak256(&s.pubkey));

        // Take only the first 3 sorted signers
        let three_signers: Vec<SignerInput> = all_signers[..3].to_vec();

        // Verify stake accumulation
        let sig_stake = verify_quorum_stake(&digest, &validators, &three_signers)
            .expect("should succeed with 3 sorted signers");
        assert_eq!(sig_stake, 75, "3 × stake-25 = 75");
        assert!(
            quorum_reached(sig_stake, 100),
            "75 >= threshold 67 — quorum met"
        );

        // Assert that feeding them in an UNSORTED order (reverse) fails
        let mut reversed = three_signers.clone();
        reversed.reverse();
        let err = verify_quorum_stake(&digest, &validators, &reversed)
            .expect_err("reversed order must error");
        assert_eq!(err, QuorumError::UnsortedOrDuplicate);
    }

    // ---- Test 2: 1-of-4 sub-quorum ----------------------------------------

    #[test]
    fn test_1_of_4_sub_quorum() {
        let digest = [0x01u8; 32];
        let (validators, keys) = four_validators();

        let signer = SignerInput {
            pubkey: keys[0].0.clone(),
            sig: sign(&keys[0].1, &digest),
        };

        let sig_stake =
            verify_quorum_stake(&digest, &validators, &[signer]).expect("single sorted signer ok");
        assert_eq!(sig_stake, 25);
        assert!(!quorum_reached(sig_stake, 100), "25 < 67 — quorum not met");
    }

    // ---- Test 3: tampered signature contributes 0 (not an error) -----------

    #[test]
    fn test_tampered_sig_contributes_zero() {
        let digest = [0x02u8; 32];
        let (validators, keys) = four_validators();

        // Build + sort 3 signers
        let mut three: Vec<SignerInput> = keys[..3]
            .iter()
            .map(|(pk, sk)| SignerInput {
                pubkey: pk.clone(),
                sig: sign(sk, &digest),
            })
            .collect();
        three.sort_by_key(|s| keccak256(&s.pubkey));

        // Flip the first byte of the second signer's signature
        three[1].sig[0] ^= 0xFF;

        // Should NOT be an error — invalid sig just contributes 0 stake
        let sig_stake = verify_quorum_stake(&digest, &validators, &three)
            .expect("tampered sig must not cause Err");
        assert_eq!(sig_stake, 50, "2 valid × 25 = 50");
        assert!(!quorum_reached(sig_stake, 100), "50 < 67 — quorum not met");
    }

    // ---- Test 4: out-of-order / duplicate signers → Err -------------------

    #[test]
    fn test_unsorted_returns_err() {
        let digest = [0x03u8; 32];
        let (validators, keys) = four_validators();

        // Build all 4 signers, sorted by pkHash
        let mut sorted: Vec<SignerInput> = keys
            .iter()
            .map(|(pk, sk)| SignerInput {
                pubkey: pk.clone(),
                sig: sign(sk, &digest),
            })
            .collect();
        sorted.sort_by_key(|s| keccak256(&s.pubkey));

        // Swap positions 1 and 2 → out of order
        sorted.swap(1, 2);
        assert_eq!(
            verify_quorum_stake(&digest, &validators, &sorted),
            Err(QuorumError::UnsortedOrDuplicate)
        );
    }

    #[test]
    fn test_duplicate_returns_err() {
        let digest = [0x04u8; 32];
        let (validators, keys) = four_validators();

        // Feed the same signer twice in a row
        let signer = SignerInput {
            pubkey: keys[0].0.clone(),
            sig: sign(&keys[0].1, &digest),
        };
        let signers = vec![signer.clone(), signer];
        assert_eq!(
            verify_quorum_stake(&digest, &validators, &signers),
            Err(QuorumError::UnsortedOrDuplicate)
        );
    }

    // ---- Test 5: unregistered signer contributes 0 (no error if sorted) ---

    #[test]
    fn test_unregistered_signer_contributes_zero() {
        let digest = [0x05u8; 32];
        let (validators, keys) = four_validators();

        // Key 5 is NOT in the validator set
        let (unregistered_pk, unregistered_sk) = make_keypair(5);

        // Build 3 registered + 1 unregistered, sorted
        let mut signers: Vec<SignerInput> = keys[..3]
            .iter()
            .map(|(pk, sk)| SignerInput {
                pubkey: pk.clone(),
                sig: sign(sk, &digest),
            })
            .chain(std::iter::once(SignerInput {
                pubkey: unregistered_pk,
                sig: sign(&unregistered_sk, &digest),
            }))
            .collect();
        signers.sort_by_key(|s| keccak256(&s.pubkey));

        let sig_stake = verify_quorum_stake(&digest, &validators, &signers)
            .expect("sorted list with unregistered signer should not err");

        // Only the 3 registered signers contribute
        assert_eq!(
            sig_stake, 75,
            "3 registered × 25 = 75 (unregistered adds 0)"
        );
        assert!(quorum_reached(sig_stake, 100));
    }

    // ---- Test 6: exact threshold boundary ---------------------------------
    //
    // Custom stakes: [1, 66, 33], total = 100, threshold = (100*2)/3+1 = 67
    //   subset {66}     → sig_stake = 66 → fails  (threshold - 1)
    //   subset {1, 66}  → sig_stake = 67 → passes (exactly threshold)

    #[test]
    fn test_exact_threshold_boundary() {
        let digest = [0x06u8; 32];

        let (pk1, sk1) = make_keypair(11);
        let (pk2, sk2) = make_keypair(12);
        let (pk3, sk3) = make_keypair(13);

        let validators = vec![
            Validator {
                pk_hash: keccak256(&pk1),
                stake: 1,
            },
            Validator {
                pk_hash: keccak256(&pk2),
                stake: 66,
            },
            Validator {
                pk_hash: keccak256(&pk3),
                stake: 33,
            },
        ];
        let total_stake: u128 = 1 + 66 + 33; // = 100
        let threshold = quorum_threshold(total_stake);
        assert_eq!(threshold, 67, "threshold = (100*2)/3+1 = 67");

        // --- Case A: only the stake-66 signer signs (sig_stake = 66, fails) ---
        let just_s2 = vec![SignerInput {
            pubkey: pk2.clone(),
            sig: sign(&sk2, &digest),
        }];
        let sig_stake_a =
            verify_quorum_stake(&digest, &validators, &just_s2).expect("single signer ok");
        assert_eq!(sig_stake_a, 66);
        assert!(
            !quorum_reached(sig_stake_a, total_stake),
            "66 < 67 — one below threshold"
        );

        // --- Case B: stake-1 + stake-66 signers sign (sig_stake = 67, passes) ---
        let mut two_signers: Vec<SignerInput> = vec![
            SignerInput {
                pubkey: pk1.clone(),
                sig: sign(&sk1, &digest),
            },
            SignerInput {
                pubkey: pk2.clone(),
                sig: sign(&sk2, &digest),
            },
        ];
        two_signers.sort_by_key(|s| keccak256(&s.pubkey));

        let sig_stake_b =
            verify_quorum_stake(&digest, &validators, &two_signers).expect("two sorted signers ok");
        assert_eq!(sig_stake_b, 67);
        assert!(
            quorum_reached(sig_stake_b, total_stake),
            "67 >= 67 — exactly at threshold"
        );

        // Ensure stake-3 signer alone (33) also sub-quorum
        let just_s3 = vec![SignerInput {
            pubkey: pk3.clone(),
            sig: sign(&sk3, &digest),
        }];
        let sig_stake_c =
            verify_quorum_stake(&digest, &validators, &just_s3).expect("single signer ok");
        assert_eq!(sig_stake_c, 33);
        assert!(!quorum_reached(sig_stake_c, total_stake));
    }

    // ---- Extra: quorum_threshold correctness for edge cases ---------------

    #[test]
    fn test_quorum_threshold_values() {
        assert_eq!(quorum_threshold(0), 1); // degenerate: 0*2/3+1 = 1
        assert_eq!(quorum_threshold(1), 1); // 0+1=1
        assert_eq!(quorum_threshold(2), 2); // 1+1=2  (no 1-of-2 quorum)
        assert_eq!(quorum_threshold(3), 3); // 2+1=3  (unanimity for 3)
        assert_eq!(quorum_threshold(100), 67); // canonical case
    }
}
