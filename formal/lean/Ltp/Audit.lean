import Ltp.Counting
import Ltp.Quorum
import Ltp.Commitment
import Ltp.LatticeKey
import Ltp.Bandwidth
import Ltp.Erasure
import Ltp.Policy
import Ltp.Governance
import Ltp.TestVectors
import Ltp.Ramp
import Ltp.ConcreteSecurity

/-
Axiom audit.

A Lean file that compiles proves nothing on its own — `sorry` also
compiles (with a warning that is easy to lose in CI output). This module
prints the axiom dependencies of every headline theorem. The expected
output for each is at most Lean's three standard axioms:

    [propext, Classical.choice, Quot.sound]

If `sorryAx` ever appears in this list, a proof has a hole. `verify.sh`
greps for exactly that and fails the build.
-/

open Suwappu.Counting
open Suwappu.LTP
open Suwappu.LTP.Commitment

-- Counting foundations
#print axioms Suwappu.Counting.countP_add_le_inter_add_length
#print axioms Suwappu.Counting.countP_mono
#print axioms Suwappu.Counting.exists_of_countP_pos
#print axioms Suwappu.Counting.countP_le_length
#print axioms Suwappu.Counting.countP_split
#print axioms Suwappu.Counting.countP_add_countP_not

-- Corridor quorum
#print axioms Suwappu.LTP.quorum_intersection_general
#print axioms Suwappu.LTP.corridor_intersection
#print axioms Suwappu.LTP.corridor_safety
#print axioms Suwappu.LTP.corridor_liveness
#print axioms Suwappu.LTP.threshold_is_majority

-- Commitment size
#print axioms Suwappu.LTP.Commitment.commitment_size_payload_independent
#print axioms Suwappu.LTP.Commitment.commitment_size_eq_const
#print axioms Suwappu.LTP.Commitment.no_per_payload_bytes
#print axioms Suwappu.LTP.Commitment.total_768
#print axioms Suwappu.LTP.Commitment.total_1024
#print axioms Suwappu.LTP.Commitment.strict_total_unsatisfiable
#print axioms Suwappu.LTP.Commitment.provenance_of_1600
#print axioms Suwappu.LTP.Commitment.gap_is_one_signature

-- Sealed lattice key size (Paper §2.2, §3.3.7)
#print axioms Suwappu.LTP.LatticeKey.lattice_key_size_payload_independent
#print axioms Suwappu.LTP.LatticeKey.lattice_key_size_eq_const
#print axioms Suwappu.LTP.LatticeKey.sealed_768_min
#print axioms Suwappu.LTP.LatticeKey.sealed_768_max
#print axioms Suwappu.LTP.LatticeKey.sealed_768_bounded
#print axioms Suwappu.LTP.LatticeKey.inner_payload_bounds
#print axioms Suwappu.LTP.LatticeKey.record_exceeds_1kb

-- Bandwidth cost model (Paper §6.4, Appendix A)
#print axioms Suwappu.LTP.Bandwidth.rho_default
#print axioms Suwappu.LTP.Bandwidth.rho_default_exact
#print axioms Suwappu.LTP.Bandwidth.rho_default_ne_r
#print axioms Suwappu.LTP.Bandwidth.commit_overhead_constant
#print axioms Suwappu.LTP.Bandwidth.single_receiver_costs_more
#print axioms Suwappu.LTP.Bandwidth.breakeven_iff
#print axioms Suwappu.LTP.Bandwidth.amortisation_monotone

-- Erasure reconstruction threshold (Paper §2.1.1, §4.3)
#print axioms Suwappu.LTP.Erasure.reconstructable_iff
#print axioms Suwappu.LTP.Erasure.no_index_privileged
#print axioms Suwappu.LTP.Erasure.at_threshold_decodable
#print axioms Suwappu.LTP.Erasure.below_threshold_undecodable
#print axioms Suwappu.LTP.Erasure.decodable_monotone
#print axioms Suwappu.LTP.Erasure.loss_budget

-- Access-policy algebra (Paper §2.2.1, §8.4)
#print axioms Suwappu.LTP.Policy.countOk_antitone
#print axioms Suwappu.LTP.Policy.permits_antitone_count
#print axioms Suwappu.LTP.Policy.one_time_exhausts
#print axioms Suwappu.LTP.Policy.minimal_is_sound
#print axioms Suwappu.LTP.Policy.attenuate_no_amplify

-- Governance supermajority (Paper §5.1)
#print axioms Suwappu.LTP.Governance.supermajority_safety
#print axioms Suwappu.LTP.Governance.supermajority_liveness
#print axioms Suwappu.LTP.Governance.safety_bound_tight

-- §2.1.1 interoperability test vectors, recomputed in-kernel over GF(2⁸)
#print axioms Suwappu.LTP.TestVectors.gf_sanity
#print axioms Suwappu.LTP.TestVectors.vector1_matches
#print axioms Suwappu.LTP.TestVectors.vector1_non_systematic
#print axioms Suwappu.LTP.TestVectors.vector2_framing
#print axioms Suwappu.LTP.TestVectors.vector2_matches

-- Ramp-scheme entropy bookkeeping (Paper §3.3.5, v0.2.3)
#print axioms Suwappu.LTP.Ramp.leak_plus_residual
#print axioms Suwappu.LTP.Ramp.leak_per_shard
#print axioms Suwappu.LTP.Ramp.leak_monotone
#print axioms Suwappu.LTP.Ramp.residual_zero_iff
#print axioms Suwappu.LTP.Ramp.one_short_residual
#print axioms Suwappu.LTP.Ramp.candidates_step
#print axioms Suwappu.LTP.Ramp.candidates_at_threshold
#print axioms Suwappu.LTP.Ramp.candidates_one_short
#print axioms Suwappu.LTP.Ramp.candidates_eq_two_pow_residual
#print axioms Suwappu.LTP.Ramp.worked_example_pairs
#print axioms Suwappu.LTP.Ramp.worked_example_one_shard
#print axioms Suwappu.LTP.Ramp.no_blinding
#print axioms Suwappu.LTP.Ramp.shamir_extreme
#print axioms Suwappu.LTP.Ramp.share_cost_exact
#print axioms Suwappu.LTP.Ramp.blinding_costs_more

-- Ramp-scheme field-size generality (Paper §3.3.5, v0.2.5)
#print axioms Suwappu.LTP.Ramp.gf256_specialization
#print axioms Suwappu.LTP.Ramp.candidatesQ_pos
#print axioms Suwappu.LTP.Ramp.candidatesQ_step
#print axioms Suwappu.LTP.Ramp.candidatesQ_at_threshold
#print axioms Suwappu.LTP.Ramp.candidatesQ_step_strict
#print axioms Suwappu.LTP.Ramp.candidatesQ_strict_antitone

-- Concrete-security arithmetic (Paper §3.3.1, §2.1.1, §2.3.3, Appendix A; v0.2.6)
#print axioms Suwappu.LTP.ConcreteSecurity.bht_exponent
#print axioms Suwappu.LTP.ConcreteSecurity.bht_bracket
#print axioms Suwappu.LTP.ConcreteSecurity.birthday_exponent
#print axioms Suwappu.LTP.ConcreteSecurity.collision_below_preimage
#print axioms Suwappu.LTP.ConcreteSecurity.grover_square
#print axioms Suwappu.LTP.ConcreteSecurity.nonce_birthday_margin
#print axioms Suwappu.LTP.ConcreteSecurity.backoff_doubles
#print axioms Suwappu.LTP.ConcreteSecurity.mars_commit_upload_seconds
#print axioms Suwappu.LTP.ConcreteSecurity.mars_commit_upload_hours
