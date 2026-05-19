"""DKG session state machine (Spec C3b §5)."""

from __future__ import annotations

from typing import Optional

from src.ltp.zk.ec_backend import (
    g1_add,
    g1_deserialize,
    g1_eq,
    g1_generator,
    g1_identity,
    g1_scalar_mul,
    g1_serialize,
)

from .scalar_poly import ScalarField, ScalarPoly
from .threshold_signing import ThresholdSigningKey
from .types import (
    DKGCommitment,
    DKGComplaint,
    DKGPhase,
    DKGResult,
    DKGSessionConfig,
    DKGShare,
    DKGState,
)
from .vss import PedersenVSS

__all__ = ["DKGSession"]


class DKGSession:
    """Mutable state machine for a single DKG ceremony."""

    def __init__(
        self,
        config: DKGSessionConfig,
        my_fp: bytes,
        my_index: int,
    ) -> None:
        self.config = config
        self.state = DKGState.IDLE
        self.my_fp = my_fp
        self.my_index = my_index

        self._secret_poly: Optional[ScalarPoly] = None
        self._blinding_poly: Optional[ScalarPoly] = None

        self._commitments: dict[bytes, DKGCommitment] = {}
        self._shares: dict[bytes, DKGShare] = {}
        self._complaints: list[DKGComplaint] = []
        self._qual: set[bytes] = set()

    def begin(self) -> tuple[DKGCommitment, dict[bytes, DKGShare]]:
        """IDLE -> COMMITTING. Generate polynomials and return outputs."""
        if self.state is not DKGState.IDLE:
            raise ValueError(f"cannot begin: state is not IDLE (is {self.state.value})")

        degree = self.config.threshold - 1
        self._secret_poly = ScalarPoly.random(degree)
        self._blinding_poly = ScalarPoly.random(degree)

        feldman, pedersen = PedersenVSS.generate_commitments(
            self._secret_poly,
            self._blinding_poly,
        )
        commitment = DKGCommitment(
            dealer_fp=self.my_fp,
            feldman_commitments=feldman,
            pedersen_commitments=pedersen,
            round_id=self.config.start_round,
        )
        self._commitments[self.my_fp] = commitment

        # Create shares for each other participant
        shares: dict[bytes, DKGShare] = {}
        for idx, fp in enumerate(self.config.participants, start=1):
            if fp == self.my_fp:
                continue
            s, b = PedersenVSS.create_share(
                self._secret_poly,
                self._blinding_poly,
                idx,
            )
            shares[fp] = DKGShare(
                dealer_fp=self.my_fp,
                recipient_fp=fp,
                share=s,
                blinding_share=b,
            )

        self.state = DKGState.COMMITTING
        return commitment, shares

    def receive_commitment(self, commitment: DKGCommitment) -> None:
        """Collect a commitment from another dealer."""
        self._commitments[commitment.dealer_fp] = commitment

    def end_commitment_phase(self) -> None:
        """COMMITTING -> SHARING."""
        self.state = DKGState.SHARING

    def receive_share(self, share: DKGShare) -> None:
        """Collect a share from a dealer."""
        self._shares[share.dealer_fp] = share

    def end_sharing_phase(self) -> list[DKGComplaint]:
        """SHARING -> VERIFYING -> COMPLAINING. Verify shares, return complaints."""
        self.state = DKGState.VERIFYING
        complaints: list[DKGComplaint] = []

        for dealer_fp, share in self._shares.items():
            commitment = self._commitments.get(dealer_fp)
            if commitment is None:
                continue
            valid = PedersenVSS.verify_share(
                self.my_index,
                share.share,
                share.blinding_share,
                commitment.pedersen_commitments,
            )
            if not valid:
                complaints.append(
                    DKGComplaint(
                        complainant_fp=self.my_fp,
                        dealer_fp=dealer_fp,
                        revealed_share=share.share,
                        revealed_blinding=share.blinding_share,
                        round_id=self.config.start_round,
                    )
                )

        self._complaints = complaints
        self.state = DKGState.COMPLAINING
        return complaints

    def receive_complaint(self, complaint: DKGComplaint) -> None:
        """Collect a complaint during the COMPLAINING phase."""
        self._complaints.append(complaint)

    def finalize(self) -> tuple[DKGResult, ThresholdSigningKey]:
        """COMPLAINING -> FINALIZING -> COMPLETED. Resolve complaints and derive keys."""
        self.state = DKGState.FINALIZING

        # Build QUAL: start with all dealers, remove those with valid complaints
        self._qual = set(self._commitments.keys())
        for complaint in self._complaints:
            commitment = self._commitments.get(complaint.dealer_fp)
            if commitment is None:
                continue
            complainant_idx = self.config.participants.index(complaint.complainant_fp) + 1
            valid = PedersenVSS.verify_share(
                complainant_idx,
                complaint.revealed_share,
                complaint.revealed_blinding,
                commitment.pedersen_commitments,
            )
            if not valid:
                # Complaint is valid — dealer sent a bad share, exclude dealer
                self._qual.discard(complaint.dealer_fp)

        if len(self._qual) < self.config.threshold:
            self.state = DKGState.FAILED
            raise ValueError(
                f"QUAL set too small: {len(self._qual)} < threshold {self.config.threshold}"
            )

        # Derive group public key: sum of feldman_commitments[0] for QUAL dealers
        group_point = g1_identity()
        for fp in self._qual:
            c0_bytes = self._commitments[fp].feldman_commitments[0]
            c0 = g1_deserialize(c0_bytes)
            group_point = g1_add(group_point, c0) if group_point is not None else c0

        # Derive my secret share: sum of received shares from QUAL dealers
        my_secret_share = 0
        for fp in self._qual:
            if fp == self.my_fp:
                my_secret_share = ScalarField.add(
                    my_secret_share,
                    self._secret_poly.evaluate(self.my_index),
                )
            else:
                share = self._shares.get(fp)
                if share is not None:
                    my_secret_share = ScalarField.add(my_secret_share, share.share)

        my_vk = g1_serialize(g1_scalar_mul(g1_generator(), my_secret_share))
        participant_vks = {self.my_fp: my_vk}
        group_pk_bytes = g1_serialize(group_point)

        self.state = DKGState.COMPLETED

        result = DKGResult(
            vm_tag=self.config.vm_tag,
            epoch=self.config.epoch,
            group_pk=group_pk_bytes,
            participant_vks=participant_vks,
            threshold=self.config.threshold,
            qual_set=frozenset(self._qual),
            phase=DKGPhase.EAGER,
            my_secret_share=my_secret_share,
        )

        signing_key = ThresholdSigningKey(
            participant_fp=self.my_fp,
            participant_index=self.my_index,
            secret_share=my_secret_share,
            group_pk=group_pk_bytes,
            threshold=self.config.threshold,
            epoch=self.config.epoch,
            vm_tag=self.config.vm_tag,
        )

        return result, signing_key

    def abort(self, reason: str) -> None:
        """Any state -> FAILED."""
        self.state = DKGState.FAILED

    def check_timeout(self, current_round: int) -> bool:
        """Returns True and fails if timeout exceeded."""
        if current_round >= self.config.start_round + self.config.timeout_rounds:
            self.state = DKGState.FAILED
            return True
        return False
