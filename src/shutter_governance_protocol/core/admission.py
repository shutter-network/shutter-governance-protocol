"""Ballot admission — the correctness kernel.

A deterministic function from the data layer's ordered ballot list + election
config + eligibility key to an **admitted set** and typed **exclusion reasons**.
This is the authoritative definition of which ballots the tally counts; each keyper
runs it to produce its aggregate submission, the auditor runs it to re-derive the
tally, and it is reproducible by anyone from public data alone.

Verification is authoritative here (at tally time), not at the gateway. Each
ballot is validated independently; then the duplicate policy is applied over the
still-valid ballots in the data layer's stable total order.

Reason precedence per ballot (first failure wins): ``MALFORMED`` (wrong-election
binding / structural) → ``OUT_OF_WINDOW`` → ``INVALID_ATTESTATION`` →
``INVALID_SIGNATURE`` / ``INVALID_PROOF``. ``DUPLICATE_PSEUDONYM`` is assigned
only among otherwise-valid ballots.
"""

from __future__ import annotations

from dataclasses import dataclass

from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, Variant
from shutter_governance_protocol.crypto.ballot import verify_ballot_crypto
from shutter_governance_protocol.crypto.points import g2_from_compressed
from shutter_governance_protocol.envelopes.types import BallotEnvelope, Exclusion, ExclusionReason, StoredBallot
from shutter_governance_protocol.ports.eligibility import verify_attestation
from shutter_governance_protocol.core.state import is_voting_open

__all__ = [
    "StoredBallot",
    "AdmittedBallot",
    "AdmissionResult",
    "validate_ballot",
    "admit",
]


@dataclass(frozen=True)
class AdmittedBallot:
    sequence_number: int
    envelope: BallotEnvelope
    weight: int


@dataclass(frozen=True)
class AdmissionResult:
    admitted: tuple[AdmittedBallot, ...]
    exclusions: tuple[Exclusion, ...]
    total_admitted_weight: int


def validate_ballot(sb: StoredBallot, config: ElectionConfig, mpk) -> ExclusionReason | None:
    """Public single-ballot validity check (no duplicate handling).

    Returns ``None`` if the ballot is independently valid, else the
    :class:`ExclusionReason`. ``mpk`` is a decoded G2 point.
    """
    env = sb.envelope
    # Stored, but not decodable into a ballot (see StoredBallot).
    if env is None:
        return ExclusionReason.MALFORMED
    att = env.attestation

    # Wrong-election binding / structural mismatch. Ballot crypto implements Variant A
    # only, so a Variant B election (refused at registration) admits nothing.
    if env.election_id != config.election_id or config.variant != Variant.A:
        return ExclusionReason.MALFORMED

    # Out-of-window (only when the adapter supplies an authoritative time).
    if sb.submitted_at is not None and not is_voting_open(config, sb.submitted_at):
        return ExclusionReason.OUT_OF_WINDOW

    # Attestation must bind this exact ballot (election, pseudonym, vk).
    if att.election_id != config.election_id or att.pseudonym != env.pseudonym or att.vk != env.vk:
        return ExclusionReason.INVALID_ATTESTATION
    if not verify_attestation(
        config.eligibility_key, att, election_id=config.election_id
    ):
        return ExclusionReason.INVALID_ATTESTATION
    # One per voter: an unweighted election counts every ballot once, whatever weight the
    # issuer signed. Excluded rather than counted at 1, so a misconfigured issuer shows up
    # in the exclusions instead of being silently corrected.
    if not config.weighted and att.weight != 1:
        return ExclusionReason.INVALID_ATTESTATION

    # Ballot crypto: range/budget proofs + Schnorr signature.
    ok, reason = verify_ballot_crypto(
        mpk=mpk,
        election_id=env.election_id,
        pseudonym=env.pseudonym,
        vk_bytes=env.vk,
        ciphertext_bytes=[(ct.c1, ct.c2) for ct in env.ciphertexts],
        zk_proof=env.zk_proof,
        voter_signature=env.voter_signature,
        attestation=att,
        num_candidates=config.num_candidates,
        budget=config.budget,
        mode=config.mode,
    )
    if not ok:
        # A pre-v2 client signed a message that excluded the credential. Surfaced as
        # its own reason rather than INVALID_SIGNATURE, which would send an operator
        # after the voter's key instead of the client version.
        if reason == "INVALID_SIGNATURE_PRE_V2":
            return ExclusionReason.INVALID_SIGNATURE
        return ExclusionReason(reason)  # "MALFORMED" | "INVALID_PROOF" | "INVALID_SIGNATURE"

    return None


def _duplicate_losers(valid: list[StoredBallot], policy: DuplicatePolicy) -> set[int]:
    """Sequence numbers excluded as duplicates, per policy.

    The winner per pseudonym is chosen by the attestation's monotonic **nonce**, not by
    raw submission order: ``LAST_WINS`` keeps the highest nonce (the voter's latest genuine
    re-vote), ``FIRST_WINS`` the lowest — with the stored ``sequence_number`` as the
    tie-break (later for last-wins, earlier for first-wins). Ordering by the issuer-signed
    nonce is what defeats replay/reordering: a replayed old ballot carries a lower nonce and
    always loses, no matter when it was submitted.
    """
    def rank(sb: StoredBallot) -> tuple[int, int]:
        return (sb.envelope.attestation.nonce, sb.sequence_number)

    winner_seq: dict[bytes, int] = {}   # pseudonym -> winning sequence number
    winner_rank: dict[bytes, tuple[int, int]] = {}
    for sb in valid:  # already in stable total order
        pseud = sb.envelope.pseudonym
        r = rank(sb)
        cur = winner_rank.get(pseud)
        if cur is None or (r > cur if policy is DuplicatePolicy.LAST_WINS else r < cur):
            winner_rank[pseud] = r
            winner_seq[pseud] = sb.sequence_number

    winners = set(winner_seq.values())
    return {sb.sequence_number for sb in valid if sb.sequence_number not in winners}


def admit(ballots: list[StoredBallot], config: ElectionConfig, mpk_bytes: bytes) -> AdmissionResult:
    """Compute the admitted set and typed exclusions.

    ``ballots`` must be in the data layer's stable total order. ``mpk_bytes`` is
    the finalized election key (``FinalizedKey.pk_election``).
    """
    mpk = g2_from_compressed(mpk_bytes)

    exclusions: list[Exclusion] = []
    valid: list[StoredBallot] = []
    for sb in ballots:
        reason = validate_ballot(sb, config, mpk)
        if reason is None:
            valid.append(sb)
        else:
            exclusions.append(Exclusion(sequence_number=sb.sequence_number, reason=reason))

    losers = _duplicate_losers(valid, config.duplicate_policy)

    admitted: list[AdmittedBallot] = []
    for sb in valid:
        if sb.sequence_number in losers:
            exclusions.append(
                Exclusion(sequence_number=sb.sequence_number, reason=ExclusionReason.DUPLICATE_PSEUDONYM)
            )
        else:
            admitted.append(
                AdmittedBallot(
                    sequence_number=sb.sequence_number,
                    envelope=sb.envelope,
                    weight=sb.envelope.attestation.weight,
                )
            )

    exclusions.sort(key=lambda x: x.sequence_number)
    total_weight = sum(a.weight for a in admitted)
    return AdmissionResult(
        admitted=tuple(admitted),
        exclusions=tuple(exclusions),
        total_admitted_weight=total_weight,
    )
