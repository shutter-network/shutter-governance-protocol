"""Conversions between shutter_governance_protocol envelopes and the on-chain contract structs.

Enum-like fields are ``uint8`` on chain; the attestation (with weight) is packed
verbatim into the ballot's ``wrAttestation`` bytes (the contract does not
interpret it). ``election_id`` is a ``bytes32`` off chain and the ``uint256``
contract ``electionId`` on chain.
"""

from __future__ import annotations

import json

from eth_utils import keccak

from shutter_governance_protocol.core.config import DuplicatePolicy, Mode, Variant
from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
    Exclusion,
    ExclusionReason,
    StoredBallot,
)

MODE_TO_U8 = {Mode.EXACT: 0, Mode.AT_MOST: 1}
U8_TO_MODE = {v: k for k, v in MODE_TO_U8.items()}
VARIANT_TO_U8 = {Variant.A: 0, Variant.B: 1}
U8_TO_VARIANT = {v: k for k, v in VARIANT_TO_U8.items()}
DUP_TO_U8 = {DuplicatePolicy.FIRST_WINS: 0, DuplicatePolicy.LAST_WINS: 1}
U8_TO_DUP = {v: k for k, v in DUP_TO_U8.items()}
REASON_TO_U8 = {
    ExclusionReason.INVALID_PROOF: 0,
    ExclusionReason.INVALID_SIGNATURE: 1,
    ExclusionReason.INVALID_ATTESTATION: 2,
    ExclusionReason.DUPLICATE_PSEUDONYM: 3,
    ExclusionReason.MALFORMED: 4,
    ExclusionReason.OUT_OF_WINDOW: 5,
}
U8_TO_REASON = {v: k for k, v in REASON_TO_U8.items()}


def eid_to_uint(election_id: bytes) -> int:
    return int.from_bytes(election_id, "big")


def uint_to_eid(value: int) -> bytes:
    return int(value).to_bytes(32, "big")


# --- attestation packing (into wrAttestation bytes) ------------------------ #

def pack_attestation(att) -> bytes:
    """Pack the credential — and the voter's binding — into ``wrAttestation``.

    The contract treats these bytes as opaque and never interprets them, so the
    binding signature rides here rather than in a new ``Ballot`` field. That keeps
    ``VotingTypes.sol`` untouched by a change that is purely off-chain semantics.

    ``voterBinding`` is a sibling key, not a member of the credential: the
    attestation is the eligibility service's artifact and the binding is the
    voter's. Folding one into the other would make `enc_attestation` lie about who
    signed what.
    """
    body = codecs.enc_attestation(att)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def unpack_attestation(raw: bytes):
    """The credential from ``wrAttestation``; the binding is read separately."""
    return codecs.dec_attestation(json.loads(bytes(raw).decode("utf-8")))


def ballot_to_tuple(env: BallotEnvelope):
    """Contract ``Ballot``: (pseudonym, vk, ciphertexts[(c1,c2)], zkProof, voterSignature, wrAttestation)."""
    cts = [(ct.c1, ct.c2) for ct in env.ciphertexts]
    return (env.pseudonym, env.vk, cts, env.zk_proof, env.voter_signature,
            pack_attestation(env.attestation))


def ballot_record_from_contract(raw, election_id: bytes, sequence_number: int,
                                zk_proof: bytes | None) -> StoredBallot:
    """Contract ``BallotRecord``: (ballot, submittedAt, submittedBy) -> StoredBallot.

    ``submittedAt`` is the block timestamp the contract stamped at accept time — the
    one adversarially authoritative receive time in the system, since the chain is the
    only backend whose clock the data-layer operator does not control.

    Storage holds only ``keccak256(zkProof)``; ``zk_proof`` is the proof from this
    ballot's ``VoteSubmitted`` log (``None`` if none was found). It is used only if it
    matches the stored commitment.
    """
    ballot, submitted_at = raw[0], raw[1]
    # A record that cannot be turned into a ballot is returned as malformed rather than
    # failing the read; see StoredBallot. That covers bytes in ``wrAttestation`` that are
    # not a credential (the contract stores any non-empty bytes there) and a proof that
    # is missing from the logs or does not match its commitment.
    try:
        if zk_proof is None:
            raise ValueError("proof missing from the VoteSubmitted log")
        if keccak(zk_proof) != bytes(ballot[3]):
            raise ValueError("proof does not match its on-chain commitment")
        envelope, reason = ballot_from_contract(ballot, election_id, zk_proof), None
    except codecs.BALLOT_DECODE_ERRORS as exc:
        envelope, reason = None, f"{type(exc).__name__}: {exc}"
    return StoredBallot(
        sequence_number=sequence_number,
        envelope=envelope,
        submitted_at=int(submitted_at),
        malformed_reason=reason,
    )


def ballot_from_contract(raw, election_id: bytes, zk_proof: bytes) -> BallotEnvelope:
    """Contract ``BallotView`` plus the proof from its log (``raw[3]`` is only its hash)."""
    pseudonym, vk, cts, voter_sig, wr = raw[0], raw[1], raw[2], raw[4], raw[5]
    return BallotEnvelope(
        election_id=election_id,
        pseudonym=bytes(pseudonym),
        vk=bytes(vk),
        ciphertexts=tuple(Ciphertext(c1=bytes(c[0]), c2=bytes(c[1])) for c in cts),
        zk_proof=bytes(zk_proof),
        voter_signature=bytes(voter_sig),
        attestation=unpack_attestation(wr),
    )


# --- aggregate ------------------------------------------------------------- #

def aggregate_to_tuple(agg: AggregateArtifact):
    """Contract ``EncryptedTally``: (aggregates[(c1,c2)], admitted[], exclusions[(seq,reason)], totalAdmittedWeight, totalScaledWeight)."""
    aggregates = [(ct.c1, ct.c2) for ct in agg.aggregates]
    admitted = [int(s) for s in agg.admitted]
    exclusions = [(int(x.sequence_number), REASON_TO_U8[x.reason]) for x in agg.exclusions]
    return (
        aggregates,
        admitted,
        exclusions,
        int(agg.total_admitted_weight),
        int(agg.total_scaled_weight),
    )


def aggregate_from_contract(raw, election_id: bytes) -> AggregateArtifact:
    aggregates, admitted, exclusions, total_weight = raw[0], raw[1], raw[2], raw[3]
    # A pre-scale contract returns four fields; those elections were unscaled, so the
    # scaled total equals the raw one. Tolerated on read rather than rejected, since a
    # deployment mid-rollout may still hold such rows.
    scaled_weight_total = int(raw[4]) if len(raw) > 4 else int(total_weight)
    return AggregateArtifact(
        election_id=election_id,
        aggregates=tuple(Ciphertext(c1=bytes(c[0]), c2=bytes(c[1])) for c in aggregates),
        admitted=tuple(int(s) for s in admitted),
        exclusions=tuple(Exclusion(sequence_number=int(x[0]), reason=U8_TO_REASON[int(x[1])]) for x in exclusions),
        total_admitted_weight=int(total_weight),
        total_scaled_weight=scaled_weight_total,
    )


# --- decryption share ------------------------------------------------------ #

def share_to_contract(share: DecryptionShareEnvelope):
    """Return (shares[bytes], proofs[(e,z)]) for ``submitDecryptionShare``."""
    shares = [entry.sigma for entry in share.entries]
    proofs = [
        (int.from_bytes(entry.proof[:32], "big"), int.from_bytes(entry.proof[32:], "big"))
        for entry in share.entries
    ]
    return shares, proofs


def share_from_contract(raw, election_id: bytes) -> DecryptionShareEnvelope:
    """Contract ``DecryptionShare``: (keyperIndex u8 [0-based], submittedAt, shares[], proofs[(e,z)])."""
    keyper_index_0based, _submitted_at, shares, proofs = raw[0], raw[1], raw[2], raw[3]
    entries = []
    for sigma, proof in zip(shares, proofs):
        e_val, z_val = int(proof[0]), int(proof[1])
        entries.append(
            DecryptionShareEntry(sigma=bytes(sigma), proof=e_val.to_bytes(32, "big") + z_val.to_bytes(32, "big"))
        )
    return DecryptionShareEnvelope(
        election_id=election_id, keyper_index=int(keyper_index_0based) + 1, entries=tuple(entries)
    )
