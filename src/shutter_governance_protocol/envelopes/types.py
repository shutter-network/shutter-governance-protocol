"""Artifact envelope dataclasses.

In-memory representations of the five transport artifacts plus the
``ATTESTATION_V1`` credential. These are pure data holders; JSON
encoding/decoding and byte-length validation live in
:mod:`shutter_governance_protocol.envelopes.codecs`.

Byte fields are held as raw ``bytes`` here and only become ``0x``-hex at the JSON
boundary. Fixed byte sizes (from the SDK v1 codecs) are defined
in :mod:`shutter_governance_protocol.crypto.params` and enforced by the codecs so malformed
input is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Fixed byte sizes of the crypto suite, enforced on decode. Defined once, in
# crypto/params.py, and re-exported here for the codecs.
from shutter_governance_protocol.crypto.params import DLEQ_BYTES, G1_BYTES, G2_BYTES, SCHNORR_BYTES  # noqa: E402,F401

BYTES32 = 32  # election_id, pseudonym


class ExclusionReason(str, Enum):
    """Typed reasons a stored ballot was excluded from the aggregate."""

    INVALID_PROOF = "INVALID_PROOF"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_ATTESTATION = "INVALID_ATTESTATION"
    DUPLICATE_PSEUDONYM = "DUPLICATE_PSEUDONYM"
    MALFORMED = "MALFORMED"
    OUT_OF_WINDOW = "OUT_OF_WINDOW"


class AttestationScheme(str, Enum):
    """Which eligibility-credential scheme an attestation uses.

    Only ``V1`` -- the weighted, domain-separated ``ATTESTATION_V1``. The weightless
    Wahlregister scheme (``keccak(electionId‖pseudonym‖vk)``, no domain separator,
    valid only at weight 1) was dropped when the credential moved inside the signed
    ballot: with one scheme there is nothing for a scheme code to disambiguate, so it
    left the signed message too. Deployments needing it stay on SDK 0.1.2.

    Kept as an enum rather than collapsed away so the wire format still carries an
    explicit ``scheme`` and a future scheme has somewhere to go.
    """

    V1 = "ATTESTATION_V1"


@dataclass(frozen=True)
class Ciphertext:
    """Exponential-ElGamal ciphertext in G2: ``(C1, C2)``."""

    c1: bytes  # G2, 96 bytes
    c2: bytes  # G2, 96 bytes


@dataclass(frozen=True)
class Attestation:
    """``ATTESTATION_V1`` eligibility credential.

    A Schnorr-on-G1 signature by ``eligibility_key`` over a domain-separated
    transcript of ``(election_id, pseudonym, vk, weight, nonce)``. Extends the prior
    Wahlregister attestation (which covered the tuple without ``weight``/``nonce``)
    and is a distinct codec, not a silent modification. ``weight`` travels inside the
    credential so the whole tally is re-derivable from public artifacts; ``nonce`` is
    a monotonic per-(election, pseudonym) re-vote counter (issued 1, 2, 3, … by the
    eligibility service) that the tally uses to pick the voter's latest ballot, so a
    replayed old ballot (lower nonce) can never override a genuine re-vote. The
    """

    election_id: bytes  # bytes32
    pseudonym: bytes  # bytes32
    vk: bytes  # G1, 48 bytes — voter ephemeral Schnorr verification key
    weight: int  # >= 1, uncapped
    signature: bytes  # Schnorr, 80 bytes, by eligibility_key over the tuple
    scheme: AttestationScheme = AttestationScheme.V1
    nonce: int = 1  # monotonic re-vote counter per (election, pseudonym); V1 only, >= 1


@dataclass(frozen=True)
class BallotEnvelope:
    """Ballot artifact.

    Generalises the on-chain ballot (``eth_client.py::_decode_ballot``) by adding
    an explicit ``election_id`` and carrying the eligibility credential as
    ``attestation`` (``ATTESTATION_V1``, which carries ``weight``) rather than the
    weightless ``wrAttestation``.
    """

    election_id: bytes  # bytes32
    pseudonym: bytes  # bytes32
    vk: bytes  # G1, 48 bytes
    ciphertexts: tuple[Ciphertext, ...]  # one per candidate
    zk_proof: bytes  # versioned BallotValidityProof encoding (variable length)
    # Schnorr, 80 bytes, over the canonical ballot message -- which since v2 covers
    # the attestation too, so this one signature binds the ballot *and* the credential
    # it was cast with. There used to be a second signature here for that job.
    voter_signature: bytes
    attestation: Attestation


@dataclass(frozen=True)
class StoredBallot:
    """A ballot as the data layer stores it: an envelope plus its storage metadata.

    This is what :meth:`~shutter_governance_protocol.ports.data_layer.ElectionDataLayer.list_ballots`
    returns, so the tally-time admission check can see the adapter's own view of
    *when* a ballot arrived rather than having to trust that some ingress enforced
    the window.

    ``submitted_at`` is the adapter's authoritative receive time: chain block time, or
    the NTP-disciplined service clock on memory/DB. **Every stored ballot has one** —
    all three adapters stamp it at write, and the DB column is ``NOT NULL``.

    It is ``None`` only for ballots that were never stored: the gateway's pre-write
    validity check, test fixtures, and the conformance-vector flow fixture all build
    :class:`StoredBallot` in memory. Admission skips the ``OUT_OF_WINDOW`` check in that
    case, because there is no receive time to check rather than because one was lost.

    Note the trust boundary: on memory/DB the timestamp is supplied by the data
    layer, which is untrusted for integrity, so this check catches rows written
    out-of-band (direct SQL, a second writer, a restored backup) and makes the
    window publicly auditable — it does **not** defeat an operator who backdates.
    Only the chain's block time is adversarially authoritative.

    ``envelope`` is ``None`` when the stored bytes cannot be decoded into a ballot, and
    ``malformed_reason`` says why. This happens on the chain, whose contract stores the
    credential as opaque bytes, so anyone can append one that is not a credential. The
    record keeps its place in the order and admission excludes it as ``MALFORMED``.
    Raising instead would make every read of the list fail, halting the tally and the
    ingest filter for the rest of the election.
    """

    sequence_number: int
    envelope: BallotEnvelope | None
    submitted_at: int | None = None
    malformed_reason: str | None = None


@dataclass(frozen=True)
class DKGResultSubmission:
    """A keyper's signed DKG result vote.

    The finalized key exists iff >= t+1 registered keypers submit byte-identical
    ``(pk_election, committee_pks)`` — the finalization quorum rule. This envelope is one such submission.
    """

    election_id: bytes  # bytes32
    pk_election: bytes  # G2, 96 bytes — joint election public key
    committee_pks: tuple[bytes, ...]  # each G2, 96 bytes — per-keyper public shares
    keyper_signature: bytes  # signature by the submitting keyper's registered key
    submitter: bytes | None = None


@dataclass(frozen=True)
class DecryptionShareEntry:
    """One candidate's partial decryption: ``sigma`` plus its DLEQ proof."""

    sigma: bytes  # G2, 96 bytes — sigma_k = msk_k * C1
    proof: bytes  # DLEQ, 64 bytes (e || z)


@dataclass(frozen=True)
class DecryptionShareEnvelope:
    """A keyper's per-candidate decryption shares."""

    election_id: bytes  # bytes32
    keyper_index: int
    entries: tuple[DecryptionShareEntry, ...]  # one per candidate


@dataclass(frozen=True)
class Exclusion:
    """A ballot excluded from the aggregate, with a typed reason."""

    sequence_number: int
    reason: ExclusionReason


@dataclass(frozen=True)
class AggregateArtifact:
    """Aggregate artifact with its admitted set.

    Publishing the admitted set (plus per-exclusion reason codes and the total
    admitted weight) makes the committee's admission decisions public and
    re-checkable — each keyper re-derives it deterministically, and it becomes
    canonical only at the t+1 byte-identical quorum.
    """

    election_id: bytes  # bytes32
    aggregates: tuple[Ciphertext, ...]  # per-candidate homomorphic sum
    admitted: tuple[int, ...]  # sequence numbers included in the aggregate
    exclusions: tuple[Exclusion, ...]  # (sequence_number, reason) per excluded ballot
    total_admitted_weight: int  # Σ attested weights, as issued — turnout, in token units
    # Σ of the *scaled* weights the aggregate was actually built from, i.e.
    # `Σ (w_i + scale//2) // scale`. Equal to `total_admitted_weight` when `scale` is
    # 1, which is the common case.
    #
    # Carried rather than derived because it is not recoverable from the raw total:
    # per-voter rounding does not commute with summing, so `Σ round(w_i/s)` does not
    # follow from `(Σ w_i, s)`. It is what `bsgs_bound` is computed from, so a
    # verifier that assumed the raw total would search the wrong range.
    total_scaled_weight: int = 0


@dataclass(frozen=True)
class ResultArtifact:
    """Final result artifact."""

    election_id: bytes  # bytes32
    totals: tuple[int, ...]  # per-candidate plaintext totals
    keyper_indices: tuple[int, ...]  # the t+1 keyper indices whose shares were used
    bsgs_bound: int  # derived bound = budget * sum(*scaled* admitted weights)
