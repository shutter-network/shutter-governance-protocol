"""``ATTESTATION_V1`` — the weighted eligibility credential.

A Schnorr-on-G1 signature by ``eligibility_key`` over a **domain-separated
transcript** of ``(election_id, pseudonym, vk, weight, nonce)``. This extends the
prior Wahlregister attestation (which covered ``(election_id, pseudonym, vk)`` as a
bare keccak concatenation with no domain separator, weight, or nonce) and is a
**distinct codec**, not a silent modification:

* the transcript is seeded with the label ``SHUTTER-VOTE-ATTEST-v1`` and every
  field is length-prefixed (the Merlin discipline), so nothing is ambiguous;
* ``weight`` is bound as a scalar, so the credential is inseparable from the
  weight it authorizes — the whole tally stays re-derivable from public artifacts;
* ``nonce`` is bound as a scalar — a monotonic per-(election, pseudonym) re-vote
  counter issued by the eligibility service. The tally picks the voter's ballot
  with the highest signed nonce, so a replayed old ballot (lower nonce) can never
  override a genuine re-vote.

The 80-byte wire form is the standard Schnorr encoding (``R ‖ s``). The signed
message is ``keccak256(transcript.preimage())``.
"""

from __future__ import annotations

from eth_utils import keccak

from shutter_governance_protocol.crypto import schnorr
from shutter_governance_protocol.crypto.params import ATTESTATION_LABEL, CURVE_ORDER
from shutter_governance_protocol.crypto.points import g1_from_compressed
from shutter_governance_protocol.crypto.transcript import Transcript


def _attestation_transcript(election_id: bytes, pseudonym: bytes, vk_bytes: bytes,
                            weight: int, nonce: int) -> Transcript:
    if len(election_id) != 32:
        raise ValueError(f"electionId must be 32 bytes (got {len(election_id)})")
    if len(pseudonym) != 32:
        raise ValueError(f"pseudonym must be 32 bytes (got {len(pseudonym)})")
    if len(vk_bytes) != 48:
        raise ValueError(f"vk must be 48 bytes (got {len(vk_bytes)})")
    if weight < 1:
        raise ValueError(f"weight must be >= 1 (got {weight})")
    if nonce < 1:
        raise ValueError(f"nonce must be >= 1 (got {nonce})")
    # Both are signed as scalars but counted as plain integers, so each must have
    # exactly one encoding: ``weight + CURVE_ORDER`` would otherwise carry the same
    # signature as ``weight`` while inflating the tally bound.
    if weight >= CURVE_ORDER:
        raise ValueError("weight must be < CURVE_ORDER")
    if nonce >= CURVE_ORDER:
        raise ValueError("nonce must be < CURVE_ORDER")
    t = Transcript(ATTESTATION_LABEL)
    t.append("attest:electionId", election_id)
    t.append("attest:pseudonym", pseudonym)
    t.append("attest:vk", vk_bytes)
    t.append_scalar("attest:weight", weight)
    t.append_scalar("attest:nonce", nonce)
    return t


def attestation_message(election_id: bytes, pseudonym: bytes, vk_bytes: bytes,
                        weight: int, nonce: int) -> bytes:
    """The keccak256 digest the eligibility key signs for ``ATTESTATION_V1``."""
    return keccak(_attestation_transcript(election_id, pseudonym, vk_bytes, weight, nonce).preimage())


def sign_attestation(elig_sk: int, elig_vk, election_id: bytes, pseudonym: bytes,
                     vk_bytes: bytes, weight: int, nonce: int, *, k: int | None = None) -> bytes:
    """Issue an ``ATTESTATION_V1`` signature (80-byte ``R ‖ s``)."""
    msg = attestation_message(election_id, pseudonym, vk_bytes, weight, nonce)
    R, s = schnorr.sign(elig_sk, elig_vk, msg, k=k)
    return schnorr.encode(R, s)


def verify_attestation_sig(elig_vk_bytes: bytes, election_id: bytes, pseudonym: bytes,
                           vk_bytes: bytes, weight: int, nonce: int, signature: bytes) -> bool:
    """Verify an ``ATTESTATION_V1`` signature against ``eligibility_key``.

    Returns ``False`` (never raises) on any malformed input, so callers can treat
    a ``False`` uniformly as ``INVALID_ATTESTATION``.
    """
    try:
        if len(election_id) != 32 or len(pseudonym) != 32 or len(vk_bytes) != 48:
            return False
        if not (1 <= weight < CURVE_ORDER and 1 <= nonce < CURVE_ORDER):
            return False
        elig_vk = g1_from_compressed(elig_vk_bytes)
        R, s = schnorr.decode(signature)
        msg = attestation_message(election_id, pseudonym, vk_bytes, weight, nonce)
        return schnorr.verify(elig_vk, msg, R, s)
    except Exception:  # noqa: BLE001
        return False


