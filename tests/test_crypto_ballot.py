"""Ballot construction + crypto verification (Variant A / exact)."""

from __future__ import annotations

import pytest

from tests.conftest import make_attestation
from shutter_governance_protocol.crypto.points import g1_to_compressed
from shutter_governance_protocol.crypto import ballot, schnorr
from shutter_governance_protocol.crypto.ballot import _pre_v1_ballot_message
from shutter_governance_protocol.crypto.params import CURVE_ORDER
from shutter_governance_protocol.crypto.points import G2, mul, random_scalar


def _mpk():
    return mul(G2, random_scalar())


def _build(votes, budget, mpk=None, election_id=None, pseudonym=None):
    mpk = mpk or _mpk()
    sk, vk = schnorr.keygen()
    eid = election_id or b"\x11" * 32
    pseudo = pseudonym or b"\x22" * 32
    # Minted before the ballot: since v2 the voter's signature covers the credential.
    att, _ = make_attestation(eid, pseudo, g1_to_compressed(vk))
    return mpk, ballot.build_ballot(
        mpk=mpk,
        election_id=eid,
        pseudonym=pseudo,
        sk=sk, vk=vk,
        attestation=att,
        votes=votes,
        num_candidates=len(votes),
        budget=budget,
    ), att


def _verify(mpk, b, num_candidates, budget, att):
    return ballot.verify_ballot_crypto(
        mpk=mpk,
        election_id=b.election_id,
        pseudonym=b.pseudonym,
        vk_bytes=b.vk,
        ciphertext_bytes=b.ciphertexts,
        zk_proof=b.zk_proof,
        voter_signature=b.voter_signature,
        attestation=att,
        num_candidates=num_candidates,
        budget=budget,
        mode="exact",
    )


def test_build_then_verify_ok():
    mpk, b, att = _build([1, 0, 2], budget=3)
    ok, reason = _verify(mpk, b, 3, 3, att)
    assert ok and reason is None


def test_single_choice_budget_1():
    mpk, b, att = _build([0, 1], budget=1)
    ok, reason = _verify(mpk, b, 2, 1, att)
    assert ok and reason is None


def test_build_rejects_wrong_sum_exact():
    with pytest.raises(ValueError, match="exact mode requires"):
        _build([1, 1, 0], budget=3)  # sum 2 != 3


def test_build_rejects_out_of_range_vote():
    with pytest.raises(ValueError, match="not in"):
        _build([5, 0], budget=3)


def test_tampered_ciphertext_fails_proof():
    mpk, b, att = _build([1, 2], budget=3)
    # Swap in a different valid ciphertext component (breaks the range proof binding).
    other_mpk, other, att = _build([2, 1], budget=3, mpk=mpk)
    tampered = b.ciphertexts[:]
    tampered[0] = other.ciphertexts[0]
    b.ciphertexts = tampered
    ok, reason = _verify(mpk, b, 2, 3, att)
    assert not ok and reason in ("INVALID_PROOF", "INVALID_SIGNATURE")


def test_tampered_signature_detected():
    mpk, b, att = _build([1, 2], budget=3)
    # Corrupt the signature's scalar half.
    sig = bytearray(b.voter_signature)
    sig[-1] ^= 0x01
    b.voter_signature = bytes(sig)
    ok, reason = _verify(mpk, b, 2, 3, att)
    assert not ok and reason in ("INVALID_SIGNATURE", "MALFORMED")


def test_wrong_mpk_fails():
    mpk, b, att = _build([1, 2], budget=3)
    ok, reason = _verify(_mpk(), b, 2, 3, att)  # different mpk
    assert not ok


def test_bvp_codec_round_trip():
    mpk, b, att = _build([1, 0, 2], budget=3)
    rp, budget_proof = ballot.decode_ballot_validity_proof(b.zk_proof, 3, 3)
    reencoded = ballot.encode_ballot_validity_proof(rp, budget_proof)
    assert reencoded == b.zk_proof


def test_bvp_decode_rejects_wrong_params():
    mpk, b, att = _build([1, 0, 2], budget=3)
    with pytest.raises(ValueError, match="numCandidates|branch_count"):
        ballot.decode_ballot_validity_proof(b.zk_proof, 2, 3)


def test_canonical_message_binds_election_id():
    att, _ = make_attestation(b"\x11" * 32, b"\x22" * 32, b"\x44" * 48)
    m1 = ballot.canonical_ballot_message(b"\x11" * 32, b"\x22" * 32, [], b"", att)
    m2 = ballot.canonical_ballot_message(b"\x33" * 32, b"\x22" * 32, [], b"", att)
    assert m1 != m2


def test_canonical_message_binds_the_credential():
    """Every credential field, and the issuer's signature bytes, change the preimage.

    The signature is included deliberately: Schnorr signing is randomised, so one set
    of fields has many valid signatures, and leaving the bytes uncovered would let a
    relay swap one for another while the voter's signature stayed valid — making the
    envelope malleable.
    """
    eid, pseudo, vk = b"\x11" * 32, b"\x22" * 32, b"\x44" * 48
    att, _ = make_attestation(eid, pseudo, vk, weight=5, nonce=2)
    base = ballot.canonical_ballot_message(eid, pseudo, [], b"", att)

    import dataclasses
    for field, value in [
        ("pseudonym", b"\x99" * 32),
        ("vk", b"\x55" * 48),
        ("weight", 6),
        ("nonce", 3),
        ("signature", bytes(80)),
    ]:
        altered = dataclasses.replace(att, **{field: value})
        assert ballot.canonical_ballot_message(eid, pseudo, [], b"", altered) != base, field


# --- canonical scalars inside the ballot-validity proof --------- #

def _bvp_offsets(num_candidates: int):
    """Byte offset of the first OR-branch's `e`, and of the trailing budget-proof `e`."""
    header = 1 + 1 + 2 + 2 * num_candidates          # version, variant, n_outer, branch_counts
    first_branch_e = header + 96 + 96                # a1 || a2 || e || z
    return header, first_branch_e


def test_bvp_rejects_non_canonical_branch_scalar():
    """A branch scalar bumped by CURVE_ORDER is the same scalar, so the proof still
    verifies mathematically — decode must refuse the second encoding of it."""
    mpk, b, att = _build([1, 0, 2], budget=3)
    _, off = _bvp_offsets(3)
    e = int.from_bytes(b.zk_proof[off:off + 32], "big")
    assert e < CURVE_ORDER  # the honest encoding is canonical
    tampered = b.zk_proof[:off] + (e + CURVE_ORDER).to_bytes(32, "big") + b.zk_proof[off + 32:]
    assert len(tampered) == len(b.zk_proof)
    with pytest.raises(ValueError, match="non-canonical"):
        ballot.decode_ballot_validity_proof(tampered, 3, 3)


def test_bvp_rejects_non_canonical_budget_scalar():
    mpk, b, att = _build([1, 0, 2], budget=3)
    # budget proof sits at the very end: ... || tag(1) || e_b(32) || z_b(32)
    off = len(b.zk_proof) - 64
    z_b = int.from_bytes(b.zk_proof[off + 32:], "big")
    tampered = b.zk_proof[:off + 32] + (z_b + CURVE_ORDER).to_bytes(32, "big")
    with pytest.raises(ValueError, match="non-canonical"):
        ballot.decode_ballot_validity_proof(tampered, 3, 3)


def test_bvp_honest_proof_still_decodes_and_verifies():
    """Guard against the canonicality check being too strict."""
    mpk, b, att = _build([2, 1, 0], budget=3)
    rp, budget_proof = ballot.decode_ballot_validity_proof(b.zk_proof, 3, 3)
    assert ballot.encode_ballot_validity_proof(rp, budget_proof) == b.zk_proof
    ok, reason = _verify(mpk, b, 3, 3, att)
    assert ok, reason


# --- the three ballot domain separators must stay distinct ------------------- #

def test_ballot_labels_are_three_distinct_domains():
    """Guard against "tidying" the labels into agreement.

    Three strings are in play and only two of them are versions of each other:

      * ``BALLOT_MESSAGE_LABEL``          -- what the voter signs today (v2)
      * ``BALLOT_PROOF_TRANSCRIPT_LABEL`` -- the range/budget proof's Fiat-Shamir
        domain, which has never been versioned and must not move: changing it
        re-challenges every proof and re-pins every known-answer vector
      * the literal in ``_pre_v1_ballot_message`` -- the *superseded* message format,
        kept only so a pre-v2 client is reported as a format mismatch

    The proof label and the v1 diagnostic were once the same literal, so one string
    meant two unrelated things and bumping the apparently-stale "v1" silently
    invalidated every proof. That is the mistake this test exists to catch.
    """
    from shutter_governance_protocol.crypto.params import BALLOT_MESSAGE_LABEL, BALLOT_PROOF_TRANSCRIPT_LABEL

    v1_diagnostic = "SHUTTER-VOTE-BALLOT-v1"
    labels = [BALLOT_MESSAGE_LABEL, BALLOT_PROOF_TRANSCRIPT_LABEL, v1_diagnostic]
    assert len(set(labels)) == 3, f"ballot domain separators collided: {labels}"

    # And the diagnostic really is the format the old code signed, so the v1
    # detection in verify_ballot_crypto keeps working.
    assert _pre_v1_ballot_message(b"\x11" * 32, b"\x22" * 32, [], b"").startswith(
        v1_diagnostic.encode()
    )
