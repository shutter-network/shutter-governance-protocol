"""Round-trip and malformed-input tests for the JSON envelope codecs (Issue 1).

Every artifact type round-trips through encode -> JSON string -> decode and
compares equal to the original; every decoder rejects malformed input (bad hex,
wrong byte size, missing field, unknown reason code) with a ``CodecError``.
"""

from __future__ import annotations

import json

import pytest

from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.envelopes.codecs import CodecError
from shutter_governance_protocol.envelopes.types import (
    BYTES32,
    DLEQ_BYTES,
    G1_BYTES,
    G2_BYTES,
    SCHNORR_BYTES,
    AggregateArtifact,
    Attestation,
    AttestationScheme,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    Exclusion,
    ExclusionReason,
    ResultArtifact,
)


# --------------------------------------------------------------------------- #
#  Fixtures / builders (deterministic byte patterns of the correct sizes)
# --------------------------------------------------------------------------- #

def _b(size: int, fill: int) -> bytes:
    return bytes([fill % 256]) * size


def make_attestation() -> Attestation:
    return Attestation(
        election_id=_b(BYTES32, 0x11),
        pseudonym=_b(BYTES32, 0x22),
        vk=_b(G1_BYTES, 0x33),
        weight=7,
        signature=_b(SCHNORR_BYTES, 0x44),
    )


def make_ballot() -> BallotEnvelope:
    return BallotEnvelope(
        election_id=_b(BYTES32, 0x11),
        pseudonym=_b(BYTES32, 0x22),
        vk=_b(G1_BYTES, 0x33),
        ciphertexts=(
            Ciphertext(c1=_b(G2_BYTES, 0x01), c2=_b(G2_BYTES, 0x02)),
            Ciphertext(c1=_b(G2_BYTES, 0x03), c2=_b(G2_BYTES, 0x04)),
        ),
        zk_proof=bytes(range(20)),  # variable length
        voter_signature=_b(SCHNORR_BYTES, 0x55),
        attestation=make_attestation(),
    )


def make_dkg_result() -> DKGResultSubmission:
    return DKGResultSubmission(
        election_id=_b(BYTES32, 0x11),
        pk_election=_b(G2_BYTES, 0xA1),
        committee_pks=(_b(G2_BYTES, 0xB1), _b(G2_BYTES, 0xB2), _b(G2_BYTES, 0xB3)),
        keyper_signature=bytes(range(65)),  # variable length (adapter-defined)
    )


def make_decryption_share() -> DecryptionShareEnvelope:
    return DecryptionShareEnvelope(
        election_id=_b(BYTES32, 0x11),
        keyper_index=2,
        entries=(
            DecryptionShareEntry(sigma=_b(G2_BYTES, 0x01), proof=_b(DLEQ_BYTES, 0x02)),
            DecryptionShareEntry(sigma=_b(G2_BYTES, 0x03), proof=_b(DLEQ_BYTES, 0x04)),
        ),
    )


def make_aggregate() -> AggregateArtifact:
    return AggregateArtifact(
        election_id=_b(BYTES32, 0x11),
        aggregates=(Ciphertext(c1=_b(G2_BYTES, 0x01), c2=_b(G2_BYTES, 0x02)),),
        admitted=(0, 1, 3, 4),
        exclusions=(
            Exclusion(sequence_number=2, reason=ExclusionReason.DUPLICATE_PSEUDONYM),
            Exclusion(sequence_number=5, reason=ExclusionReason.INVALID_PROOF),
        ),
        total_admitted_weight=12,
    )


def make_result() -> ResultArtifact:
    return ResultArtifact(
        election_id=_b(BYTES32, 0x11),
        totals=(3, 5, 4),
        keyper_indices=(1, 2),
        bsgs_bound=1200,
    )


ROUND_TRIP_CASES = [
    ("attestation", make_attestation(), codecs.enc_attestation, codecs.dec_attestation),
    ("ballot", make_ballot(), codecs.enc_ballot, codecs.dec_ballot),
    ("dkg_result", make_dkg_result(), codecs.enc_dkg_result, codecs.dec_dkg_result),
    ("share", make_decryption_share(), codecs.enc_decryption_share, codecs.dec_decryption_share),
    ("aggregate", make_aggregate(), codecs.enc_aggregate, codecs.dec_aggregate),
    ("result", make_result(), codecs.enc_result, codecs.dec_result),
]


# --------------------------------------------------------------------------- #
#  Round-trip
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,obj,enc,dec", ROUND_TRIP_CASES, ids=[c[0] for c in ROUND_TRIP_CASES])
def test_round_trip_through_json(name, obj, enc, dec):
    """encode -> json.dumps -> json.loads -> decode reproduces the object."""
    encoded = enc(obj)
    # Must be JSON-serialisable (proves 0x-hex byte fields, no raw bytes leaked).
    round_tripped = json.loads(json.dumps(encoded))
    assert dec(round_tripped) == obj


@pytest.mark.parametrize("name,obj,enc,dec", ROUND_TRIP_CASES, ids=[c[0] for c in ROUND_TRIP_CASES])
def test_all_byte_fields_are_0x_hex(name, obj, enc, dec):
    """Every string field in an encoded envelope that carries bytes is 0x-hex."""
    encoded = enc(obj)
    dumped = json.dumps(encoded)
    # No accidental non-ascii / raw byte leakage.
    assert dumped.isascii()


def test_ballot_carries_explicit_election_id_and_weighted_attestation():
    """The generalised ballot adds election_id and an ATTESTATION_V1 with weight."""
    encoded = codecs.enc_ballot(make_ballot())
    assert encoded["electionId"].startswith("0x")
    assert encoded["attestation"]["weight"] == "7"  # decimal string: exact in any JSON reader


def test_aggregate_exclusion_reason_is_serialised_by_name():
    encoded = codecs.enc_aggregate(make_aggregate())
    reasons = {x["reason"] for x in encoded["exclusions"]}
    assert reasons == {"DUPLICATE_PSEUDONYM", "INVALID_PROOF"}


def test_attestation_scheme_defaults_to_v1():
    encoded = codecs.enc_attestation(make_attestation())
    assert encoded["scheme"] == "ATTESTATION_V1"


def test_attestation_scheme_absent_on_wire_decodes_as_v1():
    d = codecs.enc_attestation(make_attestation())
    del d["scheme"]  # legacy producers may omit it
    assert codecs.dec_attestation(d).scheme is AttestationScheme.V1


def test_unknown_scheme_rejected():
    d = codecs.enc_attestation(make_attestation())
    d["scheme"] = "ATTESTATION_V99"
    with pytest.raises(CodecError, match="unknown scheme"):
        codecs.dec_attestation(d)


# --------------------------------------------------------------------------- #
#  Malformed-input rejection
# --------------------------------------------------------------------------- #

def test_missing_field_rejected():
    d = codecs.enc_ballot(make_ballot())
    del d["vk"]
    with pytest.raises(CodecError, match="missing field 'vk'"):
        codecs.dec_ballot(d)


def test_bad_hex_rejected():
    d = codecs.enc_attestation(make_attestation())
    d["vk"] = "0xZZZZ"
    with pytest.raises(CodecError, match="invalid hex"):
        codecs.dec_attestation(d)


def test_missing_0x_prefix_rejected():
    d = codecs.enc_attestation(make_attestation())
    d["signature"] = d["signature"][2:]  # strip 0x
    with pytest.raises(CodecError, match="missing '0x' prefix"):
        codecs.dec_attestation(d)


def test_wrong_byte_size_rejected():
    d = codecs.enc_attestation(make_attestation())
    d["vk"] = "0x" + ("aa" * (G1_BYTES - 1))  # 47 bytes, should be 48
    with pytest.raises(CodecError, match=r"expected 48 bytes, got 47"):
        codecs.dec_attestation(d)


def test_wrong_ciphertext_size_rejected():
    d = codecs.enc_ballot(make_ballot())
    d["ciphertexts"][0]["c1"] = "0x" + ("bb" * (G2_BYTES + 1))  # 97 bytes
    with pytest.raises(CodecError, match=r"ciphertexts\[0\].c1: expected 96 bytes"):
        codecs.dec_ballot(d)


def test_unknown_exclusion_reason_rejected():
    d = codecs.enc_aggregate(make_aggregate())
    d["exclusions"][0]["reason"] = "NOT_A_REAL_REASON"
    with pytest.raises(CodecError, match="unknown reason code"):
        codecs.dec_aggregate(d)


def test_non_integer_weight_rejected():
    d = codecs.enc_attestation(make_attestation())
    d["weight"] = "seven"
    with pytest.raises(CodecError, match="weight: expected"):
        codecs.dec_attestation(d)


def test_bool_is_not_accepted_as_integer():
    """bool is a subclass of int in Python; the codec must reject it explicitly."""
    d = codecs.enc_result(make_result())
    d["bsgsBound"] = True
    with pytest.raises(CodecError, match="bsgsBound: expected integer"):
        codecs.dec_result(d)


def test_negative_weight_rejected():
    d = codecs.enc_attestation(make_attestation())
    d["weight"] = 0
    with pytest.raises(CodecError, match="weight: must be >= 1"):
        codecs.dec_attestation(d)


def test_non_object_rejected():
    with pytest.raises(CodecError, match="expected object"):
        codecs.dec_ballot("not a dict")


def test_non_array_ciphertexts_rejected():
    d = codecs.enc_ballot(make_ballot())
    d["ciphertexts"] = {"not": "an array"}
    with pytest.raises(CodecError, match="ciphertexts: expected array"):
        codecs.dec_ballot(d)


# --------------------------------------------------------------------------- #
#  Big integers travel as decimal strings
# --------------------------------------------------------------------------- #

BIG = [1_234_567_890_123_456_789, 25 * 10**21 + 7, 2**255]  # ~1.2 tokens, ~25k tokens in wei; huge


def test_big_weights_and_nonces_round_trip_exactly_as_strings():
    """A JSON number above 2^53 is rounded by browser parsers (and written in exponent form
    from 10^21), so a voter would sign a different weight from the issuer's."""
    import json
    from dataclasses import replace

    for w in BIG:
        b = make_ballot()
        b = replace(b, attestation=replace(b.attestation, weight=w, nonce=w))
        wire = json.loads(json.dumps(codecs.enc_ballot(b)))
        assert wire["attestation"]["weight"] == str(w) and wire["attestation"]["nonce"] == str(w)
        assert codecs.dec_ballot(wire).attestation.weight == w


def test_aggregate_and_result_totals_round_trip_exactly_as_strings():
    import json
    from dataclasses import replace

    agg = replace(make_aggregate(), total_admitted_weight=BIG[1], total_scaled_weight=BIG[0])
    wire = json.loads(json.dumps(codecs.enc_aggregate(agg)))
    assert (wire["totalAdmittedWeight"], wire["totalScaledWeight"]) == (str(BIG[1]), str(BIG[0]))
    assert codecs.dec_aggregate(wire) == agg

    res = ResultArtifact(election_id=b"\x11" * 32, totals=(BIG[1], 0, BIG[0]), keyper_indices=(1, 2), bsgs_bound=BIG[2])
    wire = json.loads(json.dumps(codecs.enc_result(res)))
    assert wire["totals"] == [str(BIG[1]), "0", str(BIG[0])] and wire["bsgsBound"] == str(BIG[2])
    assert codecs.dec_result(wire) == res


def test_big_integer_fields_still_accept_json_integers():
    """Records written before the switch (database rows, on-chain credential bytes) hold
    JSON integers; they must still decode."""
    wire = codecs.enc_ballot(make_ballot())
    wire["attestation"]["weight"], wire["attestation"]["nonce"] = 7, 3
    att = codecs.dec_ballot(wire).attestation
    assert (att.weight, att.nonce) == (7, 3)


def test_big_integer_fields_reject_non_decimal_strings():
    import pytest

    for bad in ("1e18", "1.0", "-1", " 7", "0x10", "", "٧", 7.0, True):
        wire = codecs.enc_ballot(make_ballot())
        wire["attestation"]["weight"] = bad
        with pytest.raises(codecs.CodecError):
            codecs.dec_ballot(wire)


def test_dkg_submission_submitter_round_trips_and_is_optional():
    from dataclasses import replace

    from shutter_governance_protocol.envelopes.types import DKGResultSubmission

    sub = DKGResultSubmission(election_id=b"\x11" * 32, pk_election=b"\x22" * 96,
                              committee_pks=(b"\x33" * 96,), keyper_signature=b"")
    assert "submitter" not in codecs.enc_dkg_result(sub)
    assert codecs.dec_dkg_result(codecs.enc_dkg_result(sub)) == sub
    with_sender = replace(sub, submitter=b"\x44" * 20)
    assert codecs.dec_dkg_result(json.loads(json.dumps(codecs.enc_dkg_result(with_sender)))) == with_sender


def test_chain_ballot_with_a_missing_or_wrong_proof_reads_as_malformed():
    """Storage keeps only keccak256(zkProof); the proof comes from the VoteSubmitted log. A
    proof that is missing or does not match the commitment must not crash the read."""
    from eth_utils import keccak

    from shutter_governance_protocol.adapters.chain import codec as chain_codec

    b = make_ballot()
    t = chain_codec.ballot_to_tuple(b)
    stored = ((t[0], t[1], t[2], keccak(b.zk_proof), t[4], t[5]), 1500, "0x" + "00" * 20)
    assert chain_codec.ballot_record_from_contract(stored, b.election_id, 0, b.zk_proof).envelope == b
    for proof in (None, b.zk_proof + b"\x00"):
        row = chain_codec.ballot_record_from_contract(stored, b.election_id, 0, proof)
        assert row.envelope is None and row.malformed_reason
