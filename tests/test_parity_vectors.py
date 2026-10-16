"""Byte-parity conformance vectors.

Reproduces fully-pinned vectors byte-for-byte, proving this reimplementation of
the crypto suite is wire-compatible with the reference (and, transitively, with
the TS frontend SDK). Vectors live in ``tests/vectors/`` — see its README.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shutter_governance_protocol.crypto import ballot, schnorr
from shutter_governance_protocol.crypto.points import g1_from_compressed, g2_from_compressed

VECTORS = Path(__file__).parent / "vectors"


def _int(h: str) -> int:
    return int(h, 16)


def _bytes(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


# --------------------------------------------------------------------------- #
#  Schnorr — deterministic sign reproduces exact R, s, encoded bytes
# --------------------------------------------------------------------------- #

def test_schnorr_known_vector_byte_parity():
    v = json.loads((VECTORS / "schnorr" / "schnorr_known_sk_k.json").read_text())
    i = v["inputs"]
    sk = _int(i["sk"])
    vk = g1_from_compressed(_bytes(i["vk"]))
    msg = _bytes(i["message"])
    R, s = schnorr.sign(sk, vk, msg, k=_int(i["k"]))

    # Byte-for-byte against the fixture.
    from shutter_governance_protocol.crypto.points import g1_to_compressed
    assert g1_to_compressed(R).hex() == i["R"]
    assert s == _int(i["s"])
    assert schnorr.encode(R, s).hex() == i["sig_encoded"]
    # And it verifies.
    assert schnorr.verify(vk, msg, R, s) is v["expected"]["verify"]


# --------------------------------------------------------------------------- #
#  Ballot — deterministic build reproduces exact ciphertexts, proof, signature
# --------------------------------------------------------------------------- #

def _vector_attestation(i):
    """The credential pinned in the vector, as an ``Attestation``."""
    from shutter_governance_protocol.envelopes.types import Attestation, AttestationScheme
    a = i["attestation"]
    return Attestation(
        election_id=_bytes(a["electionId"]), pseudonym=_bytes(a["pseudonym"]),
        vk=_bytes(a["vk"]), weight=a["weight"], nonce=a["nonce"],
        signature=_bytes(a["signature"]), scheme=AttestationScheme.V1,
    )


def test_ballot_known_vector_byte_parity():
    v = json.loads((VECTORS / "ballot" / "ballot_variantA_exact_known.json").read_text())
    i = v["inputs"]
    params = i["params"]
    mpk = g2_from_compressed(_bytes(i["mpk"]))
    vk = g1_from_compressed(_bytes(i["vk"]))

    # Convert pinned range-proof simulations: per-candidate list of {e,z}|None.
    sims = None
    if i.get("range_proof_sims") is not None:
        sims = [
            [None if b is None else (_int(b["e"]), _int(b["z"])) for b in cand]
            for cand in i["range_proof_sims"]
        ]

    built = ballot.build_ballot(
        mpk=mpk,
        election_id=_bytes(i["electionId"]),
        pseudonym=_bytes(i["pseudonym"]),
        sk=_int(i["sk"]),
        vk=vk,
        attestation=_vector_attestation(i),
        votes=[int(x) for x in i["votes"]],
        num_candidates=params["numCandidates"],
        budget=params["budget"],
        mode=params["mode"],
        rs=[_int(r) for r in i["randomness"]],
        range_proof_w=[_int(w) for w in i["range_proof_w"]],
        range_proof_sims=sims,
        budget_proof_w=_int(i["budget_proof_w"]),
        schnorr_k=_int(i["k"]),
    )

    out = v["outputs"]
    assert [[c1.hex(), c2.hex()] for (c1, c2) in built.ciphertexts] == out["ciphertexts"]
    assert built.zk_proof.hex() == out["zkProof"]
    assert built.voter_signature.hex() == out["voterSignature"]
    assert built.canonical_preimage.hex() == out["canonical_preimage"]


def test_ballot_known_vector_verifies():
    v = json.loads((VECTORS / "ballot" / "ballot_variantA_exact_known.json").read_text())
    i, out, params = v["inputs"], v["outputs"], v["inputs"]["params"]
    mpk = g2_from_compressed(_bytes(i["mpk"]))
    ok, reason = ballot.verify_ballot_crypto(
        mpk=mpk,
        election_id=_bytes(i["electionId"]),
        pseudonym=_bytes(i["pseudonym"]),
        vk_bytes=_bytes(i["vk"]),
        ciphertext_bytes=[(bytes.fromhex(a), bytes.fromhex(b)) for (a, b) in out["ciphertexts"]],
        zk_proof=bytes.fromhex(out["zkProof"]),
        voter_signature=bytes.fromhex(out["voterSignature"]),
        attestation=_vector_attestation(i),
        num_candidates=params["numCandidates"],
        budget=params["budget"],
        mode=params["mode"],
    )
    assert ok is v["expected"]["verifyBallot"]
    assert reason is None
