"""Ballot construction + crypto verification, ``atMost`` mode (Variant A).

In ``atMost`` a ballot may spend anything from 0 to the budget, and proves it with a
(B+1)-branch OR proof over the homomorphic sum instead of the exact-mode DLEQ. The SDK
builds and checks these; this side used to call every one of them malformed, so an
atMost election published all zeros.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.conftest import make_attestation
from shutter_governance_protocol.crypto import ballot, schnorr
from shutter_governance_protocol.crypto.points import G2, g1_to_compressed, g2_to_compressed, mul, random_scalar

ROOT = Path(__file__).resolve().parents[1]
SDK_VERIFY = ROOT / "tests" / "sdk" / "verify_ballot.mjs"
SDK_PACKAGE = ROOT / "frontend" / "node_modules" / "@shutter-network" / "urban-verified-crypto"


def _build(votes, budget, *, mode="atMost", mpk=None):
    mpk = mpk or mul(G2, random_scalar())
    sk, vk = schnorr.keygen()
    eid, pseudo = b"\x11" * 32, b"\x22" * 32
    att, elig_vk = make_attestation(eid, pseudo, g1_to_compressed(vk))
    built = ballot.build_ballot(
        mpk=mpk, election_id=eid, pseudonym=pseudo, sk=sk, vk=vk, attestation=att,
        votes=votes, num_candidates=len(votes), budget=budget, mode=mode,
    )
    return mpk, built, att, elig_vk


def _verify(mpk, b, att, *, budget, mode="atMost"):
    return ballot.verify_ballot_crypto(
        mpk=mpk, election_id=b.election_id, pseudonym=b.pseudonym, vk_bytes=b.vk,
        ciphertext_bytes=b.ciphertexts, zk_proof=b.zk_proof, voter_signature=b.voter_signature,
        attestation=att, num_candidates=len(b.ciphertexts), budget=budget, mode=mode,
    )


@pytest.mark.parametrize("votes", [[1, 0, 1], [0, 0, 0], [3, 0, 0], [1, 1, 1]],
                         ids=["partly-spent", "blank", "all-on-one", "fully-spent"])
def test_at_most_ballot_builds_and_verifies(votes):
    mpk, b, att, _ = _build(votes, budget=3)
    assert _verify(mpk, b, att, budget=3) == (True, None)


def test_at_most_builder_refuses_more_than_the_budget():
    with pytest.raises(ValueError, match="atMost"):
        _build([2, 1, 1], budget=3)


def test_exact_builder_still_requires_the_whole_budget():
    with pytest.raises(ValueError, match="exact"):
        _build([1, 0, 1], budget=3, mode="exact")


def test_a_proof_for_the_other_mode_is_malformed():
    """The budget proof's wire tag must match the election's mode, as the SDK requires
    (``verify.ts``: "budget mode on wire differs from params"). A ballot spending exactly
    B is valid in both modes' arithmetic, so only the tag can tell them apart."""
    mpk, at_most, att, _ = _build([1, 1, 1], budget=3, mode="atMost")
    assert _verify(mpk, at_most, att, budget=3, mode="exact") == (False, "MALFORMED")
    mpk, exact, att, _ = _build([1, 1, 1], budget=3, mode="exact")
    assert _verify(mpk, exact, att, budget=3, mode="atMost") == (False, "MALFORMED")


def test_tampered_budget_proof_fails():
    mpk, b, att, _ = _build([1, 0, 1], budget=3)
    proof = bytearray(b.zk_proof)
    proof[-1] ^= 0x01  # last byte: z of the budget proof's final branch
    b.zk_proof = bytes(proof)
    ok, reason = _verify(mpk, b, att, budget=3)
    assert not ok and reason in ("INVALID_PROOF", "MALFORMED")


@pytest.mark.parametrize("cut", ["unknown-tag", "truncated"])
def test_a_damaged_budget_section_is_malformed(cut):
    mpk, b, att, _ = _build([1, 0, 1], budget=3)
    budget_start = len(b.zk_proof) - 4 * 256 - 1  # tag + (B + 1) branches
    proof = bytearray(b.zk_proof)
    if cut == "unknown-tag":
        proof[budget_start] = 0x02
    else:
        del proof[-100:]
    b.zk_proof = bytes(proof)
    assert _verify(mpk, b, att, budget=3) == (False, "MALFORMED")


def test_codec_round_trips_an_at_most_proof():
    _, b, _, _ = _build([0, 2, 1], budget=3)
    rp, budget_proof = ballot.decode_ballot_validity_proof(b.zk_proof, 3, 3)
    assert isinstance(budget_proof, list) and len(budget_proof) == 4  # B + 1 branches
    assert ballot.encode_ballot_validity_proof(rp, budget_proof) == b.zk_proof


def test_unknown_mode_is_refused():
    with pytest.raises(ValueError, match="mode"):
        _build([1, 0, 1], budget=3, mode="sometimes")


@pytest.mark.skipif(shutil.which("node") is None or not SDK_PACKAGE.exists(),
                    reason="needs node and the frontend's installed SDK")
@pytest.mark.parametrize("votes", [[1, 0, 1], [0, 0, 0]], ids=["partly-spent", "blank"])
def test_sdk_accepts_an_at_most_ballot_built_here(tmp_path, votes):
    """The reverse of the SDK-built vectors in ``tests/vectors/ballot``: a ballot built by
    this implementation must pass the SDK's own ``verifyBallot``."""
    mpk, b, att, elig_vk = _build(votes, budget=3)
    vector = {
        "inputs": {
            "mpk": g2_to_compressed(mpk).hex(), "vk": b.vk.hex(),
            "election_id": b.election_id.hex(), "pseudonym": b.pseudonym.hex(),
            "eligibility_key": elig_vk.hex(),
            "params": {"numCandidates": 3, "budget": 3, "mode": "atMost", "variant": "A"},
            "ciphertexts": [{"c1": c1.hex(), "c2": c2.hex()} for c1, c2 in b.ciphertexts],
            "zkProof": b.zk_proof.hex(), "signature": b.voter_signature.hex(),
            "attestation": {
                "electionId": att.election_id.hex(), "pseudonym": att.pseudonym.hex(),
                "vk": att.vk.hex(), "weight": att.weight, "nonce": att.nonce,
                "signature": att.signature.hex(),
            },
        },
        "expected": {"verify": True},
    }
    path = tmp_path / "ballot.json"
    path.write_text(json.dumps(vector))
    out = subprocess.run(["node", str(SDK_VERIFY), str(path)], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
