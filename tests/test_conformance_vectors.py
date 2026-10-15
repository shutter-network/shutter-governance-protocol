"""Cross-language conformance vectors.

Verifies that shutter_governance_protocol's crypto reproduces every cross-implementation vector — the
same JSON files an independent re-verifier (the TS SDK, a future port) consumes.
Vectors follow the shared schema: compressed-hex points, decimal-string scalars,
hex byte blobs. Adopted from the reference SDK suite and extended here; this is
the protocol conformance gate (single command: ``pytest tests/test_conformance_vectors.py``).

Categories: encrypt, dleq, or, budget (exact+atMost), schnorr, decrypt-share,
ballot, tally. Variant-B / atMost *ballots* are conformance level 2 (specified,
not implemented in the reference); adding one here fails until it is supported.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shutter_governance_protocol.crypto import schnorr
from shutter_governance_protocol.crypto.ballot import verify_ballot_crypto
from shutter_governance_protocol.crypto.elgamal import encrypt
from shutter_governance_protocol.crypto.points import Z2, add, g1_from_compressed, g2_from_compressed, g2_to_compressed, mul, neg
from shutter_governance_protocol.crypto.proofs import (
    ORBranch,
    decode_dleq,
    verify_budget_at_most,
    verify_budget_exact,
    verify_decryption_share,
    verify_dleq,
    verify_or,
)
from shutter_governance_protocol.crypto.recovery import baby_step_giant_step, combine_shares
from shutter_governance_protocol.crypto.transcript import Transcript

VECTORS = Path(__file__).parent / "vectors"


def _load(category: str):
    files = sorted((VECTORS / category).glob("*.json"))
    return [(f.stem, json.loads(f.read_text())) for f in files]


def _g2(h):
    return g2_from_compressed(bytes.fromhex(h))


def _g1(h):
    return g1_from_compressed(bytes.fromhex(h))


def _hx(h):
    return bytes.fromhex(h)


def _decode_or(hexstr: str):
    b = bytes.fromhex(hexstr)
    n = (b[0] << 8) | b[1]
    off, branches = 2, []
    for _ in range(n):
        a1 = g2_from_compressed(b[off:off + 96]); off += 96
        a2 = g2_from_compressed(b[off:off + 96]); off += 96
        e = int.from_bytes(b[off:off + 32], "big"); off += 32
        z = int.from_bytes(b[off:off + 32], "big"); off += 32
        branches.append(ORBranch(a1, a2, e, z))
    return branches


def _ids(cases):
    return [c[0] for c in cases]


# --------------------------------------------------------------------------- #
#  encrypt — byte-parity (deterministic ciphertext under pinned r)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("encrypt"), ids=_ids(_load("encrypt")))
def test_encrypt_vector(name, v):
    i = v["inputs"]
    c1, c2, _ = encrypt(_g2(i["mpk"]), int(i["m"]), int(i["r"]))
    assert g2_to_compressed(c1).hex() == v["expected"]["c1"]
    assert g2_to_compressed(c2).hex() == v["expected"]["c2"]


# --------------------------------------------------------------------------- #
#  dleq / or / budget / schnorr / decrypt-share — verify path
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("dleq"), ids=_ids(_load("dleq")))
def test_dleq_vector(name, v):
    i = v["inputs"]
    e, z = decode_dleq(_hx(i["proof"]))
    ok = verify_dleq(_g2(i["base1"]), _g2(i["point1"]), _g2(i["base2"]), _g2(i["point2"]),
                     e, z, Transcript(i["transcript_label"]))
    assert ok is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("or"), ids=_ids(_load("or")))
def test_or_vector(name, v):
    i = v["inputs"]
    branches = _decode_or(i["or_proof_encoded"])
    ok = verify_or(_g2(i["ct"]["c1"]), _g2(i["ct"]["c2"]), _g2(i["mpk"]),
                   [int(x) for x in i["candidates"]], branches, Transcript(i["transcript_label"]))
    assert ok is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("budget"), ids=_ids(_load("budget")))
def test_budget_vector(name, v):
    i = v["inputs"]
    c1, c2, mpk, B = _g2(i["ct_sum"]["c1"]), _g2(i["ct_sum"]["c2"]), _g2(i["mpk"]), i["budget"]
    t = Transcript(i["transcript_label"])
    if i["mode"] == "exact":
        e, z = decode_dleq(_hx(i["proof_encoded"]))
        ok = verify_budget_exact(c1, c2, mpk, B, e, z, t)
    else:
        ok = verify_budget_at_most(c1, c2, mpk, B, _decode_or(i["proof_encoded"]), t)
    assert ok is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("schnorr"), ids=_ids(_load("schnorr")))
def test_schnorr_vector(name, v):
    i = v["inputs"]
    # Pinned build fixtures store the encoded signature alongside their inputs.
    R, s = schnorr.decode(_hx(i["sig"] if "sig" in i else i["sig_encoded"]))
    assert schnorr.verify(_g1(i["vk"]), _hx(i["message"]), R, s) is v["expected"]["verify"]


@pytest.mark.parametrize("name,v", _load("decrypt-share"), ids=_ids(_load("decrypt-share")))
def test_decrypt_share_vector(name, v):
    i = v["inputs"]
    sh = i["share"]
    e, z = decode_dleq(_hx(sh["dleq_proof"]))
    ok = verify_decryption_share(
        Transcript(i["transcript_label"]),
        _g2(i["ct_sum"]["c1"]), _g2(i["ct_sum"]["c2"]),
        _g2(i["committee_pk"]), _g2(sh["sigma"]), e, z, i["keyper_index"],
    )
    assert ok is v["expected"]["verify"]


# --------------------------------------------------------------------------- #
#  ballot — full validity-proof + signature (variant A / exact = level 1)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("ballot"), ids=_ids(_load("ballot")))
def test_ballot_vector(name, v):
    i = v["inputs"]
    if "zkProof" not in i:
        # Verify the pinned build output as well as checking its byte parity elsewhere.
        out = v["outputs"]
        i = {
            **i,
            "election_id": i["electionId"],
            "ciphertexts": [{"c1": c1, "c2": c2} for c1, c2 in out["ciphertexts"]],
            "zkProof": out["zkProof"],
            "signature": out["voterSignature"],
        }
    params = i["params"]
    if params["mode"] != "exact" or params["variant"] != "A":
        pytest.fail("variant B / atMost ballot is conformance level 2 (not implemented)")
    from shutter_governance_protocol.envelopes.types import Attestation, AttestationScheme
    a = i["attestation"]
    attestation = Attestation(
        election_id=_hx(a["electionId"]), pseudonym=_hx(a["pseudonym"]),
        vk=_hx(a["vk"]), weight=a["weight"], nonce=a["nonce"],
        signature=_hx(a["signature"]), scheme=AttestationScheme.V1,
    )
    ok, _reason = verify_ballot_crypto(
        mpk=_g2(i["mpk"]),
        election_id=_hx(i["election_id"]),
        pseudonym=_hx(i["pseudonym"]),
        vk_bytes=_hx(i["vk"]),
        ciphertext_bytes=[(_hx(c["c1"]), _hx(c["c2"])) for c in i["ciphertexts"]],
        zk_proof=_hx(i["zkProof"]),
        voter_signature=_hx(i["signature"]),
        attestation=attestation,
        num_candidates=params["numCandidates"],
        budget=params["budget"],
    )
    expected = v["expected"]
    assert ok is (expected["verify"] if "verify" in expected else expected["verifyBallot"])


# --------------------------------------------------------------------------- #
#  tally — Lagrange combine (via published alphas) + BSGS recovery
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("tally"), ids=_ids(_load("tally")))
def test_tally_vector(name, v):
    i = v["inputs"]
    c2 = _g2(i["ct_sum"]["c2"])
    # `alphas` are the evaluation points (keyper indices) of the t+1 subset,
    # in shares order; Lagrange-combine at zero, then subtract and BSGS-recover.
    pairs = [(int(alpha), _g2(sh["sigma"])) for sh, alpha in zip(i["shares"], i["alphas"])]
    tau = add(c2, neg(combine_shares(pairs)))
    recovered = baby_step_giant_step(tau, int(i["upper_bound"]))
    assert recovered == int(v["expected"]["V"])


# --------------------------------------------------------------------------- #
#  attestation (shutter-governance-protocol-native: ATTESTATION_V1 + legacy, positive + negative)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,v", _load("attestation"), ids=_ids(_load("attestation")))
def test_attestation_vector(name, v):
    from shutter_governance_protocol.envelopes.types import Attestation, AttestationScheme
    from shutter_governance_protocol.ports.eligibility import verify_attestation

    i = v["inputs"]
    att = Attestation(
        election_id=_hx(i["electionId"]), pseudonym=_hx(i["pseudonym"]), vk=_hx(i["vk"]),
        # Decimal strings in the attestation vectors (exact in any JSON reader); int() also
        # accepts a plain number.
        weight=int(i["weight"]), signature=_hx(i["signature"]), scheme=AttestationScheme(i["scheme"]),
        nonce=int(i.get("nonce", 1)),
    )
    ok = verify_attestation(_hx(i["eligibilityKey"]), att, election_id=_hx(i["electionId"]))
    assert ok is v["expected"]["verify"]


# --------------------------------------------------------------------------- #
#  flow — replay a full election from its stored public artifacts
# --------------------------------------------------------------------------- #

def test_full_election_flow_replay():
    from shutter_governance_protocol.core.admission import StoredBallot, admit
    from shutter_governance_protocol.core.aggregation import build_aggregate_artifact, check_result, recover_result
    from shutter_governance_protocol.envelopes import codecs

    fx = json.loads((VECTORS / "flow" / "full_election_level1.json").read_text())
    config = codecs.dec_config(fx["config"])
    mpk_bytes = bytes.fromhex(fx["finalizedKey"]["pkElection"])
    committee = tuple(bytes.fromhex(p) for p in fx["finalizedKey"]["committeePKs"])
    stored = [StoredBallot(seq, codecs.dec_ballot(b)) for seq, b in enumerate(fx["ballots"])]
    published_agg = codecs.dec_aggregate(fx["aggregate"])
    shares = [codecs.dec_decryption_share(s) for s in fx["shares"]]
    published_result = codecs.dec_result(fx["result"])

    # 1. Re-derive admission + aggregate; must byte-match the published aggregate.
    admission = admit(stored, config, mpk_bytes)
    recomputed_agg = build_aggregate_artifact(config, admission)
    assert recomputed_agg == published_agg
    # sanity on the fixture's shape: last-wins keeps the P1 duplicate at seq 3,
    # excludes seq 0 (duplicate) and seq 2 (invalid signature).
    assert set(published_agg.admitted) == {1, 3, 4}
    assert {x.reason.value for x in published_agg.exclusions} == {"INVALID_SIGNATURE", "DUPLICATE_PSEUDONYM"}

    # 2. Recover from the published aggregate + shares; must match the published result.
    recovered = recover_result(config, published_agg, shares, committee, config.threshold.t)
    assert recovered is not None
    assert tuple(recovered.totals) == tuple(published_result.totals)
    assert recovered.bsgs_bound == published_result.bsgs_bound

    # 3. The same artifacts through the *checking* path rather than the solving one.
    #
    # This is the cross-implementation half of the guarantee: the SDK drives this
    # very file through `verifyTallyAgainstTotals`
    # (sx-monorepo `packages/shutter-governance-protocol-parity/tests/shutter-governance-protocol-parity.test.ts`), so the two must
    # agree on what "this tally verifies" means against identical bytes. Tested
    # against the vector rather than only against locally generated data, because a
    # divergence here would surface as a committee and a browser disagreeing about
    # a real election.
    ok, reason = check_result(
        config, published_agg, shares, committee, config.threshold.t,
        tuple(published_result.totals),
    )
    assert ok, reason

    bound = published_result.bsgs_bound
    totals = list(published_result.totals)

    # Moving a vote between candidates keeps the sum intact, so only the
    # per-candidate group equality separates this from the truth.
    moved = list(totals)
    moved[0] += 1
    moved[1] -= 1
    ok, reason = check_result(config, published_agg, shares, committee, config.threshold.t, tuple(moved))
    assert not ok and "does not decrypt the aggregate" in reason

    # Breaks the exact-mode identity instead: every admitted ballot spends its
    # whole budget, so the totals must sum to budget x total admitted weight.
    inflated = list(totals)
    inflated[0] += 1
    ok, reason = check_result(config, published_agg, shares, committee, config.threshold.t, tuple(inflated))
    assert not ok and reason.startswith("result:")

    # Outside the bound, which is what stops a published `T + q` — the same group
    # element as `T` — passing the equality as a nonsense 256-bit integer.
    over = list(totals)
    over[0] = bound + 1
    ok, reason = check_result(config, published_agg, shares, committee, config.threshold.t, tuple(over))
    assert not ok and "outside" in reason

    # A quorum-short share set is an availability failure, not an integrity one,
    # and the reason prefix has to say so.
    ok, reason = check_result(
        config, published_agg, shares[: config.threshold.t - 1], committee,
        config.threshold.t, tuple(totals),
    )
    assert not ok and reason.startswith("shares:")


# --------------------------------------------------------------------------- #
#  scale — integer half-up weight scaling, pinned across implementations
# --------------------------------------------------------------------------- #

def test_scaled_weight_vector():
    """The `.5` boundary, asserted against bytes the SDK asserts against too.

    Python's `round` is half-to-even and JavaScript's `Math.round` is half-up, so a
    float implementation of this agrees everywhere except at exactly `.5` — and there
    it makes shutter_governance_protocol and the browser build different aggregates from identical ballots.
    The failure surfaces as an honest committee appearing to publish a false
    aggregate, with nothing in the error pointing at rounding, which is why this is
    pinned to a shared vector rather than to each side's own arithmetic.

    sx replays this same file in `packages/shutter-governance-protocol-parity`.
    """
    from shutter_governance_protocol.core.aggregation import scaled_weight

    fx = json.loads((VECTORS / "scale" / "scaled_weight_boundary.json").read_text())
    assert fx["cases"], "empty vector"
    for c in fx["cases"]:
        assert scaled_weight(c["weight"], c["scale"]) == c["scaled"], c

    # Guards the guard: this is the side the divergence actually lives on, so if a
    # float `round` ever stopped failing here, the vector would have stopped covering
    # the boundary and the parity claim would be hollow.
    naive = [c for c in fx["cases"]
             if (c["weight"] if c["scale"] <= 1 else round(c["weight"] / c["scale"])) != c["scaled"]]
    assert naive, "vector no longer distinguishes half-to-even from half-up"
