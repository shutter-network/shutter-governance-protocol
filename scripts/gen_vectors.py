"""Generate shutter-governance-protocol-native conformance vectors.

Produces vectors for the protocol extensions the reference SDK suite does not
cover — the weighted ``ATTESTATION_V1`` (positive + negative cases) — plus a full-election **flow fixture** (config, ballots incl.
invalid + duplicate, aggregate with exclusions, decryption shares, result) that
any implementation can replay to reproduce the tally.

Run: ``python scripts/gen_vectors.py`` (writes under tests/vectors/).
Deterministic vectors pin their randomness so regeneration is stable in git; the
flow fixture is a self-consistent snapshot (its stored artifacts replay to the
same result regardless of how it was generated).
"""

from __future__ import annotations

import json
from pathlib import Path

from shutter_governance_protocol.core.admission import StoredBallot, admit
from shutter_governance_protocol.core.aggregation import build_aggregate_artifact, recover_result
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.crypto import attestation as att, ballot as ballot_crypto, proofs, schnorr
from shutter_governance_protocol.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from shutter_governance_protocol.crypto.params import CURVE_ORDER
from shutter_governance_protocol.crypto.points import G2, g1_to_compressed, g2_from_compressed, g2_to_compressed, mul
from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.envelopes.types import (
    Attestation,
    AttestationScheme,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
)
from shutter_governance_protocol.ports.eligibility import AttestationRequest

VECTORS = Path(__file__).resolve().parents[1] / "tests" / "vectors"
ELECTION_ID = bytes.fromhex("11" * 32)


def _write(category: str, name: str, obj: dict) -> None:
    d = VECTORS / category
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(obj, indent=2) + "\n")
    print(f"wrote {category}/{name}.json")


# --------------------------------------------------------------------------- #
#  Attestation vectors (ATTESTATION_V1; positive + negative)
# --------------------------------------------------------------------------- #

def gen_attestation():
    elig_sk, elig_vk = schnorr.keygen(0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
    elig_key = g1_to_compressed(elig_vk)
    _, voter_vk = schnorr.keygen(0x0FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA098765432)
    vk = g1_to_compressed(voter_vk)
    pseudonym = bytes.fromhex("22" * 32)
    k = 0x1111222233334444555566667777888899990000AAAABBBBCCCCDDDDEEEEFFFF

    def att_obj(name, desc, *, weight, scheme, election_id, sig, verify, nonce=1):
        return {
            "name": name, "description": desc, "version": 1,
            "inputs": {
                "eligibilityKey": elig_key.hex(), "electionId": election_id.hex(),
                # Decimal strings, not JSON numbers: a JavaScript reader rounds any integer
                # above 2^53, and the non-canonical vectors carry 77-digit values.
                "pseudonym": pseudonym.hex(), "vk": vk.hex(), "weight": str(weight), "nonce": str(nonce),
                "scheme": scheme, "signature": sig.hex(),
            },
            "expected": {"verify": verify},
        }

    # Valid V1 (weighted). nonce=1 = the voter's first vote.
    sig_v1 = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, 5, 1, k=k)
    _write("attestation", "attestation_v1_valid",
           att_obj("attestation_v1_valid", "Weighted ATTESTATION_V1 over (eid,pseudonym,vk,weight=5,nonce=1).",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=True))

    # Negative: tampered weight (signature over 5, envelope claims 9).
    _write("attestation", "attestation_v1_tampered_weight",
           att_obj("attestation_v1_tampered_weight", "Signature over weight=5 but envelope claims weight=9.",
                   weight=9, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=False))

    # Negative: tampered nonce (signature over nonce=1, envelope claims nonce=2). This is the
    # replay-protection binding — a lower-nonce credential can't masquerade as a re-vote.
    _write("attestation", "attestation_v1_tampered_nonce",
           att_obj("attestation_v1_tampered_nonce", "Signature over nonce=1 but envelope claims nonce=2.",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=False, nonce=2))

    # Negative: non-canonical weight / nonce. ``5 + q`` and ``1 + q`` are the same scalars
    # as the signed 5 and 1, so a verifier that reduced mod q would accept them while the
    # tally counted the raw, enormous integers. Both must be rejected.
    _write("attestation", "attestation_v1_weight_plus_q",
           att_obj("attestation_v1_weight_plus_q", "Signature over weight=5 but envelope claims weight=5+q.",
                   weight=5 + CURVE_ORDER, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1,
                   verify=False))
    _write("attestation", "attestation_v1_nonce_plus_q",
           att_obj("attestation_v1_nonce_plus_q", "Signature over nonce=1 but envelope claims nonce=1+q.",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_v1, verify=False,
                   nonce=1 + CURVE_ORDER))

    # Negative: wrong-election binding (signature over a different election id).
    other = bytes.fromhex("99" * 32)
    sig_other = att.sign_attestation(elig_sk, elig_vk, other, pseudonym, vk, 5, 1, k=k)
    _write("attestation", "attestation_v1_wrong_election",
           att_obj("attestation_v1_wrong_election", "Signature bound to a different electionId.",
                   weight=5, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_other, verify=False))

    # A large weight, to pin that nothing rejects it.
    sig_big = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk, 50, 1, k=k)
    # Was `attestation_v1_over_max_weight`, asserting a per-election ceiling rejected
    # weight 50. There is no ceiling now -- it constrained nothing once weights were
    # uncapped -- so the vector asserts the opposite: a large weight verifies.
    _write("attestation", "attestation_v1_large_weight",
           att_obj("attestation_v1_large_weight", "weight=50 verifies; there is no upper bound.",
                   weight=50, scheme="ATTESTATION_V1", election_id=ELECTION_ID, sig=sig_big, verify=True))



# --------------------------------------------------------------------------- #
#  Full-election flow fixture (conformance level 1: variant A / exact / weighted)
# --------------------------------------------------------------------------- #

def _run_dkg(n, quorum):
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms, shares = {}, {}
    for i, st in states.items():
        comms[i], shares[i] = st.round1(i, n, quorum)
    for i, st in states.items():
        st.round2(comms, {d: shares[d][i] for d in states})
    # Both helpers require the quorum explicitly — inferring the expected commitment
    # count from the vectors would accept a committee that all agreed on a wrong degree.
    # (This call site was stale: it predates the commitment-length guard that made the
    # argument mandatory, so the script raised TypeError before it could emit the flow
    # vector. Note the generator is NOT seeded — running it rewrites the flow vector's
    # crypto material, so regenerate deliberately, not casually.)
    mpk = derive_joint_mpk(comms, quorum)
    committee = {i: derive_mpk_share(i, comms, quorum) for i in states}
    return mpk, committee, states


def gen_flow():
    n, t, budget, num_candidates = 3, 2, 3, 3  # t IS the quorum: 2-of-3
    mpk, committee, states = _run_dkg(n, t)
    mpk_bytes = g2_to_compressed(mpk)
    committee_pks = tuple(g2_to_compressed(committee[i]) for i in range(1, n + 1))

    elig_sk, elig_vk = schnorr.keygen()
    elig_key = g1_to_compressed(elig_vk)

    config = ElectionConfig(
        election_id=ELECTION_ID, num_candidates=num_candidates, budget=budget, mode=Mode.EXACT,
        variant=Variant.A, weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1000, voting_end=2000, threshold=Threshold(t=t, n=n),
        keypers=tuple(KeyperIdentity(signing_key=bytes([i]) * 20, url="") for i in range(n)),
        eligibility_key=elig_key, result_publisher_key=b"\xa1" * 20, gateway_keys=(b"\x91" * 20,),
        admin_key=b"\xad" * 20, protocol_version="SHUTTER-VOTE-v1",
    )

    def make_ballot(votes, pseudonym, weight, *, nonce=1, tamper_sig=False):
        sk, vk = schnorr.keygen()
        vk_b = g1_to_compressed(vk)
        # Minted first: since v2 the voter's signature covers the credential.
        a = att.sign_attestation(elig_sk, elig_vk, ELECTION_ID, pseudonym, vk_b, weight, nonce)
        att_obj = Attestation(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vk_b, weight=weight,
                              signature=a, scheme=AttestationScheme.V1, nonce=nonce)
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=ELECTION_ID, pseudonym=pseudonym,
                                           sk=sk, vk=vk, attestation=att_obj, votes=votes,
                                           num_candidates=num_candidates, budget=budget)
        sig = built.voter_signature
        if tamper_sig:
            b = bytearray(sig); b[-1] ^= 0x01; sig = bytes(b)
        return BallotEnvelope(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vk_b,
                              ciphertexts=tuple(Ciphertext(c1=c[0], c2=c[1]) for c in built.ciphertexts),
                              zk_proof=built.zk_proof, voter_signature=sig, attestation=att_obj)

    P1, P2, P3, P4 = (bytes([x]) * 32 for x in (0xA1, 0xA2, 0xA3, 0xA4))
    stored = [
        StoredBallot(0, make_ballot([3, 0, 0], P1, 2, nonce=1)),                 # P1 first vote (nonce 1)
        StoredBallot(1, make_ballot([0, 3, 0], P2, 3, nonce=1)),                 # valid, weight 3
        StoredBallot(2, make_ballot([1, 1, 1], P3, 1, nonce=1, tamper_sig=True)),  # invalid signature
        StoredBallot(3, make_ballot([0, 0, 3], P1, 2, nonce=2)),                 # P1 re-vote (nonce 2 wins)
        StoredBallot(4, make_ballot([1, 1, 1], P4, 1, nonce=1)),                 # valid, weight 1
    ]

    admission = admit(stored, config, mpk_bytes)
    aggregate = build_aggregate_artifact(config, admission)

    # Keypers t+1 partially decrypt the aggregate.
    shares = []
    for i in (1, 2):
        entries = []
        for j, ct in enumerate(aggregate.aggregates):
            c1 = g2_from_compressed(ct.c1); c2 = g2_from_compressed(ct.c2)
            sigma = states[i].partial_decrypt(c1)
            tr = proofs.make_decrypt_transcript(ELECTION_ID, j)
            e, z = proofs.prove_decryption_share(tr, c1, c2, committee[i], sigma, states[i].combined_share, i)
            entries.append(DecryptionShareEntry(sigma=g2_to_compressed(sigma), proof=proofs.encode_dleq(e, z)))
        shares.append(DecryptionShareEnvelope(election_id=ELECTION_ID, keyper_index=i, entries=tuple(entries)))

    result = recover_result(config, aggregate, shares, committee_pks, t)

    fixture = {
        "name": "full_election_level1",
        "description": "Complete variant-A/exact/weighted election: 5 ballots (1 invalid, 1 duplicate), "
                       "t+1 shares, replayable to the published aggregate + result.",
        "version": 1,
        "config": codecs.enc_config(config),
        "finalizedKey": {"pkElection": mpk_bytes.hex(), "committeePKs": [p.hex() for p in committee_pks]},
        "ballots": [codecs.enc_ballot(sb.envelope) for sb in stored],
        "aggregate": codecs.enc_aggregate(aggregate),
        "shares": [codecs.enc_decryption_share(s) for s in shares],
        "result": codecs.enc_result(result),
    }
    _write("flow", "full_election_level1", fixture)


# --------------------------------------------------------------------------- #
#  Ballot vectors (the v2 signed message; cross-language)
# --------------------------------------------------------------------------- #

def gen_ballot():
    """Vectors for the v2 ballot, so the SDK can prove it agrees byte-for-byte.

    This corpus is the **only** cross-language lock on the ballot message. Its v1
    predecessor was generated once and hand-maintained on both sides, which is how the
    aggregate digest drifted: both halves went stale together and every test passed.
    Regenerate here and copy into the SDK in the same change -- never one without the
    other.

    A negative case is included on purpose: `ballot_swapped_credential` carries a
    credential the issuer genuinely signed, for the same voter and election, but with a
    different weight. Under v1 that verified, because the credential sat outside the
    signed message. It must now fail. A corpus of positive cases alone would not
    notice an implementation that dropped the credential from the preimage.
    """
    from shutter_governance_protocol.crypto.points import g2_to_compressed as _g2c

    ELECTION = b"\xe1" * 32
    PSEUDO = b"\x42" * 32
    elig_sk, elig_vk = schnorr.keygen(0xE11A)
    mpk_sk = 0xB0B
    mpk = mul(G2, mpk_sk)

    def case(name, desc, *, votes, budget, weight, nonce, mutate=None, verify=True):
        sk, vk = schnorr.keygen()
        vk_b = g1_to_compressed(vk)
        a = att.sign_attestation(elig_sk, elig_vk, ELECTION, PSEUDO, vk_b, weight, nonce)
        att_obj = Attestation(election_id=ELECTION, pseudonym=PSEUDO, vk=vk_b,
                              weight=weight, signature=a, scheme=AttestationScheme.V1,
                              nonce=nonce)
        built = ballot_crypto.build_ballot(
            mpk=mpk, election_id=ELECTION, pseudonym=PSEUDO, sk=sk, vk=vk,
            attestation=att_obj, votes=votes, num_candidates=len(votes), budget=budget)
        wire_att = att_obj
        if mutate is not None:
            wire_att = mutate(att_obj, elig_sk, elig_vk, vk_b)
        _write("ballot", name, {
            "name": name,
            "description": desc,
            "version": 2,
            "inputs": {
                "mpk": _g2c(mpk).hex(),
                "vk": vk_b.hex(),
                "election_id": ELECTION.hex(),
                "pseudonym": PSEUDO.hex(),
                "eligibility_key": g1_to_compressed(elig_vk).hex(),
                "params": {"numCandidates": len(votes), "budget": budget,
                           "mode": "exact", "variant": "A"},
                "ciphertexts": [{"c1": c1.hex(), "c2": c2.hex()}
                                for (c1, c2) in built.ciphertexts],
                "zkProof": built.zk_proof.hex(),
                "signature": built.voter_signature.hex(),
                "attestation": {
                    "electionId": wire_att.election_id.hex(),
                    "pseudonym": wire_att.pseudonym.hex(),
                    "vk": wire_att.vk.hex(),
                    "weight": wire_att.weight,
                    "nonce": wire_att.nonce,
                    "signature": wire_att.signature.hex(),
                },
            },
            "expected": {"verify": verify},
        })

    case("ballot_variantA_exact",
         "Full ballot: Variant A, exact, l=3, B=3, votes [1,1,1], weight 5. Must verify.",
         votes=[1, 1, 1], budget=3, weight=5, nonce=1)

    def _reweight(a, esk, evk, vk_b):
        sig = att.sign_attestation(esk, evk, ELECTION, PSEUDO, vk_b, 99, a.nonce)
        return Attestation(election_id=a.election_id, pseudonym=a.pseudonym, vk=a.vk,
                           weight=99, signature=sig, scheme=a.scheme, nonce=a.nonce)

    case("ballot_swapped_credential",
         "Credential swapped for another the issuer signed (weight 99). Verified under "
         "v1; must fail under v2, where the voter's signature covers the credential.",
         votes=[1, 1, 1], budget=3, weight=5, nonce=1, mutate=_reweight, verify=False)


if __name__ == "__main__":
    import sys

    # Named targets, because the generator is unseeded: regenerating a category
    # rewrites its crypto material, so a schema change to one fixture must not
    # churn the others as a side effect.
    targets = sys.argv[1:] or ["attestation", "ballot", "flow"]
    for name in targets:
        {"attestation": gen_attestation, "ballot": gen_ballot, "flow": gen_flow}[name]()
