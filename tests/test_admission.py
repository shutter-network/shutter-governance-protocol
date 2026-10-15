"""Ballot admission: happy path, every exclusion reason, duplicate policies, determinism."""

from __future__ import annotations

from dataclasses import replace

from shutter_governance_protocol.core.admission import StoredBallot, admit
from shutter_governance_protocol.core.config import DuplicatePolicy
from shutter_governance_protocol.envelopes.types import Attestation, AttestationScheme, ExclusionReason

P1 = b"\xa1" * 32
P2 = b"\xa2" * 32
P3 = b"\xa3" * 32


def _stored(env, seq, votes, pseudonym, **kw):
    return StoredBallot(sequence_number=seq, envelope=env.ballot(votes, pseudonym, **kw))


def test_all_valid_admitted(env):
    cfg = env.config()
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        _stored(env, 1, [0, 3, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert len(res.admitted) == 2
    assert res.exclusions == ()
    assert res.total_admitted_weight == 2  # weight 1 each


def test_weighted_admission_sums_weights(env):
    cfg = env.config()
    ballots = [
        _stored(env, 0, [1, 0, 2], P1, weight=3),
        _stored(env, 1, [0, 3, 0], P2, weight=5),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.total_admitted_weight == 8
    assert {a.weight for a in res.admitted} == {3, 5}


def test_exclude_wrong_election_malformed(env):
    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1, election_id=b"\x99" * 32))]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.MALFORMED


def test_exclude_out_of_window(env):
    cfg = env.config()  # window [1000, 2000)
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1), submitted_at=2000)]  # at end = out
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.OUT_OF_WINDOW


def test_in_window_submitted_at_admitted(env):
    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1), submitted_at=1500)]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert len(res.admitted) == 1


def test_exclude_bad_attestation_signature(env):
    cfg = env.config()
    b = env.ballot([1, 0, 2], P1)
    bad_sig = bytearray(b.attestation.signature)
    bad_sig[-1] ^= 0x01
    b = replace(b, attestation=replace(b.attestation, signature=bytes(bad_sig)))
    res = admit([StoredBallot(0, b)], cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION


def test_admits_a_large_weight_now_that_there_is_no_ceiling(env):
    """The per-election `max_weight` cap is gone, so a large weight is just a weight.

    It used to be excluded as INVALID_ATTESTATION above the ceiling. That ceiling only
    made sense while voting power was clamped; once it is not, the bound had to be set
    at least as high as the largest legitimate holder, at which point it stopped
    constraining anything. Weights are public in every ballot, so a forged one is
    visible to an auditor either way.
    """
    cfg = env.config()
    ballots = [_stored(env, 0, [1, 0, 2], P1, weight=10**9)]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.exclusions == ()
    assert res.total_admitted_weight == 10**9



def test_exclude_attestation_not_bound_to_ballot_vk(env):
    """Attestation for a different vk must not admit this ballot."""
    cfg = env.config()
    b1 = env.ballot([1, 0, 2], P1)
    b2 = env.ballot([0, 3, 0], P1)
    # Graft b2's attestation (different vk) onto b1.
    b = replace(b1, attestation=b2.attestation)
    res = admit([StoredBallot(0, b)], cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION


def test_exclude_tampered_ciphertext_invalid_proof(env):
    cfg = env.config()
    b1 = env.ballot([1, 0, 2], P1)
    b2 = env.ballot([0, 3, 0], P2)
    cts = list(b1.ciphertexts)
    cts[0] = b2.ciphertexts[0]
    b = replace(b1, ciphertexts=tuple(cts))
    res = admit([StoredBallot(0, b)], cfg, env.mpk_bytes)
    assert res.exclusions[0].reason in (ExclusionReason.INVALID_PROOF, ExclusionReason.INVALID_SIGNATURE)


def test_first_wins_duplicate_policy(env):
    cfg = env.config(duplicate_policy=DuplicatePolicy.FIRST_WINS)
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        _stored(env, 1, [0, 3, 0], P1),  # duplicate pseudonym
        _stored(env, 2, [3, 0, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted_seqs = {a.sequence_number for a in res.admitted}
    assert admitted_seqs == {0, 2}
    dup = [x for x in res.exclusions if x.reason is ExclusionReason.DUPLICATE_PSEUDONYM]
    assert [x.sequence_number for x in dup] == [1]


def test_last_wins_duplicate_policy(env):
    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        _stored(env, 1, [0, 3, 0], P1),  # duplicate; this one wins
        _stored(env, 2, [3, 0, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted_seqs = {a.sequence_number for a in res.admitted}
    assert admitted_seqs == {1, 2}
    dup = [x for x in res.exclusions if x.reason is ExclusionReason.DUPLICATE_PSEUDONYM]
    assert [x.sequence_number for x in dup] == [0]


def test_last_wins_orders_by_nonce_not_sequence(env):
    """The winner is the highest attestation nonce, regardless of submission order."""
    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    ballots = [
        _stored(env, 0, [0, 3, 0], P1, nonce=2),  # genuine re-vote (higher nonce)
        _stored(env, 1, [1, 0, 2], P1, nonce=1),  # earlier vote, submitted LATER
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted_seqs = {a.sequence_number for a in res.admitted}
    assert admitted_seqs == {0}  # the nonce-2 ballot wins even though nonce-1 came later
    dup = [x for x in res.exclusions if x.reason is ExclusionReason.DUPLICATE_PSEUDONYM]
    assert [x.sequence_number for x in dup] == [1]


def test_replayed_old_ballot_never_overrides_revote(env):
    """Replay/reordering defense: re-submitting a voter's OLD ballot at a later sequence
    cannot revert their re-vote — the higher-nonce ballot always wins. Mirrors: vote A
    (nonce 1), re-vote B (nonce 2), attacker replays A verbatim at a later sequence."""
    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    a = env.ballot([1, 0, 2], P1, nonce=1)   # first vote
    b = env.ballot([0, 3, 0], P1, nonce=2)   # genuine re-vote
    ballots = [
        StoredBallot(0, a),
        StoredBallot(1, b),
        StoredBallot(2, a),  # attacker replays the OLD ballot verbatim, later
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted = res.admitted
    assert len(admitted) == 1
    assert admitted[0].sequence_number == 1  # the nonce-2 re-vote, not the replayed nonce-1


def test_invalid_ballot_not_counted_as_duplicate(env):
    """A crypto-invalid ballot gets its crypto reason, never DUPLICATE."""
    cfg = env.config(duplicate_policy=DuplicatePolicy.FIRST_WINS)
    good = env.ballot([1, 0, 2], P1)
    bad = env.ballot([0, 3, 0], P1)
    bad_sig = bytearray(bad.voter_signature)
    bad_sig[-1] ^= 0x01
    bad = replace(bad, voter_signature=bytes(bad_sig))
    res = admit([StoredBallot(0, good), StoredBallot(1, bad)], cfg, env.mpk_bytes)
    assert {a.sequence_number for a in res.admitted} == {0}
    assert res.exclusions[0].reason in (ExclusionReason.INVALID_SIGNATURE, ExclusionReason.MALFORMED)


def test_admission_is_deterministic(env):
    cfg = env.config()
    ballots = [_stored(env, 0, [1, 0, 2], P1), _stored(env, 1, [0, 3, 0], P2)]
    r1 = admit(ballots, cfg, env.mpk_bytes)
    r2 = admit(ballots, cfg, env.mpk_bytes)
    assert [a.sequence_number for a in r1.admitted] == [a.sequence_number for a in r2.admitted]
    assert r1.exclusions == r2.exclusions


# --------------------------------------------------------------------------- #
#  Non-canonical weight / nonce (credential value >= q)
# --------------------------------------------------------------------------- #

def _self_signed(env, votes, pseudonym, *, weight=1, nonce=1, claimed_weight=None, claimed_nonce=None):
    """A voter holding a genuine (weight, nonce) credential edits it, then signs the
    ballot over the edited credential with their own key, as a real attacker would."""
    from shutter_governance_protocol.crypto import attestation as att_crypto
    from shutter_governance_protocol.crypto import ballot as ballot_crypto
    from shutter_governance_protocol.crypto import schnorr
    from shutter_governance_protocol.crypto.points import g1_to_compressed
    from shutter_governance_protocol.envelopes.types import BallotEnvelope, Ciphertext

    sk, vk = schnorr.keygen()
    vk_bytes = g1_to_compressed(vk)
    _, elig_vk = schnorr.keygen(env.elig_sk)
    sig = att_crypto.sign_attestation(env.elig_sk, elig_vk, env_eid(env), pseudonym, vk_bytes, weight, nonce)
    att = Attestation(
        election_id=env_eid(env), pseudonym=pseudonym, vk=vk_bytes,
        weight=weight if claimed_weight is None else claimed_weight,
        signature=sig, nonce=nonce if claimed_nonce is None else claimed_nonce,
    )
    built = ballot_crypto.build_ballot(
        mpk=env.mpk_point, election_id=env_eid(env), pseudonym=pseudonym, sk=sk, vk=vk,
        attestation=att, votes=votes, num_candidates=len(votes), budget=3,
    )
    return BallotEnvelope(
        election_id=env_eid(env), pseudonym=pseudonym, vk=vk_bytes,
        ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
        zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
    )


def env_eid(env):
    return env.config().election_id


def test_voter_cannot_inflate_own_weight_by_curve_order(env):
    """Weight 1 signed, ``1 + q`` claimed and voter-signed: excluded, and the total weight
    (hence the BSGS bound) stays honest, so the tally remains solvable."""
    from shutter_governance_protocol.crypto.params import CURVE_ORDER

    cfg = env.config()
    bad = _self_signed(env, [3, 0, 0], P1, weight=1, claimed_weight=1 + CURVE_ORDER)
    ok = _stored(env, 1, [0, 3, 0], P2)
    res = admit([StoredBallot(0, bad), ok], cfg, env.mpk_bytes)
    assert [a.sequence_number for a in res.admitted] == [1]
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION
    assert res.total_admitted_weight == 1


def test_oversized_weight_on_stored_ballot_is_excluded_not_a_crash(env):
    """Anyone who can store a ballot sets weight to ``w + 3q`` (> 2^256), no re-signing.
    It used to raise OverflowError out of admit() and halt every keyper."""
    from shutter_governance_protocol.crypto.params import CURVE_ORDER

    cfg = env.config()
    good = env.ballot([1, 0, 2], P1)
    bad = replace(good, attestation=replace(good.attestation, weight=1 + 3 * CURVE_ORDER))
    res = admit([StoredBallot(0, bad), _stored(env, 1, [0, 3, 0], P2)], cfg, env.mpk_bytes)
    assert [a.sequence_number for a in res.admitted] == [1]
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION


def test_oversized_nonce_does_not_lock_in_a_ballot(env):
    """Nonce 1 signed, ``1 + q`` claimed: excluded, so the voter's genuine nonce-2 re-vote
    still wins under last-wins."""
    from shutter_governance_protocol.crypto.params import CURVE_ORDER

    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    locked = _self_signed(env, [3, 0, 0], P1, nonce=1, claimed_nonce=1 + CURVE_ORDER)
    revote = env.ballot([0, 0, 3], P1, nonce=2)
    res = admit([StoredBallot(0, locked), StoredBallot(1, revote)], cfg, env.mpk_bytes)
    assert [a.sequence_number for a in res.admitted] == [1]
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION


def test_unencodable_credential_is_malformed_in_ballot_crypto(env):
    """Defense in depth below admission: ``verify_ballot_crypto`` alone must not raise on
    a credential too large for the 32-byte ballot-message field."""
    from shutter_governance_protocol.crypto.ballot import verify_ballot_crypto

    b = env.ballot([1, 0, 2], P1)
    att = replace(b.attestation, weight=2**256)
    ok, reason = verify_ballot_crypto(
        mpk=env.mpk_point, election_id=b.election_id, pseudonym=b.pseudonym, vk_bytes=b.vk,
        ciphertext_bytes=[(ct.c1, ct.c2) for ct in b.ciphertexts], zk_proof=b.zk_proof,
        voter_signature=b.voter_signature, attestation=att, num_candidates=3, budget=3, mode="exact",
    )
    assert (ok, reason) == (False, "MALFORMED")


def test_undecodable_record_is_excluded_as_malformed(env):
    """A stored record with no decodable envelope is MALFORMED and does not disturb the
    rest of the admission."""
    cfg = env.config()
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        StoredBallot(1, None, malformed_reason="JSONDecodeError: Expecting value"),
        _stored(env, 2, [0, 3, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert [a.sequence_number for a in res.admitted] == [0, 2]
    assert [(x.sequence_number, x.reason) for x in res.exclusions] == [(1, ExclusionReason.MALFORMED)]


def test_dec_stored_ballot_never_raises():
    from shutter_governance_protocol.envelopes.codecs import dec_stored_ballot

    for bad in (None, {}, [], 7, "x", {"attestation": []}):
        envelope, reason = dec_stored_ballot(bad)
        assert envelope is None and reason


# --------------------------------------------------------------------------- #
#  One per voter: weight must be 1 in an unweighted election
# --------------------------------------------------------------------------- #

def test_unweighted_election_excludes_a_credential_above_weight_1(env):
    """`weighted=False` used to be enforced only through a max_weight ceiling of 1; once
    that ceiling was removed nothing read the flag, and a weight-79 credential counted 79
    times in a one-per-voter election."""
    cfg = env.config(weighted=False)
    ballots = [_stored(env, 0, [3, 0, 0], P1, weight=79), _stored(env, 1, [0, 3, 0], P2, weight=1)]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert [a.sequence_number for a in res.admitted] == [1]
    assert [(x.sequence_number, x.reason) for x in res.exclusions] == [(0, ExclusionReason.INVALID_ATTESTATION)]
    assert res.total_admitted_weight == 1


def test_weighted_election_admits_any_signed_weight(env):
    cfg = env.config(weighted=True)
    ballots = [_stored(env, 0, [3, 0, 0], P1, weight=79), _stored(env, 1, [0, 3, 0], P2, weight=1)]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.total_admitted_weight == 80 and res.exclusions == ()
