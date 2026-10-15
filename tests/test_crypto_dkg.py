"""DKG + threshold decryption end-to-end at the crypto layer.

Runs a full Feldman VSS ceremony among n keypers, checks the derived joint key
matches the sum of public shares, then encrypts a homomorphic aggregate and
recovers it from a quorum of partial decryptions with DLEQ-verified shares.
"""

from __future__ import annotations

from shutter_governance_protocol.crypto import elgamal, proofs
from shutter_governance_protocol.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from shutter_governance_protocol.crypto.params import ONCHAIN_DECRYPT_LABEL
from shutter_governance_protocol.crypto.points import G2, mul
from shutter_governance_protocol.crypto.recovery import threshold_decrypt
from shutter_governance_protocol.crypto.transcript import Transcript


def run_dkg(n: int, quorum: int):
    """Simulate a full DKG. Returns (mpk, committee_pks, states, all_commitments).

    ``quorum`` is the number of keypers required to decrypt (config ``threshold.t``),
    so a 2-of-3 committee is ``run_dkg(n=3, quorum=2)``.
    """
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    all_commitments, all_shares = {}, {}
    for i, st in states.items():
        comms, shares = st.round1(i, n, quorum)
        all_commitments[i] = comms
        all_shares[i] = shares
    for i, st in states.items():
        received = {dealer: all_shares[dealer][i] for dealer in states}
        st.round2(all_commitments, received)
    mpk = derive_joint_mpk(all_commitments, quorum)
    committee_pks = {i: derive_mpk_share(i, all_commitments, quorum) for i in states}
    return mpk, committee_pks, states, all_commitments


def test_dkg_joint_key_matches_public_shares():
    mpk, committee_pks, states, _ = run_dkg(n=3, quorum=2)
    # Each keyper's public share equals combined_share * P2.
    for i, st in states.items():
        assert committee_pks[i] == mul(G2, st.combined_share)
        assert st.public_key_share == committee_pks[i]


def test_threshold_decrypt_recovers_aggregate():
    mpk, committee_pks, states, _ = run_dkg(n=3, quorum=2)
    # Homomorphic aggregate of votes 2 + 3 + 4 = 9 under mpk.
    cts = [elgamal.encrypt(mpk, v)[:2] for v in (2, 3, 4)]
    c1_sum, c2_sum = elgamal.sum_cts(cts)

    # A quorum of 2 keypers each partially decrypt the aggregate C1.
    used = [1, 2]
    shares = [(i, states[i].partial_decrypt(c1_sum)) for i in used]
    recovered = threshold_decrypt(c1_sum, c2_sum, shares, max_val=100)
    assert recovered == 9


def test_any_quorum_sized_subset_recovers_same_value():
    mpk, committee_pks, states, _ = run_dkg(n=3, quorum=2)
    c1_sum, c2_sum = elgamal.sum_cts([elgamal.encrypt(mpk, 7)[:2]])
    results = set()
    for subset in ([1, 2], [1, 3], [2, 3]):
        shares = [(i, states[i].partial_decrypt(c1_sum)) for i in subset]
        results.add(threshold_decrypt(c1_sum, c2_sum, shares, max_val=50))
    assert results == {7}


def test_decryption_share_dleq_verifies():
    mpk, committee_pks, states, _ = run_dkg(n=3, quorum=2)
    c1, c2 = elgamal.sum_cts([elgamal.encrypt(mpk, 5)[:2]])
    i = 1
    msk_k = states[i].combined_share
    mpk_k = committee_pks[i]
    sigma = states[i].partial_decrypt(c1)

    t = Transcript(ONCHAIN_DECRYPT_LABEL)
    e, z = proofs.prove_decryption_share(t, c1, c2, mpk_k, sigma, msk_k, keyper_index=i)

    tv = Transcript(ONCHAIN_DECRYPT_LABEL)
    assert proofs.verify_decryption_share(tv, c1, c2, mpk_k, sigma, e, z, keyper_index=i)


def test_decryption_share_dleq_rejects_wrong_sigma():
    mpk, committee_pks, states, _ = run_dkg(n=3, quorum=2)
    c1, c2 = elgamal.sum_cts([elgamal.encrypt(mpk, 5)[:2]])
    i = 1
    msk_k = states[i].combined_share
    mpk_k = committee_pks[i]
    sigma = states[i].partial_decrypt(c1)
    t = Transcript(ONCHAIN_DECRYPT_LABEL)
    e, z = proofs.prove_decryption_share(t, c1, c2, mpk_k, sigma, msk_k, keyper_index=i)

    wrong_sigma = mul(sigma, 2)
    tv = Transcript(ONCHAIN_DECRYPT_LABEL)
    assert not proofs.verify_decryption_share(tv, c1, c2, mpk_k, wrong_sigma, e, z, keyper_index=i)


# --------------------------------------------------------------------------- #
#  Commitment-vector length
# --------------------------------------------------------------------------- #

def _over_long_dealer(keyper_id: int, n: int, quorum: int):
    """A malicious dealer: degree-``quorum`` polynomial with ``quorum + 1`` commitments.

    An honest dealer publishes exactly ``quorum`` commitments (degree ``quorum - 1``), so
    this is one degree too many. Every share it deals still satisfies the Feldman equation
    against this longer vector, so nothing in round 2 complains unless the LENGTH itself
    is checked.
    """
    from shutter_governance_protocol.crypto.params import CURVE_ORDER
    from shutter_governance_protocol.crypto.points import random_scalar

    coeffs = [random_scalar() for _ in range(quorum + 1)]     # one degree too many
    comms = [mul(G2, c) for c in coeffs]
    shares = {}
    for i in range(1, n + 1):
        val, x_power = 0, 1
        for c in coeffs:
            val = (val + c * x_power) % CURVE_ORDER
            x_power = (x_power * i) % CURVE_ORDER
        shares[i] = val
    return comms, shares


def test_over_long_commitments_pass_feldman_but_break_recovery():
    """Why the length check matters: the extra commitment is INVISIBLE to per-share verification.

    Each share checks out against the dealer's own over-long vector, so no keyper can
    complain on share grounds — yet the sharing polynomial is one degree too high, so no
    quorum-sized subset Lagrange-interpolates to the right secret and the tally is
    unrecoverable.
    This pins the underlying maths, independently of where the guard lives.
    """
    from shutter_governance_protocol.crypto.points import Z2, add
    from shutter_governance_protocol.crypto.recovery import combine_shares

    n, quorum = 3, 2
    comms, shares = _over_long_dealer(2, n, quorum)

    # 1. Every recipient's Feldman check passes against the over-long vector, so the
    #    fault is invisible to the complaint flow.
    for i in range(1, n + 1):
        expected, x_power = Z2, 1
        for c in comms:
            expected = add(expected, mul(c, x_power))
            x_power = x_power * i
        assert expected == mul(G2, shares[i]), "share verifies — the fault is not visible per-share"

    # 2. But `quorum` points cannot interpolate a degree-`quorum` polynomial: the combination
    #    misses φ(0)·G2 (= γ_0, the dealer's own first commitment).
    secret = comms[0]
    combined = combine_shares([(i, mul(G2, shares[i])) for i in (1, 2)])   # quorum = 2 points
    assert combined != secret, "over-long sharing must NOT interpolate from a quorum of points"

    # 3. Sanity: with quorum+1 points it DOES interpolate — confirming the failure above is the
    #    degree, not a broken test.
    assert combine_shares([(i, mul(G2, shares[i])) for i in (1, 2, 3)]) == secret


def test_round2_rejects_over_long_commitment_vector():
    """The guard. A dealer publishing quorum+1 commitments is named in bad_dealers."""
    import pytest

    n, quorum = 3, 2
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms, shares = {}, {}
    for i, st in states.items():
        c, s = st.round1(i, n, quorum)
        comms[i], shares[i] = c, s
    comms[2], shares[2] = _over_long_dealer(2, n, quorum)   # dealer 2 goes rogue

    with pytest.raises(ValueError) as ei:
        states[1].round2(comms, {d: shares[d][1] for d in states})
    assert ei.value.bad_dealers == [2]


def test_round2_rejects_short_commitment_vector():
    """The mirror case: fewer than `quorum` commitments is equally malformed."""
    import pytest

    n, quorum = 3, 3
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms, shares = {}, {}
    for i, st in states.items():
        c, s = st.round1(i, n, quorum)
        comms[i], shares[i] = c, s
    comms[3] = comms[3][:-1]  # drop a commitment → too low a degree

    with pytest.raises(ValueError) as ei:
        states[1].round2(comms, {d: shares[d][1] for d in states})
    assert ei.value.bad_dealers == [3]


def test_round2_rejects_dealer_whose_commitments_never_arrived():
    """A dealer that sends a share but no usable commitments (e.g. its vector was refused
    at ingest for being the wrong length) is disqualified rather than raising KeyError."""
    import pytest

    n, quorum = 3, 2
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms, shares = {}, {}
    for i, st in states.items():
        c, s = st.round1(i, n, quorum)
        comms[i], shares[i] = c, s
    del comms[2]  # keyper 1 refused dealer 2's commitments at ingest

    with pytest.raises(ValueError) as ei:
        states[1].round2(comms, {d: shares[d][1] for d in states})
    assert ei.value.bad_dealers == [2]


def test_derive_helpers_reject_wrong_length():
    """Last gate before a key is published: neither helper may consume a bad vector."""
    import pytest

    from shutter_governance_protocol.crypto.dkg import check_commitment_lengths

    n, quorum = 3, 2
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms = {}
    for i, st in states.items():
        comms[i], _ = st.round1(i, n, quorum)
    comms[2], _ = _over_long_dealer(2, n, quorum)

    for call in (lambda: derive_joint_mpk(comms, quorum),
                 lambda: derive_mpk_share(1, comms, quorum),
                 lambda: check_commitment_lengths(comms, quorum)):
        with pytest.raises(ValueError) as ei:
            call()
        assert ei.value.bad_dealers == [2]


def test_round2_flags_a_dealer_whose_share_never_arrived():
    """A dealer that published commitments but withheld this keyper's share used to be
    skipped silently, leaving a secret that does not match the published key."""
    import pytest

    from shutter_governance_protocol.crypto.dkg import KeyperDKGState

    states = {i: KeyperDKGState() for i in (1, 2, 3)}
    comms, shares = {}, {}
    for i, st in states.items():
        comms[i], shares[i] = st.round1(i, 3, 2)
    received = {1: shares[1][1], 2: shares[2][1]}  # dealer 3 withheld keyper 1's share
    with pytest.raises(ValueError) as ei:
        states[1].round2(comms, received)
    assert ei.value.bad_dealers == [3]


def test_excluding_an_equivocating_dealer_restores_every_share():
    """Dealer 3 deals polynomial A to keypers 1 and 3 and a different polynomial B to
    keyper 2. Every Feldman check passes, yet keyper 2's share does not fit the key built
    from A. Dropping dealer 3 from both the shares and the key makes all three fit."""
    from shutter_governance_protocol.crypto.dkg import (
        KeyperDKGState,
        committee_keys,
        derive_joint_mpk,
        qualified,
    )
    from shutter_governance_protocol.crypto.points import G2, eq, mul

    st = {i: KeyperDKGState() for i in (1, 2, 3)}
    c, s = {}, {}
    for i in (1, 2):
        c[i], s[i] = st[i].round1(i, 3, 2)
    cA, sA = st[3].round1(3, 3, 2)
    cB, sB = KeyperDKGState().round1(3, 3, 2)
    view = {1: {1: c[1], 2: c[2], 3: cA}, 2: {1: c[1], 2: c[2], 3: cB}, 3: {1: c[1], 2: c[2], 3: cA}}
    got = {1: {1: s[1][1], 2: s[2][1], 3: sA[1]}, 2: {1: s[1][2], 2: s[2][2], 3: sB[2]},
           3: {1: s[1][3], 2: s[2][3], 3: sA[3]}}

    # Without exclusion: no complaint, but keyper 2 cannot decrypt under key A.
    for i in (1, 2, 3):
        st[i].round2(view[i], got[i])
    keys_a = committee_keys(3, view[1], 2)
    assert not eq(keys_a[1], mul(G2, st[2].combined_share))

    # With dealer 3 excluded everywhere, every view yields the same key and every share fits.
    for i in (1, 2, 3):
        st[i].round2(view[i], got[i], dealers=[1, 2])
    pks = {i: derive_joint_mpk(qualified(view[i], {3}), 2) for i in (1, 2, 3)}
    assert eq(pks[1], pks[2]) and eq(pks[1], pks[3])
    keys = committee_keys(3, qualified(view[1], {3}), 2)
    assert len(keys) == 3
    for i in (1, 2, 3):
        assert eq(keys[i - 1], mul(G2, st[i].combined_share))
