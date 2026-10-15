"""End-to-end service flows on the in-memory adapter.

Drives a full election through the actual services — admin → coordinator (DKG +
tally) → gateway → keypers → auditor — plus the security-relevant negative cases
(keyper preconditions, gateway filter, admin lead-time gate, auditor tamper
detection).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.aggregation import check_result
from shutter_governance_protocol.envelopes.types import ExclusionReason, StoredBallot
from shutter_governance_protocol.ports.data_layer import VotingWindowError
from shutter_governance_protocol.services import admin, auditor
from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord
from shutter_governance_protocol.services import tally_aggregator as agg
from shutter_governance_protocol.services.gateway import GatewayRejection, submit_ballot
from shutter_governance_protocol.services.keyper import KeyperRefusal

DKG_LEAD_TIME = 100


def _register_and_dkg(fe):
    admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)
    ok = coord.ensure_dkg(
        fe.config.election_id, fe.keypers, fe.dl, n=fe.n, t=fe.t,
        clock=fe.clock, deadline=fe.config.voting_start,
    )
    assert ok
    assert fe.dl.get_finalized_key(fe.config.election_id) is not None


# --------------------------------------------------------------------------- #
#  Happy path
# --------------------------------------------------------------------------- #

def test_full_single_choice_election(full_env):
    fe = full_env
    _register_and_dkg(fe)

    # Voting window.
    fe.clock.set(1_500)
    votes = [[3, 0, 0], [0, 3, 0], [0, 3, 0], [0, 0, 3]]
    for i, v in enumerate(votes):
        submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot(v, bytes([i + 1]) * 32), clock=fe.clock, gateway_signer=fe.gateway)
    assert fe.dl.count_ballots(fe.config.election_id) == 4

    # Tally.
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    assert result is not None
    # candidate totals: cand0=3, cand1=6, cand2=3
    assert list(result.totals) == [3, 6, 3]

    # Auditor confirms everything from public reads.
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert report.ok, report.discrepancies


def test_full_weighted_election(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=fe.clock, gateway_signer=fe.gateway)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    # [2*3, 5*3, 0] = [6, 15, 0]
    assert list(result.totals) == [6, 15, 0]
    assert auditor.audit(fe.dl, fe.config.election_id).ok


# --------------------------------------------------------------------------- #
#  Admin lead-time gate
# --------------------------------------------------------------------------- #

def test_registration_rejected_without_lead_time(full_env):
    fe = full_env
    fe.clock.set(950)  # voting_start=1000, lead time 100 → only 50 left
    with pytest.raises(admin.RegistrationError, match="too soon for DKG"):
        admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)


# --------------------------------------------------------------------------- #
#  Gateway filter + window
# --------------------------------------------------------------------------- #

def test_gateway_rejects_outside_voting_window(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(500)  # before voting_start → not Voting
    with pytest.raises(GatewayRejection, match="voting is not open"):
        submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)


def test_gateway_filter_rejects_malformed_ballot(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    b = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    bad_sig = bytearray(b.voter_signature); bad_sig[-1] ^= 1
    b = replace(b, voter_signature=bytes(bad_sig))
    with pytest.raises(GatewayRejection):
        submit_ballot(fe.dl, fe.config.election_id, b, clock=fe.clock, gateway_signer=fe.gateway)


def test_gateway_filter_off_admits_but_tally_still_excludes(full_env):
    """A compromised/disabled filter can inject an invalid ballot; the tally is
    unaffected because verification is authoritative at tally time."""
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    good = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    bad = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    bad_sig = bytearray(bad.voter_signature); bad_sig[-1] ^= 1
    bad = replace(bad, voter_signature=bytes(bad_sig))
    submit_ballot(fe.dl, fe.config.election_id, good, clock=fe.clock, gateway_signer=fe.gateway)
    submit_ballot(fe.dl, fe.config.election_id, bad, clock=fe.clock, gateway_signer=fe.gateway, filter_on=False)  # injected
    assert fe.dl.count_ballots(fe.config.election_id) == 2

    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    # only the good ballot counts
    assert list(result.totals) == [3, 0, 0]
    agg_artifact = fe.dl.get_aggregate(fe.config.election_id)
    assert agg_artifact.admitted == (0,)
    assert len(agg_artifact.exclusions) == 1


def test_data_layer_rejects_ballot_outside_voting_window(full_env):
    """Prevention half: the storage layer itself refuses an out-of-window ballot,
    so the bypassable gateway is no longer the only thing standing between a late
    submission and the tally. Parity with the chain contract's VotingClosed revert."""
    fe = full_env
    _register_and_dkg(fe)
    late = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    # Authorized as the registered gateway, so what is under test is the WINDOW gate and
    # not the gateway writer check that now precedes it.
    sig = write_auth.sign_ballot(fe.gateway.private_key, fe.config.election_id, late)

    fe.clock.set(2_500)  # past voting_end
    with pytest.raises(VotingWindowError):
        fe.dl.submit_ballot(fe.config.election_id, late, sig)

    fe.clock.set(500)  # before voting_start
    with pytest.raises(VotingWindowError):
        fe.dl.submit_ballot(fe.config.election_id, late, sig)

    assert fe.dl.count_ballots(fe.config.election_id) == 0


def test_out_of_band_out_of_window_ballot_is_excluded_at_tally(full_env):
    """Auditability half: a row that reaches storage *bypassing* the write gate
    (direct SQL, a second writer, a restored backup) is still excluded at tally time,
    because admission re-derives the window from the adapter's recorded receive time.
    Before this fix the row carried no receive time, so the check was skipped and the
    late ballot was silently counted."""
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    good = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    submit_ballot(fe.dl, fe.config.election_id, good, clock=fe.clock, gateway_signer=fe.gateway)

    # Inject the way a bypass would: straight into storage, stamped after voting_end.
    late = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    stored = fe.dl._elections[fe.config.election_id]
    stored.ballots.append(
        StoredBallot(sequence_number=len(stored.ballots), envelope=late, submitted_at=2_400)
    )
    assert fe.dl.count_ballots(fe.config.election_id) == 2

    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)

    assert list(result.totals) == [3, 0, 0]  # the late ballot did not count
    agg_artifact = fe.dl.get_aggregate(fe.config.election_id)
    assert agg_artifact.admitted == (0,)
    assert [x.reason for x in agg_artifact.exclusions] == [ExclusionReason.OUT_OF_WINDOW]
    # And an auditor reading only public data reproduces the same exclusion.
    assert auditor.audit(fe.dl, fe.config.election_id).ok


# --------------------------------------------------------------------------- #
#  Keyper preconditions — never trust the trigger
# --------------------------------------------------------------------------- #

def test_keyper_refuses_before_voting_ends(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)  # still Voting
    with pytest.raises(KeyperRefusal, match="not tallying"):
        fe.keypers[0].decrypt_and_submit(fe.config.election_id)


def test_keyper_refuses_without_aggregate(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(2_500)  # Tallying, but no aggregate published yet
    with pytest.raises(KeyperRefusal, match="no aggregate"):
        fe.keypers[0].decrypt_and_submit(fe.config.election_id)


def test_keyper_decryption_is_idempotent(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.trigger_aggregate(fe.keypers, fe.config.election_id)
    fe.keypers[0].decrypt_and_submit(fe.config.election_id)
    fe.keypers[0].decrypt_and_submit(fe.config.election_id)  # no-op
    mine = [s for s in fe.dl.list_decryption_shares(fe.config.election_id) if s.keyper_index == 1]
    assert len(mine) == 1


# --------------------------------------------------------------------------- #
#  Auditor tamper detection
# --------------------------------------------------------------------------- #

def test_auditor_detects_tampered_result(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)

    # Forge a wrong result directly in storage (simulating a malicious data layer).
    stored = fe.dl._elections[fe.config.election_id]
    stored.result = replace(stored.result, totals=(9, 9, 9))
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert not report.ok
    # The audit checks the published totals rather than re-deriving them, so the
    # discrepancy names the failing total. Asserting the `result:` prefix rather than
    # exact prose keeps this pinned to the guarantee, not the wording.
    assert any(d.startswith("result:") for d in report.discrepancies)
    # Shares were fine; only the totals were forged. The report must say so, or an
    # operator cannot tell a lying publisher from a committee that never delivered.
    assert report.shares_ok


def test_auditor_detects_tampered_aggregate(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.trigger_aggregate(fe.keypers, fe.config.election_id)

    # Tamper: claim no ballots were admitted (simulating a malicious data layer that
    # rewrites the quorum-canonical aggregate under every keyper's submission).
    stored = fe.dl._elections[fe.config.election_id]
    tampered = replace(fe.dl.get_aggregate(fe.config.election_id), admitted=())
    stored.aggregate_by_keyper = {i: tampered for i in stored.aggregate_by_keyper}
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert not report.aggregate_ok
    assert any("admitted set differs" in d for d in report.discrepancies)


# --------------------------------------------------------------------------- #
#  check_result — verifying published totals without re-solving
# --------------------------------------------------------------------------- #


def _tallied(fe):
    """Run a one-ballot election to completion and return the check_result inputs."""
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32),
                  clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    eid = fe.config.election_id
    return (
        fe.config,
        fe.dl.get_aggregate(eid),
        fe.dl.list_decryption_shares(eid),
        fe.dl.get_finalized_key(eid).committee_pks,
        fe.config.threshold.t,
    )


def test_check_result_accepts_the_published_totals(full_env):
    cfg, aggregate, shares, pks, quorum = _tallied(full_env)
    published = full_env.dl.get_result(cfg.election_id)
    assert published.totals == (1, 1, 1)
    ok, reason = check_result(cfg, aggregate, shares, pks, quorum, published.totals)
    assert ok and reason is None


def test_check_result_rejects_totals_above_the_bound(full_env):
    """The range guard, and the cheapest of the three checks.

    Budget 3 x one weight-1 ballot puts the bound at 3, so (9, 9, 9) never reaches the
    group arithmetic. This is also what stops a publisher offering `T + q`, which is
    the same group element as `T` and would satisfy the equality.
    """
    cfg, aggregate, shares, pks, quorum = _tallied(full_env)
    ok, reason = check_result(cfg, aggregate, shares, pks, quorum, (9, 9, 9))
    assert not ok
    assert reason.startswith("result:") and "outside [0, 3]" in reason


def test_check_result_rejects_wrong_totals_that_sum_correctly(full_env):
    """The case the sum identity alone would miss.

    (3, 0, 0) sums to the bound exactly, like the true (1, 1, 1), so only the
    per-candidate equality separates them.
    """
    cfg, aggregate, shares, pks, quorum = _tallied(full_env)
    ok, reason = check_result(cfg, aggregate, shares, pks, quorum, (3, 0, 0))
    assert not ok
    assert "does not decrypt the aggregate" in reason


def test_check_result_rejects_totals_that_do_not_sum_to_the_bound(full_env):
    """The identity check, which pins the vector as a whole.

    Every admitted ballot spends its whole budget in exact mode, so the totals must
    sum to `budget x total admitted weight`. (1, 1, 0) decrypts two candidates
    correctly and still cannot be the result.
    """
    cfg, aggregate, shares, pks, quorum = _tallied(full_env)
    ok, reason = check_result(cfg, aggregate, shares, pks, quorum, (1, 1, 0))
    assert not ok
    assert reason.startswith("result:")


def test_check_result_reports_share_failures_separately(full_env):
    """`shares:` and `result:` must be distinguishable.

    A committee that never produced a quorum is an availability problem; a publisher
    with wrong totals is an integrity problem. They need different responses, so the
    reason prefix has to tell them apart.
    """
    cfg, aggregate, shares, pks, quorum = _tallied(full_env)
    ok, reason = check_result(cfg, aggregate, shares[:quorum - 1], pks, quorum, (1, 1, 1))
    assert not ok
    assert reason.startswith("shares:")


def test_check_result_rejects_a_totals_vector_of_the_wrong_length(full_env):
    cfg, aggregate, shares, pks, quorum = _tallied(full_env)
    ok, reason = check_result(cfg, aggregate, shares, pks, quorum, (1, 1))
    assert not ok
    assert reason.startswith("result:") and "2 totals published for 3 candidates" in reason


def test_wei_scale_weights_survive_the_json_wire_and_tally_exactly(full_env):
    """Token weights in wei (~1.2 tokens here) used to travel as JSON numbers, which a
    browser rounds above 2^53, so the voter signed a different weight from the issuer's.
    They now travel as decimal strings. A JSON round trip must preserve the weight
    exactly, the ballot must be admitted, and the published artifacts must round-trip too."""
    import json

    from shutter_governance_protocol.envelopes import codecs

    fe = full_env
    fe.config = replace(fe.config, scale=10**15)  # tally in milli-tokens, as a token election would
    _register_and_dkg(fe)
    fe.clock.set(1500)
    w1, w2 = 1_234_567_890_123_456_789, 25 * 10**21 + 7
    for votes, pseudonym, w in (([3, 0, 0], b"\x01" * 32, w1), ([0, 3, 0], b"\x02" * 32, w2)):
        wire = json.loads(json.dumps(codecs.enc_ballot(fe.voter_ballot(votes, pseudonym, weight=w))))
        assert wire["attestation"]["weight"] == str(w)
        submit_ballot(fe.dl, fe.config.election_id, codecs.dec_ballot(wire), clock=fe.clock, gateway_signer=fe.gateway)

    fe.clock.set(2500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    s1, s2 = (w1 + 5 * 10**14) // 10**15, (w2 + 5 * 10**14) // 10**15  # half-up scaled weights
    assert list(result.totals) == [3 * s1, 3 * s2, 0]
    aggregate = fe.dl.get_aggregate(fe.config.election_id)
    assert aggregate.total_admitted_weight == w1 + w2
    assert codecs.dec_aggregate(json.loads(json.dumps(codecs.enc_aggregate(aggregate)))) == aggregate
    assert codecs.dec_result(json.loads(json.dumps(codecs.enc_result(result)))) == result


def test_auditor_accepts_an_honest_scaled_election(full_env):
    """The auditor's last check derived the search bound from the raw admitted weight, but
    the tally searches budget × Σ(scaled weights). Every honest election with scale > 1
    was reported as failing."""
    fe = full_env
    fe.config = replace(fe.config, scale=2)
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32, weight=3), clock=fe.clock, gateway_signer=fe.gateway)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    assert result.bsgs_bound == 3 * (2 + 3)  # budget × (scaled 3→2 + scaled 5→3)
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert report.ok, report.discrepancies
