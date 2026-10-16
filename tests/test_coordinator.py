"""Auto-DKG watcher: discovers elections needing a key via the data layer and
drives (and bootstraps) the keyper committee over HTTP.
"""

from __future__ import annotations

import threading

import pytest
from shutter_governance_protocol.core import authz
import requests
from werkzeug.serving import make_server

from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
from shutter_governance_protocol.core.authz import Signer
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.services.coordinator import AutoDKG
from shutter_governance_protocol.services.keyper import build_keyper_app

from conftest import ManualClock

N, T = 3, 2  # T is the quorum


class KeyperWorld:
    def __init__(self, tmp_path):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()
        self.admin = Signer.generate()
        self.keyper_signers = [Signer.generate() for _ in range(N)]

        self._servers = []
        self.urls = {}
        for i in range(1, N + 1):
            app = build_keyper_app(self.keyper_signers[i - 1], self.dl, self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"keyper{i}")
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            self.urls[i] = f"http://127.0.0.1:{srv.server_port}"

    def shutdown(self):
        for srv in self._servers:
            srv.shutdown()

    def register(self, *, voting_start=1000, voting_end=2000, t=T) -> bytes:
        config = ElectionConfig(
            # Assert the next id (the register replay guard); this env registers several.
            election_id=(len(self.dl.list_elections()) + 1).to_bytes(32, "big"),
            num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=voting_start, voting_end=voting_end,
            threshold=Threshold(t=t, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, url=self.urls[i + 1])
                          for i in range(N)),
            eligibility_key=b"\xe1" * 48, result_publisher_key=self.coordinator.identity,  # coordinator = result publisher
            gateway_keys=(Signer.generate().identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        return self.dl.register_election(config, self.admin.sign_register(config))

    def watcher(self):
        return AutoDKG(self.dl, self.coordinator, clock=self.clock)


@pytest.fixture
def kw(tmp_path):
    w = KeyperWorld(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def test_watcher_discovers_and_finalizes_dkg(kw):
    eid = kw.register()  # Registered (clock=0 < voting_start=1000)
    watcher = kw.watcher()

    outcomes = watcher.scan_once()
    assert outcomes[eid.hex()] == "finalized"
    assert kw.dl.get_finalized_key(eid) is not None


def test_watcher_bootstraps_the_keypers_itself(kw):
    eid = kw.register()
    # Before the watcher runs, no keyper is bootstrapped.
    assert requests.get(kw.urls[1] + "/status").json()["bootstrapped"] is False

    kw.watcher().scan_once()
    # The watcher (coordinator) installed the bearer tokens during the ceremony.
    assert requests.get(kw.urls[1] + "/status").json()["bootstrapped"] is True


def test_watcher_does_not_redrive_after_dkg(kw):
    eid = kw.register()
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    # Second pass: key finalized, election is KeyReady (pre-voting) → nothing to do
    # until it reaches Tallying. The DKG is not re-driven.
    assert watcher.scan_once()[eid.hex()] == "not_ready"


def test_watcher_marks_dkg_failed_past_voting_start(kw):
    eid = kw.register(voting_start=1000, voting_end=2000)
    kw.clock.set(1500)  # now > voting_start, still no key → terminally DKGFailed
    watcher = kw.watcher()

    assert watcher.scan_once()[eid.hex()] == "dkg_failed"
    assert kw.dl.get_finalized_key(eid) is None
    # Stays failed; not retried.
    assert watcher.scan_once()[eid.hex()] == "already_failed"


def test_watcher_drives_nearest_voting_start_first(kw, monkeypatch):
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    # Registered out of order; expect drive order sorted by voting_start ascending.
    e_far = kw.register(voting_start=3000, voting_end=4000)
    e_near = kw.register(voting_start=1000, voting_end=2000)
    e_mid = kw.register(voting_start=2000, voting_end=3000)

    driven: list[bytes] = []
    real = coord.run_dkg_http
    monkeypatch.setattr(coord, "run_dkg_http",
                        lambda eid, *a, **k: (driven.append(eid), real(eid, *a, **k))[1])

    kw.watcher().scan_once()
    assert driven == [e_near, e_mid, e_far]
    assert all(kw.dl.get_finalized_key(e) is not None for e in (e_near, e_mid, e_far))


def test_watcher_ignores_elections_not_needing_dkg(kw):
    """A second election already past its window is handled without a crash;
    a fresh Registered one still gets finalized in the same pass."""
    done = kw.register()
    kw.watcher().scan_once()  # finalize it

    fresh = kw.register()
    outcomes = kw.watcher().scan_once()
    assert outcomes[done.hex()] == "not_ready"  # KeyReady: DKG done, not yet Tallying
    assert outcomes[fresh.hex()] == "finalized"


def test_watcher_halts_and_fails_on_dkg_complaint(kw, monkeypatch):
    """A Feldman-VSS complaint during round2 is terminal: the coordinator halts before
    publishing, marks the election failed, and does not retry it. (run_dkg_http raising
    DKGComplaint is covered in test_dkg_security; here we pin AutoDKG's reaction.)"""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register()
    watcher = kw.watcher()

    def _complain(*_a, **_k):
        raise coord.DKGComplaint(
            "complaint against dealer(s) [2]",
            [{"electionId": eid.hex(), "accusedDealerIndex": 2, "recipientIndex": 1, "signature": "0xabcd"}])
    monkeypatch.setattr(coord, "run_dkg_http", _complain)  # real bootstrap, then a complaint

    assert watcher.scan_once()[eid.hex()] == "dkg_complaint"
    assert kw.dl.get_finalized_key(eid) is None            # halted before publish
    assert watcher.scan_once()[eid.hex()] == "already_failed"  # terminal, not retried


def test_watcher_abandons_tally_when_aggregate_never_reaches_quorum(kw, monkeypatch):
    """Tally has no natural deadline, so an under-quorum aggregate is bounded by
    max_tally_attempts polls, then abandoned (terminal + alert), not retriggered forever."""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"   # DKG done (clock=0)
    kw.clock.set(2500)                                     # → Tallying
    # Unreachable keypers: every trigger fails, which is what the attempt budget bounds.
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "failed", 2: "failed", 3: "failed"})

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[:-1] == ["collecting_aggregate"] * (watcher.max_tally_attempts - 1)
    assert outs[-1] == "tally_abandoned"                   # 5th attempt → abandoned (flag set)
    assert kw.dl.get_election(eid).tally_stalled is True    # persisted for the dashboard
    assert watcher.scan_once()[eid.hex()] == "tally_stalled"  # now skipped (not re-driven)
    assert kw.dl.get_result(eid) is None


def test_stall_survives_restart_and_resumes_only_on_admin_clear(kw, monkeypatch):
    """The persisted flag is authoritative: a coordinator restart does NOT resurrect a
    stalled tally (it skips). Only the admin's clear (the retry) resumes it — with a fresh
    attempt budget."""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    w1 = kw.watcher()
    assert w1.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "failed", 2: "failed", 3: "failed"})
    for _ in range(w1.max_tally_attempts):
        w1.scan_once()
    assert kw.dl.get_election(eid).tally_stalled is True

    # Restart: a fresh coordinator skips the stalled election (does NOT re-drive).
    w2 = kw.watcher()
    assert w2.scan_once()[eid.hex()] == "tally_stalled"
    assert kw.dl.get_election(eid).tally_stalled is True    # still stalled after restart

    # The admin clears it (the retry) → coordinator resumes with a fresh budget.
    kw.dl.set_tally_stalled(
        eid, False,
        kw.admin.sign("tally_resume", eid, authz.request_nonce_payload(int(kw.clock()))),
        int(kw.clock()))
    assert w2.scan_once()[eid.hex()] == "collecting_aggregate"  # resumed, retrying


def test_failed_stall_mark_is_retried_not_mistaken_for_an_admin_retry(kw, monkeypatch):
    """If writing the stalled flag fails, the abandon is still owed. It used to read the
    exhausted counter on a still-Tallying election as "the admin cleared it", reset the
    budget and re-drive the keypers, forever, without the admin ever seeing TallyStalled."""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    triggers = []
    monkeypatch.setattr(coord, "trigger_aggregate_http",
                        lambda *a, **k: (triggers.append(1), {1: "failed", 2: "failed", 3: "failed"})[1])
    real_mark, fails = kw.dl.set_tally_stalled, [2]

    def flaky_mark(eid_, stalled, *a, **k):
        if stalled and fails[0] > 0:
            fails[0] -= 1
            raise ConnectionError("data layer unreachable")
        return real_mark(eid_, stalled, *a, **k)
    monkeypatch.setattr(kw.dl, "set_tally_stalled", flaky_mark)

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[-1] == "tally_abandoned" and kw.dl.get_election(eid).tally_stalled is False  # mark failed
    n = len(triggers)
    assert watcher.scan_once()[eid.hex()] == "tally_abandoned"   # retries the mark only (fails again)
    assert watcher.scan_once()[eid.hex()] == "tally_abandoned"   # retries the mark only (lands)
    assert len(triggers) == n                                    # keypers were not re-driven
    assert kw.dl.get_election(eid).tally_stalled is True
    assert watcher.scan_once()[eid.hex()] == "tally_stalled"

    # The admin's clear is a real retry: a fresh budget of max_tally_attempts.
    kw.dl.set_tally_stalled(
        eid, False,
        kw.admin.sign("tally_resume", eid, authz.request_nonce_payload(int(kw.clock()))),
        int(kw.clock()))
    kw.clock.set(2600)  # a stall signature is single-use per timestamp; time moves on
    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[:-1] == ["collecting_aggregate"] * (watcher.max_tally_attempts - 1)
    assert outs[-1] == "tally_abandoned" and kw.dl.get_election(eid).tally_stalled is True


def test_stall_mark_that_landed_despite_an_error_still_resumes_on_first_admin_clear(kw, monkeypatch):
    """The mark write reports an error (a timeout) but actually lands. The admin's first
    clear must resume the tally, not be re-marked straight away."""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "failed", 2: "failed", 3: "failed"})
    real_mark = kw.dl.set_tally_stalled

    def lands_then_times_out(eid_, stalled, *a, **k):
        real_mark(eid_, stalled, *a, **k)
        if stalled:
            raise TimeoutError("response lost")
    monkeypatch.setattr(kw.dl, "set_tally_stalled", lands_then_times_out)
    for _ in range(watcher.max_tally_attempts):
        watcher.scan_once()
    assert watcher.scan_once()[eid.hex()] == "tally_stalled"

    kw.dl.set_tally_stalled(
        eid, False,
        kw.admin.sign("tally_resume", eid, authz.request_nonce_payload(int(kw.clock()))),
        int(kw.clock()))
    assert watcher.scan_once()[eid.hex()] == "collecting_aggregate"


def test_watcher_abandons_tally_when_decryption_never_finalizes(kw, monkeypatch):
    """A canonical aggregate forms but decryption shares never reach t+1 → the decrypt
    phase is also bounded by max_tally_attempts, then abandoned."""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_decrypt_http", lambda *a, **k: None)  # shares never land

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[-1] == "tally_abandoned"                   # aggregate finalized, decrypt stalled → abandoned
    assert kw.dl.get_aggregate(eid) is not None            # the aggregate DID reach quorum
    assert kw.dl.get_result(eid) is None                   # but no result
    assert kw.dl.get_election(eid).tally_stalled is True   # persisted


def test_working_keypers_are_not_counted_as_failed_attempts(kw, monkeypatch):
    """A slow aggregate must not look like a stalled tally.

    Aggregation runs for minutes on a large election. Before /aggregate went async the
    coordinator timed out, read that as a failed attempt, and marked TallyStalled after
    five polls — on a committee that was working perfectly.
    """
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_aggregate_http",
                        lambda *a, **k: {1: "in_progress", 2: "in_progress", 3: "started"})

    # Far more polls than max_tally_attempts: still waiting, never abandoned.
    for _ in range(watcher.max_tally_attempts * 3):
        assert watcher.scan_once()[eid.hex()] == "collecting_aggregate"
    assert kw.dl.get_election(eid).tally_stalled is False


def test_divergent_keypers_are_asked_to_re_derive_then_bounded(kw, monkeypatch):
    """All keypers submitted yet no t+1 quorum → they disagree.

    Divergence is often transient (one keyper read the ballot list a moment before
    another), and a keyper's aggregate stays overridable until the quorum freezes precisely
    so honest keypers can re-converge. So each attempt must actually ask them to re-derive
    — and the whole thing is still bounded, in case the divergence is permanent.
    """
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)

    recomputes = []

    def fake_trigger(*a, recompute=False, **k):
        recomputes.append(recompute)
        return {1: "submitted", 2: "submitted", 3: "submitted"}

    monkeypatch.setattr(coord, "trigger_aggregate_http", fake_trigger)

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[:-1] == ["collecting_aggregate"] * (watcher.max_tally_attempts - 1)
    assert outs[-1] == "tally_abandoned"
    assert kw.dl.get_election(eid).tally_stalled is True
    # Every non-final poll asked the committee to re-derive — the convergence path.
    assert recomputes.count(True) == watcher.max_tally_attempts - 1


def test_tally_phase_deadline_is_the_backstop(kw, monkeypatch):
    """Keypers claim to be working forever → the wall-clock budget ends it. Measured from
    voting_end, so it is derived and survives a coordinator restart."""
    from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "in_progress"})

    kw.clock.set(2500)                                    # just past voting_end
    assert watcher.scan_once()[eid.hex()] == "collecting_aggregate"
    kw.clock.set(2000 + int(watcher.max_tally_phase_s) + 1)   # past the deadline
    assert watcher.scan_once()[eid.hex()] == "tally_abandoned"
    assert kw.dl.get_election(eid).tally_stalled is True


# --------------------------------------------------------------------------- #
#  An interrupted publish resumes the same key instead of starting over
# --------------------------------------------------------------------------- #

def _failing_publish(kw, keypers: set[int]):
    """Patch ``requests.post`` so ``/dkg/publish`` fails, as if transiently, for ``keypers``."""
    from unittest import mock

    real = requests.post
    targets = {kw.urls[i] + "/dkg/publish" for i in keypers}

    def post(url, *a, **k):
        if url in targets:
            raise requests.ConnectionError("simulated transient failure")
        return real(url, *a, **k)

    return mock.patch("requests.post", side_effect=post)


def _scan_until_finalized(kw, watcher, eid, *, attempts=4):
    outcomes = []
    for _ in range(attempts):
        outcomes.append(watcher.scan_once()[eid.hex()])
        if outcomes[-1] == "finalized":
            break
        kw.clock.set(kw.clock() + 5)  # past the back-off
    return outcomes


def test_interrupted_publish_resumes_the_same_key_3_of_3(kw):
    """3-of-3: one keyper's publish fails once. The retry used to start a new ceremony,
    leaving two keypers locked on the first key and the third on a second one, forever."""
    eid = kw.register(t=3)
    watcher = AutoDKG(kw.dl, kw.coordinator, clock=kw.clock, backoff_base_s=1, backoff_cap_s=1)
    with _failing_publish(kw, {2}):
        assert watcher.scan_once()[eid.hex()] == "registered_retry"
    first_key = {s.pk_election for s in kw.dl.get_dkg_submissions(eid)}
    assert len(first_key) == 1 and len(kw.dl.get_dkg_submissions(eid)) == 2

    kw.clock.set(5)
    assert watcher.scan_once()[eid.hex()] == "finalized"
    subs = kw.dl.get_dkg_submissions(eid)
    assert len(subs) == 3 and {s.pk_election for s in subs} == first_key
    assert kw.dl.get_finalized_key(eid).pk_election in first_key


def test_two_partial_publishes_still_finalize_2_of_3(kw):
    """2-of-3: two attempts in a row each get only one vote out. That used to leave three
    keypers on three different keys."""
    eid = kw.register()
    watcher = AutoDKG(kw.dl, kw.coordinator, clock=kw.clock, backoff_base_s=1, backoff_cap_s=1)
    with _failing_publish(kw, {2, 3}):
        assert watcher.scan_once()[eid.hex()] == "registered_retry"
    kw.clock.set(5)
    with _failing_publish(kw, {1, 3}):
        # Keyper 1's vote is already in; resuming adds keyper 2's for the same key.
        assert watcher.scan_once()[eid.hex()] == "finalized"
    assert len({s.pk_election for s in kw.dl.get_dkg_submissions(eid)}) == 1


def test_keyper_restart_between_round2_and_publish_keeps_its_key(kw, tmp_path):
    """A keyper restarted after round 2 lost its in-memory commitments. Publishing used to
    re-derive the key from them; it now re-sends the key it saved with its secret."""
    from shutter_governance_protocol.services.keyper import build_keyper_app

    eid = kw.register(t=3)
    watcher = AutoDKG(kw.dl, kw.coordinator, clock=kw.clock, backoff_base_s=1, backoff_cap_s=1)
    with _failing_publish(kw, {2}):
        watcher.scan_once()

    # Replace keyper 2's process with a fresh one over the same state directory.
    kw._servers[1].shutdown()
    app = build_keyper_app(kw.keyper_signers[1], kw.dl, kw.coordinator.identity,
                           clock=kw.clock, state_dir=tmp_path / "keyper2")
    port = int(kw.urls[2].rsplit(":", 1)[1])
    srv = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    kw._servers[1] = srv

    kw.clock.set(5)
    assert watcher.scan_once()[eid.hex()] == "finalized"
    assert len({s.pk_election for s in kw.dl.get_dkg_submissions(eid)}) == 1


def test_keyper_refuses_a_new_round1_after_publishing(kw):
    eid = kw.register()
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    token = watcher._tokens_by_committee[tuple(sorted(kw.urls.items()))][1]
    r = requests.post(kw.urls[1] + "/dkg/round1", json={"electionId": eid.hex()},
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 409


def test_new_round1_drops_an_unpublished_key_from_an_earlier_attempt(kw):
    """A key fixed at round 2 but never voted for must not survive a fresh round 1: if
    that attempt's round 2 then failed, a resume would publish a key nobody else holds."""
    eid = kw.register()
    watcher = AutoDKG(kw.dl, kw.coordinator, clock=kw.clock, backoff_base_s=1, backoff_cap_s=1)
    with _failing_publish(kw, {1, 2, 3}):
        assert watcher.scan_once()[eid.hex()] == "registered_retry"
    assert eid.hex() in requests.get(kw.urls[1] + "/status", timeout=10).json()["elections"]
    token = watcher._tokens_by_committee[tuple(sorted(kw.urls.items()))][1]
    r = requests.post(kw.urls[1] + "/dkg/round1", json={"electionId": eid.hex()},
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    assert eid.hex() not in requests.get(kw.urls[1] + "/status", timeout=10).json()["elections"]


# --------------------------------------------------------------------------- #
#  A dealer that withholds shares or equivocates on its commitments
# --------------------------------------------------------------------------- #

def _intercept(kw, rule):
    """Patch ``requests.post``. ``rule(url, body)`` returns a response to fake, or None to
    send the request for real."""
    from unittest import mock

    real = requests.post

    def post(url, *a, **k):
        faked = rule(url, k.get("json") or {})
        return faked if faked is not None else real(url, *a, **k)

    return mock.patch("requests.post", side_effect=post)


def _ok():
    r = requests.models.Response()
    r.status_code, r._content = 200, b'{"ok": true}'
    return r


def _withheld_by(kw, dealer, recipients, *, times=None):
    """Dealer ``dealer`` reports success but never delivers its share to ``recipients``,
    for the first ``times`` sends to each (``None``: never)."""
    targets = {kw.urls[r] + "/dkg/receive_share" for r in recipients}
    dropped: dict[str, int] = {}

    def rule(url, body):
        if url in targets and body.get("dealerIndex") == dealer:
            if times is None or dropped.get(url, 0) < times:
                dropped[url] = dropped.get(url, 0) + 1
                return _ok()
        return None
    return rule


def test_commitments_withheld_from_one_keyper_are_supplied_at_round2(kw):
    """3-of-3: dealer 3 never sends its commitments to keyper 2. Keyper 2 could then never
    check a share from dealer 3 and so never publish, which let one dealer stop the key.
    Round 2 now carries the agreed, dealer-signed commitments."""
    targets = {kw.urls[2] + "/dkg/receive_commitments"}

    def rule(url, body):
        return _ok() if url in targets and body.get("dealerIndex") == 3 else None

    eid = kw.register(t=3)
    with _intercept(kw, rule):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    assert len(kw.dl.get_dkg_submissions(eid)) == 3


def test_shares_that_never_arrive_are_settled_by_public_reveal(kw):
    """Keyper 3's sealed shares to keypers 1 and 2 never arrive, even when re-sent. The key
    used to finalize anyway and the tally failed after voting. Now dealer 3 is asked to
    reveal the shares to the coordinator, which checks and forwards them, and everyone
    publishes the same key."""
    eid = kw.register()
    with _intercept(kw, _withheld_by(kw, 3, {1, 2})):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    assert len(kw.dl.get_dkg_submissions(eid)) == 3


def _refuses_public_reveal(kw, dealer):
    target = kw.urls[dealer] + "/dkg/reveal_share"

    def rule(url, body):
        if url == target and body.get("public"):
            r = requests.models.Response()
            r.status_code, r._content = 409, b'{"error": "refused"}'
            return r
        return None
    return rule


def _both(*rules):
    def rule(url, body):
        for r in rules:
            out = r(url, body)
            if out is not None:
                return out
        return None
    return rule


def test_dealer_that_withholds_and_refuses_to_reveal_is_excluded(kw):
    """A malicious dealer withholds keyper 2's share and will not reveal it. It is dropped
    from the key, so keypers 1 and 2 both hold valid shares and dealer 3 has no veto."""
    eid = kw.register()
    with _intercept(kw, _both(_withheld_by(kw, 3, {2}), _refuses_public_reveal(kw, 3))):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    assert len(kw.dl.get_dkg_submissions(eid)) == 3  # every member could publish


def test_counter_accusation_does_not_save_a_withholding_dealer(kw):
    """Dealer 3 withholds keyper 2's share and falsely accuses keyper 2 back. Keyper 2
    clears itself by revealing a valid share; dealer 3 cannot, so dealer 3 is excluded.
    Before the public reveal the two accusations looked identical."""
    import json
    from unittest import mock

    from shutter_governance_protocol.core import write_auth

    eid = kw.register()
    target = kw.urls[3] + "/dkg/round2"
    real = requests.post
    others = _both(_withheld_by(kw, 3, {2}), _refuses_public_reveal(kw, 3))
    false_accusation = {
        "electionId": eid.hex(), "accusedDealerIndex": 2, "recipientIndex": 3,
        "signature": "0x" + write_auth.sign_digest(kw.keyper_signers[2].private_key,
                                                   write_auth.dkg_accusation_digest(eid, 2, 3)).hex(),
    }

    def post(url, *a, **k):
        faked = others(url, k.get("json") or {})
        if faked is not None:
            return faked
        r = real(url, *a, **k)
        if url == target:  # dealer 3 runs round 2, then claims keyper 2 cheated it
            r._content = json.dumps({"verified": False, "complaints": [2],
                                     "accusations": [false_accusation]}).encode()
        return r

    with mock.patch("requests.post", side_effect=post):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    # Keypers 1 and 2 published; dealer 3 kept "complaining" and excluded itself.
    assert len(kw.dl.get_dkg_submissions(eid)) == 2


def test_a_share_lost_once_is_repaired_and_everyone_publishes(kw):
    """An honest dealer whose share to keyper 2 went missing re-sends it when accused."""
    eid = kw.register()
    with _intercept(kw, _withheld_by(kw, 3, {2}, times=1)):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    assert len(kw.dl.get_dkg_submissions(eid)) == 3


def _report_other_commitments(kw, reporter, dealer, *, signed_by_dealer, session=None):
    """Make keyper ``reporter`` report a different vector for ``dealer``, as if the dealer
    had sent it a second set. ``signed_by_dealer=False`` forges the signature. ``session``
    signs for another ceremony attempt instead of the current one."""
    from shutter_governance_protocol.core import write_auth
    from shutter_governance_protocol.crypto.dkg import KeyperDKGState
    from shutter_governance_protocol.crypto.points import g2_to_compressed

    import json

    target = kw.urls[reporter] + "/dkg/commitments"
    real = requests.post
    current = [b""]

    def post_and_rewrite(url, *a, **k):
        if url.endswith("/dkg/round1"):
            current[0] = bytes.fromhex(k["json"].get("session", ""))
        r = real(url, *a, **k)
        if url == target:
            eid = bytes.fromhex(k["json"]["electionId"])
            comms, _ = KeyperDKGState().round1(dealer, 3, 2)
            vector = [g2_to_compressed(c) for c in comms]
            key = kw.keyper_signers[dealer - 1 if signed_by_dealer else reporter - 1].private_key
            sig = write_auth.sign_digest(key, write_auth.dkg_commitments_digest(
                eid, dealer, vector, current[0] if session is None else session))
            data = r.json()
            data["commitments"][str(dealer)] = {"commitments": [v.hex() for v in vector],
                                                "signature": "0x" + sig.hex()}
            r._content = json.dumps(data).encode()
        return r
    return post_and_rewrite


def test_equivocating_dealer_is_excluded_and_the_dkg_finalizes(kw):
    """Keyper 2 holds a second set of commitments signed by dealer 3. Two vectors under
    one dealer's signature prove equivocation, so dealer 3's contribution is dropped and
    the key is built from dealers 1 and 2. All three members keep their committee key."""
    from unittest import mock

    eid = kw.register()
    with mock.patch("requests.post", side_effect=_report_other_commitments(kw, 2, 3, signed_by_dealer=True)):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    assert len(kw.dl.get_finalized_key(eid).committee_pks) == 3


def test_equivocation_that_would_leave_too_few_dealers_halts(kw):
    """3-of-3: excluding one dealer would leave 2, below the threshold, so the ceremony
    halts with the signed evidence instead."""
    from unittest import mock

    eid = kw.register(t=3)
    with mock.patch("requests.post", side_effect=_report_other_commitments(kw, 2, 3, signed_by_dealer=True)):
        assert kw.watcher().scan_once()[eid.hex()] == "dkg_complaint"
    assert kw.dl.get_finalized_key(eid) is None


def test_vector_signed_in_an_earlier_attempt_does_not_frame_an_honest_dealer(kw, caplog):
    """Every retry deals fresh commitments. A keyper replaying the vector an honest dealer
    signed in an earlier attempt used to "prove" equivocation and get the dealer excluded
    (or, at 3-of-3, end the election)."""
    from unittest import mock

    eid = kw.register(t=3)
    replay = _report_other_commitments(kw, 2, 3, signed_by_dealer=True, session=b"earlier-attempt!")
    with caplog.at_level("ERROR"), mock.patch("requests.post", side_effect=replay):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"
    assert "op=dkg_equivocation" not in caplog.text


def test_keyper_refuses_an_exclusion_without_valid_evidence(kw):
    """A coordinator cannot drop an honest dealer by assertion: round 2 verifies the proof."""
    eid = kw.register()
    watcher = kw.watcher()
    urls = watcher._keyper_urls(kw.dl.get_election(eid).config)
    tokens = watcher._bootstrap(urls, watcher._member_addrs(kw.dl.get_election(eid).config))
    for i in (1, 2, 3):
        requests.post(kw.urls[i] + "/dkg/round1", json={"electionId": eid.hex()},
                      headers={"Authorization": f"Bearer {tokens[i]}"}, timeout=10)
    r = requests.post(kw.urls[1] + "/dkg/round2",
                      json={"electionId": eid.hex(),
                            "excluded": [{"dealer": 3, "reason": "equivocation", "evidence": []}]},
                      headers={"Authorization": f"Bearer {tokens[1]}"}, timeout=10)
    assert r.status_code == 400


def test_a_keyper_cannot_frame_a_dealer_with_an_unsigned_set(kw):
    """A report the dealer never signed is ignored, so a lying keyper cannot halt the DKG
    by blaming an honest dealer."""
    from unittest import mock

    eid = kw.register()
    with mock.patch("requests.post", side_effect=_report_other_commitments(kw, 2, 3, signed_by_dealer=False)):
        assert kw.watcher().scan_once()[eid.hex()] == "finalized"


def test_withholding_that_cannot_be_excluded_falls_back(kw):
    """3-of-3: excluding the withholding dealer would leave 2 dealers, below the threshold.
    No exclusion is made; the victim excludes itself, too few can publish, and the DKG
    fails before voting with the signed accusation, as before."""
    eid = kw.register(t=3)
    with _intercept(kw, _both(_withheld_by(kw, 3, {2}), _refuses_public_reveal(kw, 3))):
        assert kw.watcher().scan_once()[eid.hex()] == "dkg_complaint"
    assert kw.dl.get_finalized_key(eid) is None
