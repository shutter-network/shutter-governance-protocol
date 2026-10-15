"""Coordinator as the single keyper-facing orchestrator: one ``AutoDKG`` drives an
election end to end — DKG, then (once Tallying) trigger keypers to aggregate → quorum
→ decrypt → recover + publish the result. The coordinator is also the result publisher
(``result_publisher_key == coordinator identity``).

Full admin-plane pipeline against live keyper HTTP servers.
"""

from __future__ import annotations

import threading

import pytest
from werkzeug.serving import make_server

from shutter_governance_protocol.adapters.eligibility_stub import StubEligibilityService
from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
from shutter_governance_protocol.core.authz import Signer
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.crypto import ballot as ballot_crypto, schnorr
from shutter_governance_protocol.crypto.points import g1_to_compressed, g2_from_compressed
from shutter_governance_protocol.envelopes.types import BallotEnvelope, Ciphertext
from shutter_governance_protocol.ports.eligibility import AttestationRequest
from shutter_governance_protocol.services import gateway
from shutter_governance_protocol.services.coordinator import AutoDKG
from shutter_governance_protocol.services.keyper import build_keyper_app

from conftest import ManualClock

N, T = 3, 2  # T is the quorum


class World:
    def __init__(self, tmp_path):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()  # also the result publisher
        self.admin = Signer.generate()
        self.gateway = Signer.generate()
        self.keyper_signers = [Signer.generate() for _ in range(N)]
        elig_sk, _ = schnorr.keygen()
        self.elig = StubEligibilityService(elig_sk)
        self._servers = []
        self.urls = {}
        for i in range(1, N + 1):
            # Keypers trust only the coordinator to bootstrap them (sole bootstrapper).
            app = build_keyper_app(self.keyper_signers[i - 1], self.dl,
                                   self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"k{i}")
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            self.urls[i] = f"http://127.0.0.1:{srv.server_port}"

    def shutdown(self):
        for s in self._servers:
            s.shutdown()

    def register(self, *, voting_start=1000, voting_end=2000) -> bytes:
        cfg = ElectionConfig(
            election_id=(1).to_bytes(32, "big"), num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=voting_start, voting_end=voting_end,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, url=self.urls[i + 1])
                          for i in range(N)),
            eligibility_key=self.elig.eligibility_key, result_publisher_key=self.coordinator.identity,
            gateway_keys=(self.gateway.identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        return self.dl.register_election(cfg, self.admin.sign_register(cfg))

    def voter_ballot(self, eid, votes, pseudonym, weight):
        mpk = g2_from_compressed(self.dl.get_finalized_key(eid).pk_election)
        sk, vk = schnorr.keygen()
        vkb = g1_to_compressed(vk)
        att = self.elig.issue_attestation(AttestationRequest(eid, pseudonym, vkb, weight))
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=eid, pseudonym=pseudonym, sk=sk, vk=vk,
                                           attestation=att, votes=votes, num_candidates=3, budget=3)
        return BallotEnvelope(election_id=eid, pseudonym=pseudonym, vk=vkb,
                              ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
                              zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def test_coordinator_drives_dkg_then_tally(world):
    w = world
    eid = w.register()
    watcher = AutoDKG(w.dl, w.coordinator, clock=w.clock)
    watcher.scan_once()  # Registered → DKG finalizes (bootstraps + caches tokens)
    assert w.dl.get_finalized_key(eid) is not None

    w.clock.set(1500)  # voting open
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [3, 0, 0], b"\x01" * 32, 2), clock=w.clock, gateway_signer=w.gateway)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [0, 3, 0], b"\x02" * 32, 5), clock=w.clock, gateway_signer=w.gateway)

    w.clock.set(2500)  # Tallying — same watcher now drives aggregate → decrypt → result
    # /aggregate is asynchronous: the first poll triggers it and gets 202 "started", so the
    # tally completes over several polls, exactly as the running coordinator does. A poll
    # that finds keypers still computing must NOT count as a failed attempt — that is what
    # used to stall healthy elections.
    import time as _t

    outcome = None
    for _ in range(300):
        outcome = watcher.scan_once()[eid.hex()]
        if outcome == "tallied":
            break
        assert outcome == "collecting_aggregate", outcome   # never abandoned while working
        _t.sleep(0.05)
    assert outcome == "tallied"
    result = w.dl.get_result(eid)
    assert result is not None and list(result.totals) == [6, 15, 0]


def test_tally_succeeds_after_an_equivocating_dealer_is_excluded(world):
    """End to end: dealer 3 is caught equivocating and dropped from the key. Every member,
    dealer 3 included, still holds a share that verifies, so the tally completes and no
    single keyper can block it."""
    import time as _t
    from unittest import mock

    from test_coordinator import _report_other_commitments

    from shutter_governance_protocol.crypto.points import g2_from_compressed as g2
    from shutter_governance_protocol.crypto.proofs import (
        decode_dleq,
        make_decrypt_transcript,
        verify_decryption_share,
    )

    w = world
    eid = w.register()
    watcher = AutoDKG(w.dl, w.coordinator, clock=w.clock)
    with mock.patch("requests.post", side_effect=_report_other_commitments(w, 2, 3, signed_by_dealer=True)):
        assert watcher.scan_once()[eid.hex()] == "finalized"

    w.clock.set(1500)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [3, 0, 0], b"\x01" * 32, 2), clock=w.clock, gateway_signer=w.gateway)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [0, 3, 0], b"\x02" * 32, 5), clock=w.clock, gateway_signer=w.gateway)
    w.clock.set(2500)
    outcome = None
    for _ in range(300):
        outcome = watcher.scan_once()[eid.hex()]
        if outcome == "tallied":
            break
        _t.sleep(0.05)
    assert outcome == "tallied" and list(w.dl.get_result(eid).totals) == [6, 15, 0]

    agg, fk = w.dl.get_aggregate(eid), w.dl.get_finalized_key(eid)
    c1, c2 = g2(agg.aggregates[0].c1), g2(agg.aggregates[0].c2)
    valid = set()
    for s in w.dl.list_decryption_shares(eid):
        e, z = decode_dleq(s.entries[0].proof)
        if verify_decryption_share(make_decrypt_transcript(eid, 0), c1, c2, g2(fk.committee_pks[s.keyper_index - 1]),
                                   g2(s.entries[0].sigma), e, z, s.keyper_index):
            valid.add(s.keyper_index)
    assert valid == {s.keyper_index for s in w.dl.list_decryption_shares(eid)} and len(valid) >= 2


def _run_to_tally(w, eid, watcher):
    """Vote two weighted ballots, then poll the coordinator until the tally completes."""
    import time as _t

    w.clock.set(1500)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [3, 0, 0], b"\x01" * 32, 2), clock=w.clock, gateway_signer=w.gateway)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [0, 3, 0], b"\x02" * 32, 5), clock=w.clock, gateway_signer=w.gateway)
    w.clock.set(2500)
    for _ in range(300):
        if watcher.scan_once()[eid.hex()] == "tallied":
            return list(w.dl.get_result(eid).totals)
        _t.sleep(0.05)
    return None


def _shares_that_verify(w, eid) -> set[int]:
    from shutter_governance_protocol.crypto.points import g2_from_compressed as g2
    from shutter_governance_protocol.crypto.proofs import decode_dleq, make_decrypt_transcript, verify_decryption_share

    agg, fk = w.dl.get_aggregate(eid), w.dl.get_finalized_key(eid)
    c1, c2 = g2(agg.aggregates[0].c1), g2(agg.aggregates[0].c2)
    ok = set()
    for s in w.dl.list_decryption_shares(eid):
        e, z = decode_dleq(s.entries[0].proof)
        if verify_decryption_share(make_decrypt_transcript(eid, 0), c1, c2, g2(fk.committee_pks[s.keyper_index - 1]),
                                   g2(s.entries[0].sigma), e, z, s.keyper_index):
            ok.add(s.keyper_index)
    return ok


def test_real_equivocation_over_http_is_excluded_and_the_tally_completes(world):
    """Dealer 3 really equivocates on the wire: keyper 2 receives a second polynomial's
    commitments and share, both validly signed by dealer 3 and sealed to keyper 2. Without
    the comparison keyper 2's share would not fit the finalized key. Dealer 3 is excluded,
    and every member's decryption share verifies."""
    from unittest import mock

    import requests as rq

    from shutter_governance_protocol.core import write_auth
    from shutter_governance_protocol.crypto.dkg import KeyperDKGState
    from shutter_governance_protocol.crypto.points import g2_to_compressed
    from shutter_governance_protocol.services.keyper import keyper_bootstrap as boot

    w = world
    eid = w.register()
    dealer_key = w.keyper_signers[2].private_key
    comms_b, shares_b = KeyperDKGState().round1(3, 3, 2)  # dealer 3's second polynomial
    vector_b = [g2_to_compressed(c) for c in comms_b]
    real = rq.post

    def post(url, *a, **k):
        body = dict(k.get("json") or {})
        if url == w.urls[2] + "/dkg/receive_commitments" and body.get("dealerIndex") == 3:
            body["commitments"] = [v.hex() for v in vector_b]
            body["signature"] = "0x" + write_auth.sign_digest(
                dealer_key, write_auth.dkg_commitments_digest(eid, 3, vector_b)).hex()
            k = {**k, "json": body}
        elif url == w.urls[2] + "/dkg/receive_share" and body.get("dealerIndex") == 3:
            st = rq.get(w.urls[2] + "/status", timeout=10).json()
            enc = boot.verify_encryption_pubkey(w.keyper_signers[1].identity, st["encryptionPubkey"],
                                                st["encryptionPubkeySig"])
            body["sealedShare"] = boot.seal_share(shares_b[2], enc)
            body["signature"] = "0x" + write_auth.sign_digest(
                dealer_key, write_auth.dkg_share_digest(eid, 3, 2, shares_b[2])).hex()
            k = {**k, "json": body}
        return real(url, *a, **k)

    watcher = AutoDKG(w.dl, w.coordinator, clock=w.clock)
    with mock.patch("requests.post", side_effect=post):
        assert watcher.scan_once()[eid.hex()] == "finalized"
    assert _run_to_tally(w, eid, watcher) == [6, 15, 0]
    assert _shares_that_verify(w, eid) == {s.keyper_index for s in w.dl.list_decryption_shares(eid)}


def test_tally_completes_after_a_withholding_dealer_is_excluded(world):
    """Dealer 3 withholds keyper 2's share and refuses to reveal it. It is excluded, so the
    tally completes and every member's decryption share verifies, dealer 3's included."""
    from test_coordinator import _both, _intercept, _refuses_public_reveal, _withheld_by

    w = world
    eid = w.register()
    watcher = AutoDKG(w.dl, w.coordinator, clock=w.clock)
    with _intercept(w, _both(_withheld_by(w, 3, {2}), _refuses_public_reveal(w, 3))):
        assert watcher.scan_once()[eid.hex()] == "finalized"
    assert _run_to_tally(w, eid, watcher) == [6, 15, 0]
    assert _shares_that_verify(w, eid) == {s.keyper_index for s in w.dl.list_decryption_shares(eid)}
