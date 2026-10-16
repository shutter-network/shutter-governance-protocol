"""Run the shared conformance suite against the uniform data-layer HTTP service
wrapping the in-memory backend.

The same :func:`shutter_governance_protocol.services.data_layer.build_app` that fronts Postgres in
production also fronts :class:`~shutter_governance_protocol.adapters.memory.InMemoryDataLayer` here,
driven through the exact ``HttpDataLayerClient`` services hold. Passing the full
conformance suite over HTTP + memory proves the service is genuinely
backend-agnostic — the ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` selector swaps the backend and nothing
above the port changes. No external infra required (unlike the Postgres run), so
this is the always-on proof of the uniform service.
"""

from __future__ import annotations

import threading

import pytest

from conformance import DataLayerConformance, ManualClock, SignatureBackend

from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient
from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
from shutter_governance_protocol.envelopes.types import Attestation, BallotEnvelope, Ciphertext
from shutter_governance_protocol.ports.data_layer import VotingWindowError
from shutter_governance_protocol.services.data_layer import build_app


def test_voting_window_error_round_trips_over_http():
    """A backend ``VotingWindowError`` (only chain raises it in practice) must survive
    the HTTP hop as its typed port exception: service → 422 → client → VotingWindowError.
    Proven here over the memory backend by making its write raise the error."""
    from werkzeug.serving import make_server

    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)
    dl.submit_ballot = lambda *_a, **_k: (_ for _ in ()).throw(VotingWindowError("VotingClosed(...)"))
    eid = (1).to_bytes(32, "big")
    att = Attestation(election_id=eid, pseudonym=b"\x22" * 32, vk=b"\x33" * 48, weight=1, signature=b"\x44" * 80)
    ballot = BallotEnvelope(
        election_id=eid, pseudonym=b"\x22" * 32, vk=b"\x33" * 48,
        ciphertexts=tuple(Ciphertext(c1=b"\x01" * 96, c2=b"\x02" * 96) for _ in range(3)),
        zk_proof=b"\x01\x02\x03", voter_signature=b"\x55" * 80, attestation=att,
    )
    srv = make_server("127.0.0.1", 0, build_app(dl))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}")
        with pytest.raises(VotingWindowError):
            client.submit_ballot(eid, ballot)
    finally:
        srv.shutdown()
        thread.join()


class TestUniformServiceOverMemory(DataLayerConformance):
    @pytest.fixture
    def backend(self):
        from werkzeug.serving import make_server

        clock = ManualClock(0)
        dl = InMemoryDataLayer(clock=clock)
        srv = make_server("127.0.0.1", 0, build_app(dl))
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            client = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}")
            yield SignatureBackend(client, clock)
        finally:
            srv.shutdown()
            thread.join()


def test_malformed_ballot_round_trips_over_http():
    """A record the backend could not decode is served as ``"ballot": null`` plus its
    reason, in its own slot, and the client reads it back as ``envelope=None``. Keypers
    read ballots this way, so the record must not break the read."""
    from werkzeug.serving import make_server

    from shutter_governance_protocol.envelopes.types import StoredBallot

    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)
    eid = (1).to_bytes(32, "big")
    att = Attestation(election_id=eid, pseudonym=b"\x22" * 32, vk=b"\x33" * 48, weight=1, signature=b"\x44" * 80)
    ballot = BallotEnvelope(
        election_id=eid, pseudonym=b"\x22" * 32, vk=b"\x33" * 48,
        ciphertexts=tuple(Ciphertext(c1=b"\x01" * 96, c2=b"\x02" * 96) for _ in range(3)),
        zk_proof=b"\x01\x02\x03", voter_signature=b"\x55" * 80, attestation=att,
    )
    rows = [StoredBallot(0, ballot, submitted_at=5),
            StoredBallot(1, None, submitted_at=6, malformed_reason="JSONDecodeError: bad")]
    dl.list_ballots = lambda _eid, start, count: rows[start:start + count]
    srv = make_server("127.0.0.1", 0, build_app(dl))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        got = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}").list_ballots(eid, 0, 2)
    finally:
        srv.shutdown()
        thread.join()
    assert got[0].envelope == ballot
    assert (got[1].sequence_number, got[1].envelope, got[1].submitted_at) == (1, None, 6)
    assert got[1].malformed_reason == "JSONDecodeError: bad"
