"""The ``api`` service's ``/port`` read surface, as remote keypers consume it.

Keyper operators read the data layer but write through the coordinator relay
(``keyper_server`` sends writes to ``submitter``), so they only need the port's *read*
half. Mounting that half on the public ``api`` service lets a keyper point
``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL`` at ``http://<api>/port`` instead of requiring the data-layer
service itself to be reachable from outside the deployment.

For that to be safe the ``/port`` surface must be byte-faithful to the port — not the
friendlier browser shape ``api`` serves on its own routes. The two properties that bite:

* **No pagination cap.** A keyper reads every ballot to recompute admission. ``api``'s
  browser route caps at ``_MAX_LIMIT`` (200); if the port surface inherited that cap, an
  election over 200 ballots would give each keyper a silently truncated ballot list, its
  aggregate would diverge from the committee's, the t+1 byte-identical quorum would never
  form, and the tally would stall with no error anywhere.
* **Bare-hex election ids and storage metadata.** ``api`` decimalizes ids and returns
  flat ballot envelopes; ``HttpDataLayerClient`` expects the port shape, including each
  ballot's ``sequenceNumber`` and ``submittedAt``.
"""

from __future__ import annotations

import threading

import pytest

from conformance import ManualClock

from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient
from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.authz import Signer
from shutter_governance_protocol.envelopes.types import Attestation, BallotEnvelope, Ciphertext
from shutter_governance_protocol.services.api import build_api_app

VOTING_START, VOTING_END = 1_000, 2_000


def _ballot(eid: bytes, fill: int) -> BallotEnvelope:
    pseudonym = bytes([fill % 256]) * 32
    att = Attestation(election_id=eid, pseudonym=pseudonym, vk=b"\x33" * 48, weight=1, signature=b"\x44" * 80)
    return BallotEnvelope(
        election_id=eid, pseudonym=pseudonym, vk=b"\x33" * 48,
        ciphertexts=tuple(Ciphertext(c1=b"\x01" * 96, c2=b"\x02" * 96) for _ in range(3)),
        zk_proof=b"\x01\x02\x03", voter_signature=b"\x55" * 80, attestation=att,
    )


@pytest.fixture
def env():
    """An `api` app over in-memory storage, with an election open for voting."""
    from werkzeug.serving import make_server

    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)

    admin = Signer.generate()
    keypers = [Signer.generate() for _ in range(3)]
    config = ElectionConfig(
        election_id=(1).to_bytes(32, "big"), num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
        weighted=False, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=VOTING_START, voting_end=VOTING_END, threshold=Threshold(t=2, n=3),
        keypers=tuple(KeyperIdentity(signing_key=k.identity, url=f"http://k{i}") for i, k in enumerate(keypers)),
        eligibility_key=b"\x66" * 48, result_publisher_key=Signer.generate().identity,
        gateway_keys=(), admin_key=admin.identity, protocol_version="SHUTTER-VOTE-v1",
    )
    eid = dl.register_election(config, admin.sign_register(config))

    # Finalize the DKG so the election reaches Voting (the ballot write gate).
    pk, committee = b"\xa0" * 96, [b"\xb0" * 96 for _ in range(3)]
    for k in keypers[:2]:
        dl.submit_dkg_result(eid, pk, committee, write_auth.sign_dkg_result(k.private_key, eid, pk, committee))
    clock.set(1_500)

    srv = make_server("127.0.0.1", 0, build_api_app(dl, clock=clock))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield dl, eid, f"http://127.0.0.1:{srv.server_port}", clock
    finally:
        srv.shutdown()
        thread.join()


def test_keyper_reads_work_through_api_port_prefix(env):
    """Every read the keyper performs resolves against api's /port surface."""
    dl, eid, base, _ = env
    dl.submit_ballot(eid, _ballot(eid, 1))
    client = HttpDataLayerClient(f"{base}/port")

    rec = client.get_election(eid)
    assert rec.config.election_id == eid
    assert rec.finalized_key is not None
    assert client.count_ballots(eid) == 1
    assert client.get_aggregate(eid) is None
    assert client.get_result(eid) is None
    assert client.list_decryption_shares(eid) == []
    assert client.verifiability_tier() == 0


def test_port_surface_returns_storage_metadata(env):
    """Ballots come back as StoredBallot, so the tally-time window check still works."""
    dl, eid, base, _ = env
    dl.submit_ballot(eid, _ballot(eid, 1))
    [sb] = HttpDataLayerClient(f"{base}/port").list_ballots(eid, 0, 10)
    assert sb.sequence_number == 0
    assert VOTING_START <= sb.submitted_at < VOTING_END
    assert sb.envelope.pseudonym == b"\x01" * 32


def test_port_surface_caps_a_single_page_but_paging_recovers_everything(env):
    """No single request may stream a whole election — this surface is public.

    But a cap alone would be a *worse* bug than the DoS: the keyper reads every ballot to
    recompute admission, so a silently short list would make each keyper aggregate a
    different subset and the t+1 byte-identical quorum would never form. So the route caps
    and `read_all_ballots` pages, verifying it recovered a complete contiguous read.
    """
    import requests

    from shutter_governance_protocol.services.common.reads import read_all_ballots
    from shutter_governance_protocol.services.data_layer.data_layer import MAX_BALLOT_PAGE

    dl, eid, base, _ = env
    total = 1200                                     # deliberately over MAX_BALLOT_PAGE
    for i in range(total):
        dl.submit_ballot(eid, _ballot(eid, i))

    # One request cannot drain the election, however large a count it asks for.
    raw = requests.get(f"{base}/port/elections/{eid.hex()}/ballots?start=0&count=999999").json()
    assert len(raw["ballots"]) == MAX_BALLOT_PAGE

    # Paging still recovers all of it, in order, with no gaps.
    client = HttpDataLayerClient(f"{base}/port")
    everything = read_all_ballots(client, eid)
    assert len(everything) == total
    assert [sb.sequence_number for sb in everything] == list(range(total))


def test_ballot_page_is_bounded_by_size_too(env, monkeypatch):
    """1,000 rows of large ballots made one page hundreds of MB (1.3 GB at the form's
    branch limit), slower than the client's 10 s timeout, so keyper reads failed and the
    tally stalled. A page now also stops at a byte budget; readers page on what came back."""
    import json

    import requests

    from shutter_governance_protocol.services.common.reads import read_all_ballots
    from shutter_governance_protocol.services.data_layer import data_layer

    dl, eid, base, _ = env
    total = 250
    for i in range(total):
        dl.submit_ballot(eid, _ballot(eid, i))
    one_row = len(requests.get(f"{base}/port/elections/{eid.hex()}/ballots?start=0&count=1").text)
    monkeypatch.setattr(data_layer, "MAX_BALLOT_PAGE_BYTES", one_row * 7)

    raw = requests.get(f"{base}/port/elections/{eid.hex()}/ballots?start=0&count=1000")
    page = json.loads(raw.text)["ballots"]
    assert 1 <= len(page) <= 8 and len(raw.content) < one_row * 9
    assert [r["sequenceNumber"] for r in page] == list(range(len(page)))

    everything = read_all_ballots(HttpDataLayerClient(f"{base}/port"), eid)
    assert [sb.sequence_number for sb in everything] == list(range(total))

    # A single ballot bigger than the whole budget is still served: a page never comes back empty.
    monkeypatch.setattr(data_layer, "MAX_BALLOT_PAGE_BYTES", 1)
    assert len(requests.get(f"{base}/port/elections/{eid.hex()}/ballots?start=5&count=50").json()["ballots"]) == 1


def test_read_all_ballots_raises_rather_than_returning_short(env):
    """A truncated read must fail loudly. Silently returning fewer ballots is the failure
    that makes keypers diverge, and it would look like 'the committee disagreed'."""
    import pytest as _pytest

    from shutter_governance_protocol.services.common.reads import IncompleteBallotRead, read_all_ballots

    dl, eid, base, _ = env
    for i in range(5):
        dl.submit_ballot(eid, _ballot(eid, i))

    client = HttpDataLayerClient(f"{base}/port")
    # A data layer that under-reports rows while count_ballots still says 5.
    client.list_ballots = lambda *_a, **_k: []
    with _pytest.raises(IncompleteBallotRead):
        read_all_ballots(client, eid)


def test_oversized_request_body_is_refused(env):
    """`get_json(force=True)` would otherwise buffer an arbitrary body before any
    validation — and the ballot POST is public and unauthenticated."""
    import requests

    from shutter_governance_protocol.services.data_layer.data_layer import MAX_CONTENT_LENGTH

    _, eid, base, _ = env
    oversized = b'{"ballot":"' + b"a" * (MAX_CONTENT_LENGTH + 1024) + b'"}'
    r = requests.post(f"{base}/elections/{int.from_bytes(eid, 'big')}/ballots",
                      data=oversized, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_port_surface_exposes_no_write_routes(env):
    """Reads only: a write against /port must not reach the data layer. Keyper writes go
    through the coordinator relay, which is bearer-authenticated."""
    import requests

    _, eid, base, _ = env
    hex_eid = eid.hex()
    for path, body in [
        (f"/port/elections/{hex_eid}/ballots", {"ballot": {}}),
        (f"/port/elections/{hex_eid}/aggregate", {"aggregate": {}, "keyperSig": "0x00"}),
        (f"/port/elections/{hex_eid}/result", {"result": {}, "resultPublisherSig": "0x00"}),
        ("/port/elections", {"config": {}, "adminSig": "0x00"}),
    ]:
        assert requests.post(f"{base}{path}", json=body).status_code == 405


# --------------------------------------------------------------------------- #
#  Keyper read-endpoint resolution (SHUTTER_GOVERNANCE_PROTOCOL_API_URL)
# --------------------------------------------------------------------------- #

def test_api_url_gets_the_port_path_appended():
    """Operators supply the API base URL; the keyper knows the read-surface path."""
    from shutter_governance_protocol.services.keyper.keyper_server import resolve_read_url

    assert resolve_read_url({"SHUTTER_GOVERNANCE_PROTOCOL_API_URL": "http://api:8500"}) == "http://api:8500/port"
    assert resolve_read_url({"SHUTTER_GOVERNANCE_PROTOCOL_API_URL": "http://api:8500/"}) == "http://api:8500/port"
    # Works behind a reverse proxy mounted at a sub-path.
    assert resolve_read_url({"SHUTTER_GOVERNANCE_PROTOCOL_API_URL": "https://vote.example.org/shutter_governance_protocol"}) == "https://vote.example.org/shutter_governance_protocol/port"


def test_stale_data_layer_url_is_not_honoured():
    """No back-compat fallback: nothing is deployed, so an env still carrying the old
    SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL must fail loudly rather than quietly reading from a URL that now
    points at an internal-only service."""
    from shutter_governance_protocol.services.keyper.keyper_server import resolve_read_url

    with pytest.raises(SystemExit, match="SHUTTER_GOVERNANCE_PROTOCOL_API_URL"):
        resolve_read_url({"SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL": "http://dl:8000"})


def test_missing_read_url_fails_loudly():
    from shutter_governance_protocol.services.keyper.keyper_server import resolve_read_url

    with pytest.raises(SystemExit, match="SHUTTER_GOVERNANCE_PROTOCOL_API_URL"):
        resolve_read_url({})


def test_resolved_url_actually_serves_the_port_surface(env):
    """The appended path lines up with where api mounts the blueprint."""
    from shutter_governance_protocol.services.keyper.keyper_server import resolve_read_url

    dl, eid, base, _ = env
    dl.submit_ballot(eid, _ballot(eid, 1))
    client = HttpDataLayerClient(resolve_read_url({"SHUTTER_GOVERNANCE_PROTOCOL_API_URL": base}))
    assert client.count_ballots(eid) == 1
