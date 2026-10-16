"""Public read-only API service (``shutter_governance_protocol.services.api``) — e2e over the in-memory
backend via the Flask test client.

The API is backend-blind (it takes any ``ElectionDataLayer``); driving it over the
in-memory adapter exercises the read pass-through, pagination, CORS, and error
mapping without external infra. It returns the raw envelopes today, so the
config round-trips back through the codec.
"""

from __future__ import annotations

import pytest

from conftest import ManualClock, build_full_env

from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
from shutter_governance_protocol.services.api import build_api_app


@pytest.fixture
def api():
    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)
    env = build_full_env(dl, clock)
    return build_api_app(dl).test_client(), env, dl


def _register(env, dl) -> bytes:
    # The signed config asserts the id it expects, so read the sequence head first —
    # the same read-then-sign a real admin client does.
    from dataclasses import replace

    cfg = replace(env.config, election_id=(len(dl.list_elections()) + 1).to_bytes(32, "big"))
    return dl.register_election(cfg, env.admin.sign_register(cfg))


def test_health_and_cors(api):
    client, _, _ = api
    r = client.get("/health")
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert r.headers.get("Access-Control-Allow-Origin") == "*"


def test_list_pagination(api):
    client, env, dl = api
    for _ in range(3):
        _register(env, dl)

    all_ids = client.get("/elections").get_json()
    # ids are the friendly sequential decimals, not 64-hex
    assert all_ids["total"] == 3 and all_ids["electionIds"] == [1, 2, 3]

    page1 = client.get("/elections?limit=2&offset=0").get_json()
    assert page1["total"] == 3 and page1["limit"] == 2 and page1["offset"] == 0
    assert page1["electionIds"] == [1, 2]

    page2 = client.get("/elections?limit=2&offset=2").get_json()
    assert page2["electionIds"] == [3]


def test_bad_pagination_arg_400(api):
    client, env, dl = api
    _register(env, dl)
    assert client.get("/elections?limit=abc").status_code == 400


def test_get_election_and_empty_reads(api):
    client, env, dl = api
    eid = _register(env, dl)
    n = int.from_bytes(eid, "big")  # the friendly decimal id (== 1 for the first)

    body = client.get(f"/elections/{n}").get_json()  # decimal id in the URL
    assert body["electionId"] == n
    assert body["cancelled"] is False and body["finalizedKey"] is None
    # the stalled overlay is surfaced to the dashboard (drives the TallyStalled badge + retry button)
    assert body["tallyStalled"] is False
    # Election ids are decimal *everywhere*, including inside the config
    # envelope; crypto byte-strings stay 0x-hex.
    assert body["config"]["electionId"] == n
    assert body["config"]["numCandidates"] == env.config.num_candidates
    assert body["config"]["eligibilityKey"].startswith("0x")

    assert client.get(f"/elections/{n}/ballots/count").get_json()["count"] == 0
    ballots = client.get(f"/elections/{n}/ballots").get_json()  # bare call → default page, not empty-by-footgun
    assert ballots["ballots"] == [] and ballots["total"] == 0 and ballots["limit"] == 50
    assert client.get(f"/elections/{n}/dkg").get_json()["submissions"] == []
    assert client.get(f"/elections/{n}/dkg/finalized").get_json()["finalizedKey"] is None
    assert client.get(f"/elections/{n}/aggregate").get_json()["aggregate"] is None
    assert client.get(f"/elections/{n}/shares").get_json()["shares"] == []
    assert client.get(f"/elections/{n}/result").get_json()["result"] is None
    # the canonical 64-hex form still resolves to the same election
    assert client.get(f"/elections/{eid.hex()}").get_json()["electionId"] == n


def test_admin_filter(api):
    client, env, dl = api
    _register(env, dl)
    admin_hex = env.admin.identity.hex()
    matched = client.get(f"/elections?admin={admin_hex}").get_json()
    assert matched["total"] == 1
    other = client.get("/elections?admin=" + "11" * 20).get_json()
    assert other["total"] == 0


def test_unknown_election_404(api):
    client, _, _ = api
    assert client.get("/elections/" + "00" * 32).status_code == 404


def test_strict_id_parsing(api):
    client, env, dl = api
    eid = _register(env, dl)  # id 1
    h = eid.hex()  # canonical 64-char hex

    # accepted: decimal, bare 64-hex, 0x + 64-hex — all resolve to the same election
    for good in ("1", h, "0x" + h):
        r = client.get(f"/elections/{good}")
        assert r.status_code == 200 and r.get_json()["electionId"] == 1

    # rejected (400): short/loose hex, and the cases that used to silently misparse
    for bad in ("0x1", "0x10", "0x1a", "0x0000000000000000000000000000000001"):
        assert client.get(f"/elections/{bad}").status_code == 400


def test_capability(api):
    client, _, _ = api
    assert client.get("/capability").get_json()["verifiabilityTier"] == 0


def test_ballot_list_keeps_a_malformed_record_in_its_slot(api):
    """The dashboard addresses ballots by position within a page, so an undecodable
    record must be served in its slot (as its reason) rather than dropped or a 500."""
    from shutter_governance_protocol.envelopes.types import StoredBallot

    client, env, dl = api
    eid = _register(env, dl)
    n = int.from_bytes(eid, "big")
    dl.count_ballots = lambda _eid: 1
    dl.list_ballots = lambda _eid, start, count: [
        StoredBallot(0, None, submitted_at=1, malformed_reason="JSONDecodeError: bad")
    ][start:start + count]
    resp = client.get(f"/elections/{n}/ballots")
    assert resp.status_code == 200
    assert resp.get_json()["ballots"] == [{"malformed": "JSONDecodeError: bad"}]
