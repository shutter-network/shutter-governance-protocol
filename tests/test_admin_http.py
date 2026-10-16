"""Admin HTTP service: register/cancel over HTTP, authorized by a relayed admin
**signature** (no bearer token).

The admin EOA signs the request (here we sign locally, standing in for the frontend
wallet); the service verifies the signature recovers to the admin identity and relays it.
Driven over the in-memory data layer via the Flask test client.
"""

from __future__ import annotations
from shutter_governance_protocol.core import authz

from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
from shutter_governance_protocol.core.authz import Signer
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.services.admin import build_admin_app

from conftest import ManualClock


def stall(dl, eid, publisher, at: int) -> None:
    """Mark a tally stalled the way the coordinator does: signature bound to a timestamp,
    which the data layer checks for freshness and then spends."""
    dl.set_tally_stalled(
        eid, True,
        publisher.sign("tally_stall", eid, authz.request_nonce_payload(at)),
        at,
    )



def _config(admin: Signer, result_publisher: Signer | None = None) -> ElectionConfig:
    keypers = [Signer.generate() for _ in range(3)]
    return ElectionConfig(
        election_id=(1).to_bytes(32, "big"), num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
        weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000, voting_end=2_000, threshold=Threshold(t=2, n=3),
        keypers=tuple(KeyperIdentity(signing_key=keypers[i].identity, url=f"http://keyper{i+1}:8100")
                      for i in range(3)),
        eligibility_key=b"\xe1" * 48, result_publisher_key=(result_publisher or Signer.generate()).identity,
        gateway_keys=(Signer.generate().identity,), admin_key=admin.identity, protocol_version="v1",
    )


def _app():
    admin = Signer.generate()
    dl = InMemoryDataLayer(clock=ManualClock(0))
    app = build_admin_app(dl, admin.identity, clock=lambda: 0)
    return app, admin, dl


def _register_body(cfg, signer: Signer, dkg_lead_time: int = 0):
    return {"config": codecs.enc_config(cfg), "signature": codecs.enc_bytes(signer.sign_register(cfg)),
            "dkgLeadTime": dkg_lead_time}


def test_health_is_open():
    app, _admin, _dl = _app()
    assert app.test_client().get("/health").status_code == 200


def test_register_requires_valid_admin_signature():
    app, admin, _dl = _app()
    c = app.test_client()
    cfg = _config(admin)
    # a signature from the wrong key (not config.admin_key) → 401
    bad = c.post("/elections", json=_register_body(cfg, Signer.generate()))
    assert bad.status_code == 401
    # the admin EOA's signature → 200, registry-assigned id 1
    r = c.post("/elections", json=_register_body(cfg, admin))
    assert r.status_code == 200
    assert r.get_json()["electionId"] == "0x" + (1).to_bytes(32, "big").hex()


def test_register_rejects_admin_key_mismatch():
    # config.admin_key is a different EOA than the service's admin identity → 400,
    # even though the signature over the config is itself valid.
    app, _admin, _dl = _app()
    other = Signer.generate()
    r = app.test_client().post("/elections", json=_register_body(_config(other), other))
    assert r.status_code == 400  # RegistrationError (admin identity mismatch)


def test_register_rejects_insufficient_dkg_lead_time():
    admin = Signer.generate()
    dl = InMemoryDataLayer(clock=ManualClock(0))
    # Per-election dkgLeadTime of 500s; config has voting_start=1000 with clock at 600 → only 400s left.
    app = build_admin_app(dl, admin.identity, clock=lambda: 600)
    cfg = _config(admin)
    r = app.test_client().post("/elections", json=_register_body(cfg, admin, dkg_lead_time=500))
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "InsufficientDkgLeadTime"
    assert "too soon for DKG" in body["message"]
    assert "500s" in body["message"]


def test_register_requires_dkg_lead_time_field():
    app, admin, _dl = _app()
    cfg = _config(admin)
    # Omitting dkgLeadTime is a 400 — the gate value must be supplied per-election.
    body = {"config": codecs.enc_config(cfg), "signature": codecs.enc_bytes(admin.sign_register(cfg))}
    r = app.test_client().post("/elections", json=body)
    assert r.status_code == 400
    assert r.get_json()["error"] == "MissingDkgLeadTime"


def test_register_then_cancel():
    app, admin, dl = _app()
    c = app.test_client()
    cfg = _config(admin)
    eid_hex = c.post("/elections", json=_register_body(cfg, admin)).get_json()["electionId"]
    eid = bytes.fromhex(eid_hex.removeprefix("0x"))
    assert dl.get_election(eid).cancelled is False
    # cancel needs the admin's signature over ("cancel", eid)
    good = codecs.enc_bytes(admin.sign("cancel", eid))
    bad = codecs.enc_bytes(Signer.generate().sign("cancel", eid))
    assert c.post(f"/elections/{eid.hex()}/cancel", json={"signature": bad}).status_code == 401
    assert c.post(f"/elections/{eid.hex()}/cancel", json={"signature": good}).status_code == 204
    assert dl.get_election(eid).cancelled is True


def test_retry_tally_clears_stalled_flag_admin_only():
    """The retry button: an admin-signed clear (tally_resume) clears the stalled flag; a
    non-admin signature is rejected. (The coordinator marks it stalled; only admin clears.)"""
    admin = Signer.generate()
    publisher = Signer.generate()
    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)
    cfg = _config(admin, result_publisher=publisher)
    eid = dl.register_election(cfg, admin.sign_register(cfg))
    c = build_admin_app(dl, admin.identity, clock=clock).test_client()

    clock.set(2_500)  # past voting_end
    stall(dl, eid, publisher, 2_500)  # coordinator marks it
    assert dl.get_election(eid).tally_stalled is True

    # Valid admin signature → cleared (retry).
    r = c.post(f"/elections/{eid.hex()}/tally/retry",
               json={"signature": codecs.enc_bytes(
                         admin.sign("tally_resume", eid, authz.request_nonce_payload(2_500))),
                     "issuedAt": 2_500})
    assert r.status_code == 204
    assert dl.get_election(eid).tally_stalled is False

    # Re-mark; a non-admin signature is rejected (401) and the flag stays set.
    stall(dl, eid, publisher, 2_501)
    r = c.post(f"/elections/{eid.hex()}/tally/retry",
               json={"signature": codecs.enc_bytes(
                         Signer.generate().sign("tally_resume", eid, authz.request_nonce_payload(2_502))),
                     "issuedAt": 2_502})
    assert r.status_code == 401
    assert dl.get_election(eid).tally_stalled is True


# --------------------------------------------------------------------------- #
#  Retry requests are fresh and single-use at the admin service itself
# --------------------------------------------------------------------------- #

def _stalled_election(dl_cls=InMemoryDataLayer):
    admin, publisher = Signer.generate(), Signer.generate()
    clock = ManualClock(0)
    dl = dl_cls(clock=clock)
    cfg = _config(admin, result_publisher=publisher)
    eid = dl.register_election(cfg, admin.sign_register(cfg))
    clock.set(2_500)
    stall(dl, eid, publisher, 2_500)
    return admin, publisher, clock, dl, eid, build_admin_app(dl, admin.identity, clock=clock).test_client()


def _retry(c, admin, eid, issued_at):
    sig = admin.sign("tally_resume", eid, authz.request_nonce_payload(issued_at))
    return c.post(f"/elections/{eid.hex()}/tally/retry",
                  json={"signature": codecs.enc_bytes(sig), "issuedAt": issued_at})


def test_retry_missing_issued_at_is_400_not_404():
    """The browser used to send only a signature; the missing field reached the KeyError
    handler and came back as "No election found with that id."."""
    admin, _, _, _, eid, c = _stalled_election()
    sig = admin.sign("tally_resume", eid)  # the old empty-payload signature
    r = c.post(f"/elections/{eid.hex()}/tally/retry", json={"signature": codecs.enc_bytes(sig)})
    assert r.status_code == 400 and "issuedAt" in r.get_json()["message"]


def test_retry_outside_the_freshness_window_is_rejected():
    admin, _, _, dl, eid, c = _stalled_election()
    assert _retry(c, admin, eid, 2_500 - authz.REQUEST_FRESHNESS_S - 1).status_code == 401
    assert dl.get_election(eid).tally_stalled is True


class _ChainLikeDataLayer(InMemoryDataLayer):
    """Like the chain adapter: clears the stall without checking the signature or issued_at."""

    def set_tally_stalled(self, election_id, stalled, sig, issued_at):
        self._get(election_id).tally_stalled = stalled


def test_retry_cannot_be_replayed_even_when_the_data_layer_checks_nothing():
    """On chain the admin service is the only gate: a captured retry used to be accepted
    again after every later stall, spending the admin's gas each time."""
    admin, publisher, clock, dl, eid, c = _stalled_election(_ChainLikeDataLayer)
    assert _retry(c, admin, eid, 2_500).status_code == 204
    dl._get(eid).tally_stalled = True  # the coordinator stalls it again
    r = _retry(c, admin, eid, 2_500)   # the same request, replayed
    assert r.status_code == 401 and "already been used" in r.get_json()["message"]
    assert dl.get_election(eid).tally_stalled is True
    assert _retry(c, admin, eid, 2_501).status_code == 204  # a freshly signed retry still works
