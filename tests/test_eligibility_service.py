"""Wallet-authenticated eligibility service (chain-free EIP-191 personal-sign): an
attestation issued for a wallet-signed challenge verifies under the normative
``verify_attestation``; the pseudonym is stable per (wallet, election) so re-votes dedupe;
and a missing/invalid signature is rejected."""

from __future__ import annotations

import json

from eth_account import Account
from eth_account.messages import encode_defunct

from shutter_governance_protocol.adapters.eligibility_stub import StubEligibilityService
from shutter_governance_protocol.crypto import schnorr
from shutter_governance_protocol.crypto.points import g1_to_compressed
from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.ports.eligibility import verify_attestation
from shutter_governance_protocol.services.eligibility.eligibility import build_eligibility_app, challenge_message

ELIG_SK = 0x5772000000000000000000000000000000000000000000000000000000000001
SECRET = b"\xab" * 32
EID = (1).to_bytes(32, "big")


def _client(weight=3):
    svc = StubEligibilityService(ELIG_SK)
    return build_eligibility_app(svc, pseudonym_secret=SECRET, weight=weight).test_client()


def _vk() -> bytes:
    return g1_to_compressed(schnorr.keygen()[1])


def _sign(acct, eid: bytes, vk: bytes) -> str:
    sig = acct.sign_message(encode_defunct(text=challenge_message(eid, vk))).signature
    return codecs.enc_bytes(sig)


def _post(c, acct, eid, vk):
    return c.post("/attest", json={
        "electionId": codecs.enc_bytes(eid), "vk": codecs.enc_bytes(vk),
        "signature": _sign(acct, eid, vk),
    })


def test_attest_roundtrips_and_verifies():
    c = _client(weight=3)
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    att = codecs.dec_attestation(body["attestation"])
    assert att.weight == 3
    elig_key = StubEligibilityService(ELIG_SK).eligibility_key
    assert verify_attestation(elig_key, att, election_id=EID)
    assert codecs.dec_bytes(body["pseudonym"], name="pseudonym") == att.pseudonym


def test_same_wallet_same_pseudonym_different_wallet_differs():
    c = _client()
    a1, a2 = Account.create(), Account.create()

    def pseudonym(acct, vk):
        r = _post(c, acct, EID, vk)
        assert r.status_code == 200, r.get_json()
        return r.get_json()["pseudonym"]

    # same wallet, different ballot key (a re-vote) → SAME pseudonym → tally dedups
    assert pseudonym(a1, _vk()) == pseudonym(a1, _vk())
    # different wallet → different pseudonym
    assert pseudonym(a1, _vk()) != pseudonym(a2, _vk())


def test_missing_signature_rejected():
    r = _client().post("/attest", json={
        "electionId": codecs.enc_bytes(EID), "vk": codecs.enc_bytes(_vk())})
    assert r.status_code == 401


def test_bad_signature_rejected():
    r = _client().post("/attest", json={
        "electionId": codecs.enc_bytes(EID), "vk": codecs.enc_bytes(_vk()),
        "signature": codecs.enc_bytes(b"\x00" * 65)})
    assert r.status_code == 401


def test_health_exposes_eligibility_key():
    r = _client().get("/health")
    assert r.status_code == 200
    assert r.get_json()["eligibilityKey"] == codecs.enc_bytes(StubEligibilityService(ELIG_SK).eligibility_key)


def test_cors_headers_present():
    r = _client().get("/health")
    assert r.headers["Access-Control-Allow-Origin"] == "*"


def _allow_client(tmp_path, mapping, weight=3):
    """A test client whose issuance is gated by an ``ELIGIBILITY_ALLOWLIST`` file holding
    ``mapping`` (object or array). Returns (client, path) so the file can be re-edited."""
    p = tmp_path / "allow.json"
    p.write_text(json.dumps(mapping))
    svc = StubEligibilityService(ELIG_SK)
    app = build_eligibility_app(svc, pseudonym_secret=SECRET, weight=weight, allowlist_path=str(p))
    return app.test_client(), p


def test_allowlist_denies_unlisted_wallet(tmp_path):
    c, _ = _allow_client(tmp_path, {"0x" + "11" * 20: 1})
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 403, r.get_json()
    assert "eligible" in r.get_json()["message"].lower()


def test_allowlist_allows_listed_wallet_with_its_weight(tmp_path):
    acct = Account.create()  # checksummed address; the allowlist is case-insensitive
    c, _ = _allow_client(tmp_path, {acct.address: 5}, weight=1)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 200, r.get_json()
    assert codecs.dec_attestation(r.get_json()["attestation"]).weight == 5


def test_allowlist_array_form_uses_default_weight(tmp_path):
    acct = Account.create()
    c, _ = _allow_client(tmp_path, [acct.address], weight=2)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 200, r.get_json()
    assert codecs.dec_attestation(r.get_json()["attestation"]).weight == 2


def test_allowlist_hot_reload_takes_effect_without_restart(tmp_path):
    acct = Account.create()
    c, p = _allow_client(tmp_path, {"0x" + "11" * 20: 1})
    assert _post(c, acct, EID, _vk()).status_code == 403  # not listed yet
    p.write_text(json.dumps({acct.address: 1}))            # edit the file mid-flight
    assert _post(c, acct, EID, _vk()).status_code == 200   # now eligible, no restart


def test_allowlist_malformed_file_is_server_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("this is not json")
    svc = StubEligibilityService(ELIG_SK)
    c = build_eligibility_app(svc, pseudonym_secret=SECRET, allowlist_path=str(p)).test_client()
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 500, r.get_json()


def test_nonce_increments_per_wallet_and_election():
    """Each /attest for the same (election, wallet) gets a strictly higher nonce (re-vote
    counter); a different wallet or election starts its own sequence at 1."""
    c = _client()
    a1, a2 = Account.create(), Account.create()

    def nonce(acct, eid):
        r = _post(c, acct, eid, _vk())
        assert r.status_code == 200, r.get_json()
        return codecs.dec_attestation(r.get_json()["attestation"]).nonce

    assert nonce(a1, EID) == 1          # first vote
    assert nonce(a1, EID) == 2          # re-vote → higher
    assert nonce(a1, EID) == 3          # again
    assert nonce(a2, EID) == 1          # a different wallet starts fresh
    other_eid = (2).to_bytes(32, "big")
    assert nonce(a1, other_eid) == 1    # same wallet, different election starts fresh


def test_revote_attestation_verifies_with_its_nonce():
    """A re-vote's attestation (nonce 2) verifies under the normative verifier — proving the
    issuer signs the bound nonce, so the tally can trust the ordering."""
    from shutter_governance_protocol.ports.eligibility import verify_attestation
    c = _client(weight=1)
    acct = Account.create()
    _post(c, acct, EID, _vk())               # nonce 1
    r = _post(c, acct, EID, _vk())           # nonce 2
    att = codecs.dec_attestation(r.get_json()["attestation"])
    assert att.nonce == 2
    elig_key = StubEligibilityService(ELIG_SK).eligibility_key
    assert verify_attestation(elig_key, att, election_id=EID)


def test_sqlite_nonce_store_is_monotonic_and_durable(tmp_path):
    """The durable store hands out 1,2,3… per (election, pseudonym) and survives reopen
    (so a restart cannot regress a voter's nonce and let a stale ballot win)."""
    from shutter_governance_protocol.services.eligibility.eligibility import SqliteNonceStore
    path = str(tmp_path / "nonces.db")
    store = SqliteNonceStore(path)
    assert store.next(EID, b"\x01" * 32) == 1
    assert store.next(EID, b"\x01" * 32) == 2
    assert store.next(EID, b"\x02" * 32) == 1  # different pseudonym, own sequence
    reopened = SqliteNonceStore(path)          # simulate a restart
    assert reopened.next(EID, b"\x01" * 32) == 3


def test_challenge_message_fixture():
    """Cross-impl lock: a fixed key's signature over the canonical challenge recovers a
    known address. The JS voter (viem ``recoverMessageAddress``) recovers the same address
    from the same signature — see the voter app's ``eligibilitySign.test.ts``. If the
    message bytes drift on either side, recovery fails and both break."""
    eid = (1).to_bytes(32, "big")
    vk = bytes.fromhex("ab" * 48)
    sig = bytes.fromhex(
        "73a3d985a6689ecec6c51423b78083973d40a13551b25dc7f4ad7026b2b80d76"
        "60bd09c9826035423afc7d3a8b64f693e16b58b221be8890afaf914d41ce3c4c1b")
    recovered = Account.recover_message(
        encode_defunct(text=challenge_message(eid, vk)), signature=sig)
    assert recovered == "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"



# --------------------------------------------------------------------------- #
#  One per voter: an unweighted election is issued weight 1
# --------------------------------------------------------------------------- #

def _weighted_client(tmp_path, weighted_for, weight_in_allowlist=79):
    acct = Account.create()
    p = tmp_path / "allow.json"
    p.write_text(json.dumps({acct.address: weight_in_allowlist}))
    app = build_eligibility_app(StubEligibilityService(ELIG_SK), pseudonym_secret=SECRET,
                                allowlist_path=str(p), weighted_for=weighted_for)
    return app.test_client(), acct


def test_unweighted_election_is_issued_weight_1(tmp_path):
    """The allowlist says 79, but the election is one per voter: the credential says 1, so
    the voter's ballot is counted rather than excluded at tally."""
    c, acct = _weighted_client(tmp_path, lambda _eid: False)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 200, r.get_json()
    assert codecs.dec_attestation(r.get_json()["attestation"]).weight == 1


def test_weighted_election_is_issued_the_weight_as_held(tmp_path):
    c, acct = _weighted_client(tmp_path, lambda _eid: True)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 200, r.get_json()
    assert codecs.dec_attestation(r.get_json()["attestation"]).weight == 79


def test_unknown_election_is_404(tmp_path):
    def lookup(_eid):
        raise KeyError("unknown election")
    c, acct = _weighted_client(tmp_path, lookup)
    assert _post(c, acct, EID, _vk()).status_code == 404


def test_unreadable_election_config_fails_closed(tmp_path):
    """No credential is issued when the setting cannot be read: a guessed weight could be
    one the tally rejects."""
    def lookup(_eid):
        raise ConnectionError("api down")
    c, acct = _weighted_client(tmp_path, lookup)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 503
    assert "attestation" not in r.get_json()


def test_config_weighted_lookup_reads_the_registered_config():
    """The real lookup reads the API's port surface, caches per election, and raises
    KeyError for an unknown election."""
    import threading

    from flask import Flask
    from werkzeug.serving import make_server

    from conftest import ManualClock
    from shutter_governance_protocol.adapters.memory import InMemoryDataLayer
    from shutter_governance_protocol.core.authz import Signer
    from shutter_governance_protocol.core.config import (DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode,
                                                         Threshold, Variant)
    from shutter_governance_protocol.services.data_layer.data_layer import PORT_READ_PREFIX, port_read_blueprint
    from shutter_governance_protocol.services.eligibility.eligibility import config_weighted_lookup

    dl = InMemoryDataLayer(clock=ManualClock(0))
    admin = Signer.generate()
    cfg = ElectionConfig(
        election_id=EID, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A, weighted=False,
        duplicate_policy=DuplicatePolicy.LAST_WINS, voting_start=1000, voting_end=2000, threshold=Threshold(2, 3),
        keypers=tuple(KeyperIdentity(Signer.generate().identity, "") for _ in range(3)),
        eligibility_key=StubEligibilityService(ELIG_SK).eligibility_key, result_publisher_key=b"\x09" * 20,
        gateway_keys=(), admin_key=admin.identity, protocol_version="v1")
    dl.register_election(cfg, admin.sign_register(cfg))
    api = Flask("api")
    api.register_blueprint(port_read_blueprint(dl), url_prefix=PORT_READ_PREFIX)
    srv = make_server("127.0.0.1", 0, api, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    lookup = config_weighted_lookup(f"http://127.0.0.1:{srv.server_port}")
    try:
        assert lookup(EID) is False
        try:
            lookup((2).to_bytes(32, "big"))
            raise AssertionError("expected KeyError for an unknown election")
        except KeyError:
            pass
    finally:
        srv.shutdown()
    assert lookup(EID) is False  # served from the cache once the API is gone
