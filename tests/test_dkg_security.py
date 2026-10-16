"""DKG security-hardening tests: enc-pubkey binding, share sealing, DKG P2P
signature digests, signed+sealed share exchange, the accusation-gated reveal, and
the coordinator halt-on-complaint.

Ports the reference thresholdELGamal `fix/dkg-security-hardening` guarantees to shutter_governance_protocol.
Phase 1 here covers the primitives; later phases extend this module.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.authz import Signer
from shutter_governance_protocol.crypto.params import CURVE_ORDER
from shutter_governance_protocol.services.keyper import keyper_bootstrap as boot


# --- share sealing (Leg A primitive) ----------------------------------- #

class TestSealShare:
    def test_seal_unseal_round_trips_scalar(self):
        priv = X25519PrivateKey.generate()
        share = 123456789 % CURVE_ORDER
        sealed = boot.seal_share(share, priv.public_key())
        assert isinstance(sealed, str)  # base64 for JSON transport
        assert boot.unseal_share(sealed, priv) == share

    def test_seal_hides_the_scalar_on_the_wire(self):
        priv = X25519PrivateKey.generate()
        share = 0xDEADBEEF
        sealed = boot.seal_share(share, priv.public_key())
        assert share.to_bytes(32, "big") not in base64.b64decode(sealed)  # ciphertext, not plaintext

    def test_unseal_rejects_wrong_recipient(self):
        priv = X25519PrivateKey.generate()
        other = X25519PrivateKey.generate()
        sealed = boot.seal_share(42, priv.public_key())
        with pytest.raises(Exception):
            boot.unseal_share(sealed, other)

    def test_unseal_rejects_tampered_ciphertext(self):
        priv = X25519PrivateKey.generate()
        raw = bytearray(base64.b64decode(boot.seal_share(42, priv.public_key())))
        raw[-1] ^= 0x01  # flip a ciphertext byte → AES-GCM auth fails
        with pytest.raises(Exception):
            boot.unseal_share(base64.b64encode(bytes(raw)).decode(), priv)

    def test_unseal_rejects_blob_without_share_domain_tag(self):
        """A box sealed to the same key but lacking the DKG-SHARE-SEAL-v1 tag (e.g. a
        bootstrap-shaped payload) must not unseal as a share."""
        priv = X25519PrivateKey.generate()
        wrong = boot.x25519_seal(b"not-a-share-payload", priv.public_key())
        with pytest.raises(ValueError, match="domain-tag"):
            boot.unseal_share(base64.b64encode(wrong).decode(), priv)


# --- encryption-pubkey binding (verify-before-seal) ------------------------- #

class TestVerifyEncryptionPubkey:
    def _bound(self):
        signer = Signer.generate()
        x = X25519PrivateKey.generate()
        pub = x.public_key().public_bytes_raw()
        sig = boot.sign_encryption_pubkey(signer, pub)
        return signer, pub, sig

    def test_valid_binding_returns_key(self):
        signer, pub, sig = self._bound()
        parsed = boot.verify_encryption_pubkey(signer.identity, pub.hex(), sig.hex())
        assert parsed.public_bytes_raw() == pub

    def test_accepts_0x_prefixed_hex_and_address(self):
        signer, pub, sig = self._bound()
        parsed = boot.verify_encryption_pubkey("0x" + signer.identity.hex(), "0x" + pub.hex(), "0x" + sig.hex())
        assert parsed.public_bytes_raw() == pub

    def test_wrong_member_address_rejected(self):
        _signer, pub, sig = self._bound()
        with pytest.raises(ValueError, match="signature mismatch"):
            boot.verify_encryption_pubkey(Signer.generate().identity, pub.hex(), sig.hex())

    def test_substituted_pubkey_rejected(self):
        """A dealer can't be fed a substituted X25519 key: the sig won't recover to
        the member address for a different pubkey."""
        signer, _pub, sig = self._bound()
        other_pub = X25519PrivateKey.generate().public_key().public_bytes_raw()
        with pytest.raises(ValueError, match="signature mismatch"):
            boot.verify_encryption_pubkey(signer.identity, other_pub.hex(), sig.hex())


# --- DKG P2P signature digests --------------------------------------------- #

class TestDkgDigests:
    EID = b"\x11" * 32

    def test_digests_are_deterministic(self):
        c = [b"\x02" * 96, b"\x03" * 96]
        assert write_auth.dkg_commitments_digest(self.EID, 1, c) == write_auth.dkg_commitments_digest(self.EID, 1, c)
        assert write_auth.dkg_share_digest(self.EID, 1, 2, 7) == write_auth.dkg_share_digest(self.EID, 1, 2, 7)

    def test_share_and_reveal_digests_differ_by_dst(self):
        """Same (eid, dealer, recipient, share) but distinct DSTs → a reveal signature
        can never be replayed as a share signature or vice versa."""
        assert write_auth.dkg_share_digest(self.EID, 1, 2, 9) != write_auth.dkg_reveal_digest(self.EID, 1, 2, 9)

    def test_accusation_digest_binds_dealer_and_recipient(self):
        base = write_auth.dkg_accusation_digest(self.EID, 3, 2)
        assert base != write_auth.dkg_accusation_digest(self.EID, 4, 2)  # different accused dealer
        assert base != write_auth.dkg_accusation_digest(self.EID, 3, 5)  # different recipient
        assert base != write_auth.dkg_accusation_digest(b"\x22" * 32, 3, 2)  # different election

    def test_share_digest_sign_recover_roundtrip(self):
        dealer = Signer.generate()
        digest = write_auth.dkg_share_digest(self.EID, 1, 2, 12345)
        sig = write_auth.sign_digest(dealer.private_key, digest)
        assert write_auth.recover_digest(digest, sig) == dealer.identity

    def test_accusation_sign_recover_roundtrip(self):
        recipient = Signer.generate()
        digest = write_auth.dkg_accusation_digest(self.EID, 3, 2)
        sig = write_auth.sign_digest(recipient.private_key, digest)
        assert write_auth.recover_digest(digest, sig) == recipient.identity


# --- live keyper cluster (accusation gate + halt) --------------------------- #

import threading  # noqa: E402

import requests  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from shutter_governance_protocol.adapters.memory import InMemoryDataLayer  # noqa: E402
from shutter_governance_protocol.core.config import (  # noqa: E402
    DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant,
)
from shutter_governance_protocol.crypto.dkg import KeyperDKGState  # noqa: E402
from shutter_governance_protocol.crypto.points import g2_to_compressed  # noqa: E402
from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord  # noqa: E402
from shutter_governance_protocol.services.keyper import build_keyper_app  # noqa: E402

from conftest import ManualClock  # noqa: E402

_EID = (1).to_bytes(32, "big")  # in-memory adapter assigns the first election id = 1
_N, _T = 3, 2  # _T is the quorum


class _Cluster:
    """A live 3-keyper HTTP cluster on one data layer, bootstrapped (peers + enc keys)."""

    def __init__(self, tmp_path):
        self.eid = _EID
        self.eid_hex = _EID.hex()
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()
        self.admin = Signer.generate()
        self.signers = [Signer.generate() for _ in range(_N)]
        config = ElectionConfig(
            election_id=_EID, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=1000, voting_end=2000, threshold=Threshold(t=_T, n=_N),
            keypers=tuple(KeyperIdentity(signing_key=self.signers[i].identity, url="") for i in range(_N)),
            eligibility_key=b"\xe1" * 48, result_publisher_key=Signer.generate().identity,
            gateway_keys=(Signer.generate().identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        self.dl.register_election(config, self.admin.sign_register(config))
        self._servers = []
        self.urls = {}
        for i in range(1, _N + 1):
            app = build_keyper_app(self.signers[i - 1], self.dl, self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"k{i}")
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            self.urls[i] = f"http://127.0.0.1:{srv.server_port}"
        self.api_tokens, self.peer_tokens = coord.bootstrap_keypers(
            self.coordinator, self.urls,
            member_addrs={i: self.signers[i - 1].identity for i in self.urls})

    def shutdown(self):
        for srv in self._servers:
            srv.shutdown()

    def call(self, i, phase):
        return requests.post(self.urls[i] + "/dkg/" + phase, json={"electionId": self.eid_hex},
                             headers={"Authorization": f"Bearer {self.api_tokens[i]}"})

    def enc_pub(self, i):
        st = requests.get(self.urls[i] + "/status").json()
        return X25519PublicKey.from_public_bytes(bytes.fromhex(st["encryptionPubkey"]))

    def accusation(self, accused_dealer, recipient, *, signer=None, eid=None):
        eid = eid if eid is not None else self.eid
        signer = signer or self.signers[recipient - 1]
        sig = write_auth.sign_digest(signer.private_key, write_auth.dkg_accusation_digest(eid, accused_dealer, recipient))
        return {"electionId": eid.hex(), "accusedDealerIndex": accused_dealer,
                "recipientIndex": recipient, "signature": "0x" + sig.hex()}

    def reveal(self, dealer_i, accusation):
        return requests.post(self.urls[dealer_i] + "/dkg/reveal_share", json={"accusation": accusation},
                             headers={"Authorization": f"Bearer {self.api_tokens[dealer_i]}"})


@pytest.fixture
def cluster(tmp_path):
    c = _Cluster(tmp_path)
    try:
        yield c
    finally:
        c.shutdown()


class TestRevealShareGate:
    """/dkg/reveal_share re-deals a share ONLY on a valid recipient-signed accusation
    naming that dealer; every other case is a uniform 401."""

    def _pending(self, cluster):
        assert cluster.call(1, "round1").status_code == 200  # keyper 1 now holds shares_for_others

    def test_valid_accusation_redeals_to_the_recipient_only(self, cluster):
        """A valid accusation re-deals the share — **sealed to the recipient**, never
        returned to the caller. The caller (the coordinator) learns only that it happened;
        handing it the scalar is what used to break "shares never traverse the coordinator"
       ."""
        self._pending(cluster)
        r = cluster.reveal(1, cluster.accusation(accused_dealer=1, recipient=2))  # recipient 2 accuses dealer 1
        assert r.status_code == 200
        body = r.json()
        assert body == {"ok": True, "dealerIndex": 1, "recipientIndex": 2}
        # Nothing share-shaped may appear in the response, under any key.
        assert "share" not in body and "signature" not in body
        assert not any("share" in str(k).lower() for k in body if k != "ok"), body

    def test_missing_accusation_is_400(self, cluster):
        self._pending(cluster)
        r = requests.post(cluster.urls[1] + "/dkg/reveal_share", json={},
                          headers={"Authorization": f"Bearer {cluster.api_tokens[1]}"})
        assert r.status_code == 400

    def test_wrong_signer_rejected(self, cluster):
        self._pending(cluster)
        # Accusation claims recipient 2 but is signed by keyper 3 → recovered != member(2).
        acc = cluster.accusation(accused_dealer=1, recipient=2, signer=cluster.signers[2])
        assert cluster.reveal(1, acc).status_code == 401

    def test_wrong_accused_dealer_rejected(self, cluster):
        self._pending(cluster)
        # A valid accusation against dealer 2, presented to dealer 1 → not this dealer → 401.
        assert cluster.reveal(1, cluster.accusation(accused_dealer=2, recipient=3)).status_code == 401

    def test_election_mismatch_rejected(self, cluster):
        self._pending(cluster)
        other = (999).to_bytes(32, "big")
        assert cluster.reveal(1, cluster.accusation(accused_dealer=1, recipient=2, eid=other)).status_code == 401

    def test_reveal_requires_bearer(self, cluster):
        self._pending(cluster)
        r = requests.post(cluster.urls[1] + "/dkg/reveal_share",
                          json={"accusation": cluster.accusation(1, 2)})  # no token
        assert r.status_code in (401, 503)


class TestReceiveShareSealed:
    """/dkg/receive_share accepts only sealed+signed shares; plaintext is refused."""

    def _sealed(self, cluster, dealer, recipient, value):
        sealed = boot.seal_share(value, cluster.enc_pub(recipient))
        sig = write_auth.sign_digest(
            cluster.signers[dealer - 1].private_key, write_auth.dkg_share_digest(cluster.eid, dealer, recipient, value))
        return {"electionId": cluster.eid_hex, "dealerIndex": dealer, "recipientIndex": recipient,
                "sealedShare": sealed, "signature": "0x" + sig.hex()}

    def _post(self, cluster, recipient, body):
        return requests.post(cluster.urls[recipient] + "/dkg/receive_share", json=body,
                             headers={"Authorization": f"Bearer {cluster.peer_tokens[recipient]}"})

    def test_sealed_signed_share_accepted_and_append_only(self, cluster):
        assert self._post(cluster, 1, self._sealed(cluster, 2, 1, 42)).status_code == 200
        # A different share from the same dealer is rejected → the first was stored (evidence).
        assert self._post(cluster, 1, self._sealed(cluster, 2, 1, 43)).status_code == 409

    def test_plaintext_share_rejected(self, cluster):
        body = {"electionId": cluster.eid_hex, "dealerIndex": 2, "recipientIndex": 1, "share": "0x2a",
                "signature": "0x00"}
        assert self._post(cluster, 1, body).status_code == 400

    def test_forged_dealer_signature_rejected(self, cluster):
        body = self._sealed(cluster, 2, 1, 42)
        # Re-sign with the wrong key (keyper 3, not dealer 2) → recovered != member(2).
        bad = write_auth.sign_digest(cluster.signers[2].private_key,
                                     write_auth.dkg_share_digest(cluster.eid, 2, 1, 42))
        body["signature"] = "0x" + bad.hex()
        assert self._post(cluster, 1, body).status_code == 401


class TestReceiveCommitmentsSigned:
    def _commitments(self):
        st = KeyperDKGState(); st.round1(2, _N, _T)
        return [g2_to_compressed(c) for c in st.commitments]

    def _post(self, cluster, dealer, commitments, sig_hex):
        return requests.post(cluster.urls[1] + "/dkg/receive_commitments",
                             json={"electionId": cluster.eid_hex, "dealerIndex": dealer,
                                   "commitments": [c.hex() for c in commitments], "signature": sig_hex},
                             headers={"Authorization": f"Bearer {cluster.peer_tokens[1]}"})

    def test_valid_signature_accepted(self, cluster):
        c = self._commitments()
        sig = write_auth.sign_digest(cluster.signers[1].private_key, write_auth.dkg_commitments_digest(cluster.eid, 2, c))
        assert self._post(cluster, 2, c, "0x" + sig.hex()).status_code == 200

    def test_forged_signature_rejected(self, cluster):
        c = self._commitments()
        bad = write_auth.sign_digest(cluster.signers[2].private_key, write_auth.dkg_commitments_digest(cluster.eid, 2, c))
        assert self._post(cluster, 2, c, "0x" + bad.hex()).status_code == 401

    def test_wrong_commitment_count_rejected(self, cluster):
        """A dealer must publish exactly `quorum` commitments. One more would let it
        deal a polynomial one degree too high whose shares all still pass Feldman
        verification — the DKG would finalize and every decryption-share DLEQ would verify,
        yet no quorum-sized subset could recover the tally. Refused at the door, correctly
        signed or not."""
        st = KeyperDKGState(); st.round1(2, _N, _T + 1)          # one commitment too many
        c = [g2_to_compressed(p) for p in st.commitments]
        assert len(c) == _T + 1  # honest is _T; this is one too many
        sig = write_auth.sign_digest(cluster.signers[1].private_key,
                                     write_auth.dkg_commitments_digest(cluster.eid, 2, c))
        r = self._post(cluster, 2, c, "0x" + sig.hex())
        assert r.status_code == 400
        assert "commitments" in r.text.lower()

    def test_short_commitment_count_rejected(self, cluster):
        st = KeyperDKGState(); st.round1(2, _N, _T)
        c = [g2_to_compressed(p) for p in st.commitments][:-1]   # one too few
        sig = write_auth.sign_digest(cluster.signers[1].private_key,
                                     write_auth.dkg_commitments_digest(cluster.eid, 2, c))
        assert self._post(cluster, 2, c, "0x" + sig.hex()).status_code == 400


def test_round2_emits_accusation_that_unlocks_reveal(cluster):
    """A recipient handed a share inconsistent with the dealer's commitments returns a
    signed DKG-ACCUSE-v1, and that accusation unlocks the accused dealer's reveal."""
    c = cluster
    for i in (1, 2, 3):
        assert c.call(i, "round1").status_code == 200
        assert c.call(i, "distribute_commitments").status_code == 200
    assert c.call(3, "distribute_shares").status_code == 200  # honest share dealer3 → keyper1
    # Malicious dealer 2 → keyper1: a validly-signed but VSS-inconsistent share.
    bad_val = 123456789
    sealed = boot.seal_share(bad_val, c.enc_pub(1))
    sig = write_auth.sign_digest(c.signers[1].private_key, write_auth.dkg_share_digest(c.eid, 2, 1, bad_val))
    r = requests.post(c.urls[1] + "/dkg/receive_share",
                      json={"electionId": c.eid_hex, "dealerIndex": 2, "recipientIndex": 1,
                            "sealedShare": sealed, "signature": "0x" + sig.hex()},
                      headers={"Authorization": f"Bearer {c.peer_tokens[1]}"})
    assert r.status_code == 200

    resp = c.call(1, "round2").json()
    assert resp["verified"] is False
    accs = resp["accusations"]
    assert [a["accusedDealerIndex"] for a in accs] == [2]
    acc = accs[0]
    assert acc["recipientIndex"] == 1
    # It verifies against keyper 1's (the accuser's) member address …
    assert write_auth.recover_digest(
        write_auth.dkg_accusation_digest(c.eid, 2, 1),
        bytes.fromhex(acc["signature"].removeprefix("0x"))) == c.signers[0].identity
    # … and unlocks dealer 2's reveal of the share it dealt to keyper 1.
    rev = c.reveal(2, acc)
    assert rev.status_code == 200
    assert rev.json()["recipientIndex"] == 1


def _fake_record():
    """Just enough of an ElectionRecord for run_dkg_http's dispute step: a 2-of-3 committee."""
    from types import SimpleNamespace

    keypers = tuple(SimpleNamespace(signing_key=bytes([i]) * 20) for i in (1, 2, 3))
    return SimpleNamespace(config=SimpleNamespace(threshold=SimpleNamespace(quorum=2), keypers=keypers))


def test_run_dkg_http_repairs_then_publishes_despite_a_persistent_complaint(monkeypatch):
    """One member returning verified:false must NOT be able to halt the ceremony.

    The coordinator now drives accuse → re-deal → re-verify a bounded number of times, then
    publishes with whoever holds a verified share. A keyper that keeps complaining after the
    dealer has re-dealt only excludes *itself* from decryption; the remaining quorum still
    finalizes the key. Previously this raised DKGComplaint and never called publish, which
    handed any single member a veto over key generation for every election."""
    urls = {1: "http://k1", 2: "http://k2", 3: "http://k3"}
    api = {1: "t1", 2: "t2", 3: "t3"}
    seen = []

    class _Resp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload
        def raise_for_status(self):
            pass
        def json(self):
            return self._payload

    def fake_post(url, json=None, headers=None, timeout=None):
        phase = url.rsplit("/", 1)[-1]
        seen.append(phase)
        if phase == "round2" and url.startswith("http://k2"):
            return _Resp({"verified": False, "complaints": [1],
                          "accusations": [{"electionId": _EID.hex(), "accusedDealerIndex": 1,
                                           "recipientIndex": 2, "signature": "0xabcd"}]})
        if phase == "round2":
            return _Resp({"verified": True})
        return _Resp({"ok": True})

    monkeypatch.setattr(coord.requests, "post", fake_post)

    class _DL:  # the quorum of honest keypers finalized the key
        def get_finalized_key(self, _eid):
            return object()

        def get_dkg_submissions(self, _eid):  # no earlier vote, so a full ceremony runs
            return []

        def get_election(self, _eid):
            return _fake_record()

    assert coord.run_dkg_http(_EID, urls, api, _DL()) is True

    # The accused dealer was asked to re-deal to its accuser once per repair round, then
    # once more publicly. This fake answers without a share, so the dealer is excluded...
    assert seen.count("reveal_share") == coord._MAX_REPAIR_ROUNDS + 1
    # ...the accuser was re-verified after each attempt (initial round2 on all 3, then the
    # accuser alone on each retry), and everyone re-ran round 2 after the exclusion...
    assert seen.count("round2") == 3 + coord._MAX_REPAIR_ROUNDS + 3
    # ...and the ceremony reached publish, for the two keypers that hold a verified share.
    assert seen.count("publish") == 2, "the persistent complainer must be skipped, not the ceremony"


def test_run_dkg_http_raises_when_the_quorum_cannot_publish(monkeypatch):
    """The complaint is only terminal when it actually costs the quorum. With 2 of 3
    complaining, one publisher is below the quorum of 2, so nothing finalizes and the signed
    evidence is surfaced — the failure mode is real scarcity, not a single veto."""
    urls = {1: "http://k1", 2: "http://k2", 3: "http://k3"}
    api = {1: "t1", 2: "t2", 3: "t3"}

    class _Resp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload
        def raise_for_status(self):
            pass
        def json(self):
            return self._payload

    def fake_post(url, json=None, headers=None, timeout=None):
        phase = url.rsplit("/", 1)[-1]
        if phase == "round2" and (url.startswith("http://k2") or url.startswith("http://k3")):
            accuser = 2 if url.startswith("http://k2") else 3
            return _Resp({"verified": False, "complaints": [1],
                          "accusations": [{"electionId": _EID.hex(), "accusedDealerIndex": 1,
                                           "recipientIndex": accuser, "signature": "0xabcd"}]})
        if phase == "round2":
            return _Resp({"verified": True})
        return _Resp({"ok": True})

    monkeypatch.setattr(coord.requests, "post", fake_post)

    class _DL:
        def get_finalized_key(self, _eid):
            return None

        def get_dkg_submissions(self, _eid):
            return []

        def get_election(self, _eid):
            return _fake_record()

    with pytest.raises(coord.DKGComplaint) as ei:
        coord.run_dkg_http(_EID, urls, api, _DL())
    assert ei.value.accusations, "the signed evidence must still be surfaced"
    assert "did not finalize" in str(ei.value)


def test_reveal_share_logs_disclosure(cluster, caplog):
    """A genuine share reveal is a security-significant disclosure — it must be logged."""
    assert cluster.call(1, "round1").status_code == 200
    with caplog.at_level("WARNING", logger="shutter_governance_protocol.keyper"):
        assert cluster.reveal(1, cluster.accusation(accused_dealer=1, recipient=2)).status_code == 200
    assert any("phase=reveal_share status=revealed" in r.getMessage() for r in caplog.records)


def test_reveal_share_logs_denial_reason(cluster, caplog):
    """A denied reveal logs the specific reason server-side (client still gets a uniform 401)."""
    assert cluster.call(1, "round1").status_code == 200
    with caplog.at_level("WARNING", logger="shutter_governance_protocol.keyper"):
        # Valid accusation against dealer 2, presented to dealer 1 → denied (wrong dealer).
        assert cluster.reveal(1, cluster.accusation(accused_dealer=2, recipient=3)).status_code == 401
    msgs = [r.getMessage() for r in caplog.records]
    assert any("phase=reveal_share status=denied" in m and "wrong_dealer_or_recipient" in m for m in msgs)


def test_over_long_commitments_halt_the_ceremony_with_the_dealer_named(cluster):
    """End-to-end: a dealer publishing t+2 commitments is refused at ingest and then
    named by round2, so the ceremony halts with attribution instead of finalizing a key
    whose tally can never be recovered.

    Unlike a bad *share*, this fault needs no reveal to adjudicate: commitments are
    broadcast and dealer-signed, so every honest keyper reaches the same verdict from
    public data alone.
    """
    c = cluster
    for i in (1, 2, 3):
        assert c.call(i, "round1").status_code == 200
    # Honest dealers broadcast normally.
    for i in (1, 3):
        assert c.call(i, "distribute_commitments").status_code == 200

    # Dealer 2 goes rogue: a correctly-signed but one-degree-too-high commitment vector.
    rogue = KeyperDKGState(); rogue.round1(2, _N, _T + 1)
    comms = [g2_to_compressed(p) for p in rogue.commitments]
    sig = write_auth.sign_digest(c.signers[1].private_key,
                                 write_auth.dkg_commitments_digest(c.eid, 2, comms))
    r = requests.post(c.urls[1] + "/dkg/receive_commitments",
                      json={"electionId": c.eid_hex, "dealerIndex": 2,
                            "commitments": [x.hex() for x in comms], "signature": "0x" + sig.hex()},
                      headers={"Authorization": f"Bearer {c.peer_tokens[1]}"})
    assert r.status_code == 400, "keyper 1 must refuse the malformed vector at ingest"

    # It still deals shares, so keyper 1 holds a share from dealer 2 with no commitments.
    assert c.call(2, "distribute_shares").status_code == 200
    assert c.call(3, "distribute_shares").status_code == 200

    resp = c.call(1, "round2").json()
    assert resp["verified"] is False
    assert [a["accusedDealerIndex"] for a in resp["accusations"]] == [2]
    # The accusation is this keyper's own signed statement, bound to the election.
    acc = resp["accusations"][0]
    assert acc["recipientIndex"] == 1
    assert write_auth.recover_digest(
        write_auth.dkg_accusation_digest(c.eid, 2, 1),
        bytes.fromhex(acc["signature"].removeprefix("0x"))) == c.signers[0].identity
    # And no key is published: publish self-guards on round2 having completed, so this
    # keyper cannot submit a joint key it holds no combined share for.
    pub = c.call(1, "publish")
    assert pub.status_code == 409
    assert "round 2 has not completed" in pub.text


# --------------------------------------------------------------------------- #
#  Repair loop: complaint → re-deal → round 2 succeeds
# --------------------------------------------------------------------------- #

def _dealer_deals_one_bad_share(dealer, victim, monkeypatch):
    """Make `dealer` deal a share to `victim` that is correctly signed but inconsistent
    with its own commitments — the only way to produce a real Feldman failure.

    In-flight corruption cannot model this: `receive_share` verifies the dealer's signature
    over the *unsealed* scalar, so a mangled share is rejected at ingest and never stored.
    A stored-but-invalid share therefore requires the dealer itself to sign the wrong value.

    Returns a handle so the test can restore the correct value, modelling a dealer that
    re-deals honestly once accused.
    """
    from shutter_governance_protocol.crypto.dkg import KeyperDKGState

    holder = {}
    real_round1 = KeyperDKGState.round1

    def patched_round1(self, keyper_id, n, quorum):
        comms, shares = real_round1(self, keyper_id, n, quorum)
        if keyper_id == dealer:
            holder["state"] = self          # `shares` IS self.shares_for_others
            holder["good"] = shares[victim]
            shares[victim] = (shares[victim] + 1) % CURVE_ORDER
        return comms, shares

    monkeypatch.setattr(KeyperDKGState, "round1", patched_round1)
    return holder


def test_corrupted_share_is_repaired_by_redeal_and_round2_then_succeeds(cluster, monkeypatch):
    """The end-to-end DKG repair on live keypers.

    Before the fix this ceremony was terminal: the victim complained, the coordinator raised
    DKGComplaint, and the re-deal could not even have been served because round 2 had
    already zeroized the dealer's outbound shares.
    """
    c = cluster
    dealer, victim = 2, 1
    holder = _dealer_deals_one_bad_share(dealer, victim, monkeypatch)

    for phase in ("round1", "distribute_commitments", "distribute_shares"):
        for i in (1, 2, 3):
            assert c.call(i, phase).status_code == 200, f"{phase} on keyper {i}"

    # The victim complains and names the dealer; nobody else is affected.
    r = c.call(victim, "round2").json()
    assert r["verified"] is False and r["accusations"][0]["accusedDealerIndex"] == dealer
    for i in (2, 3):
        assert c.call(i, "round2").json()["verified"] is True

    # The dealer re-deals honestly. NOTE: writing the good value back here also repopulates
    # `shares_for_others`, so this test cannot by itself prove the retention property —
    # that is covered by test_dealer_can_still_serve_a_reveal_after_its_own_round2.
    holder["state"].shares_for_others[victim] = holder["good"]
    redeal = requests.post(c.urls[dealer] + "/dkg/reveal_share",
                           json={"accusation": c.accusation(dealer, victim)},
                           headers={"Authorization": f"Bearer {c.api_tokens[dealer]}"})
    assert redeal.status_code == 200, redeal.text

    # The replacement verifies, so round 2 now succeeds and all three publish one key.
    assert c.call(victim, "round2").json()["verified"] is True
    for i in (1, 2, 3):
        assert c.call(i, "publish").status_code == 200
    assert c.dl.get_finalized_key(c.eid) is not None


def test_reveal_share_cannot_be_used_to_inject_a_bad_share(cluster, monkeypatch):
    """The repair channel is not a hole in the anti-equivocation guard: a replacement is
    accepted only if it verifies against the dealer's published commitments."""
    c = cluster
    dealer, victim = 2, 1
    holder = _dealer_deals_one_bad_share(dealer, victim, monkeypatch)
    for phase in ("round1", "distribute_commitments", "distribute_shares"):
        for i in (1, 2, 3):
            c.call(i, phase)
    assert c.call(victim, "round2").json()["verified"] is False

    # Re-deal a DIFFERENT but still-invalid share. The victim must refuse it outright rather
    # than replace one bad share with another.
    holder["state"].shares_for_others[victim] = (holder["good"] + 7) % CURVE_ORDER
    redeal = requests.post(c.urls[dealer] + "/dkg/reveal_share",
                           json={"accusation": c.accusation(dealer, victim)},
                           headers={"Authorization": f"Bearer {c.api_tokens[dealer]}"})
    assert redeal.status_code == 500, "the recipient rejected it, so the dealer's POST fails"
    assert c.call(victim, "round2").json()["verified"] is False  # still broken, not silently "fixed"


def test_reveal_share_requires_a_recipient_signed_accusation(cluster):
    """A dealer re-deals only on evidence from that share's own recipient, so the
    coordinator cannot make it disclose to anyone else."""
    c = cluster
    for phase in ("round1", "distribute_commitments", "distribute_shares"):
        for i in (1, 2, 3):
            c.call(i, phase)
    hdr = {"Authorization": f"Bearer {c.api_tokens[2]}"}
    # No accusation at all → 400 (malformed body; saying so leaks no state), matching
    # Every *gate* failure below is a uniform 401 so a prober cannot tell
    # which check failed.
    assert requests.post(c.urls[2] + "/dkg/reveal_share", json={}, headers=hdr).status_code == 400
    # Accusation signed by the WRONG keyper (3 signing as if it were 1).
    forged = c.accusation(2, 1, signer=c.signers[2])
    assert requests.post(c.urls[2] + "/dkg/reveal_share", json={"accusation": forged}, headers=hdr).status_code == 401
    # Naming a different dealer than the one being asked.
    assert requests.post(c.urls[3] + "/dkg/reveal_share", json={"accusation": c.accusation(2, 1)},
                         headers={"Authorization": f"Bearer {c.api_tokens[3]}"}).status_code == 401


def test_dealer_can_still_serve_a_reveal_after_its_own_round2(cluster):
    """The retention property that makes the whole repair possible.

    Complaints only surface after round 2 has run on every keyper, so by the time a dealer
    is asked to re-deal, its own round 2 has usually already succeeded. Round 2 used to
    zeroize `shares_for_others` at that point, which made both `/dkg/reveal_share` and
    `/dkg/redeal` return 401 for exactly the dealers most likely to be accused. Zeroization
    now happens at publish instead.
    """
    c = cluster
    dealer, recipient = 2, 1
    for phase in ("round1", "distribute_commitments", "distribute_shares"):
        for i in (1, 2, 3):
            assert c.call(i, phase).status_code == 200

    # The dealer completes its OWN round 2 first — the ordering that used to break this.
    assert c.call(dealer, "round2").json()["verified"] is True

    acc = c.accusation(dealer, recipient)
    assert c.reveal(dealer, acc).status_code == 200, "dealer must still hold the dealt share"
    redeal = requests.post(c.urls[dealer] + "/dkg/reveal_share", json={"accusation": acc},
                           headers={"Authorization": f"Bearer {c.api_tokens[dealer]}"})
    assert redeal.status_code == 200

    # ...and once it publishes, the dealing material IS dropped.
    for i in (1, 3):
        c.call(i, "round2")
    assert c.call(dealer, "publish").status_code == 200
    assert c.reveal(dealer, acc).status_code == 401, "publish must zeroize the dealing material"
