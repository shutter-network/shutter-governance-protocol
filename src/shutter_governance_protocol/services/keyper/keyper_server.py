"""Deployable keyper HTTP service (shutter_governance_protocol ports).

One process per committee member. Wraps the keyper crypto (`KeyperDKGState`,
partial decryption) behind an authenticated HTTP API the DKG coordinator drives,
with confidential round-2 shares travelling **directly keyper→keyper**. Secrets
persist encrypted at rest (:mod:`shutter_governance_protocol.services.keyper_persistence`) so the process
survives the gap between DKG and decryption.

Auth (fail-closed until bootstrapped): coordinator→keyper endpoints require the
``api_token``; keyper→keyper (`/dkg/receive_*`) require the callee's ``peer_token``;
``/status``, ``/health``, ``/auth/bootstrap`` are open. Tokens are installed via a
one-time X25519-sealed + coordinator-signed :func:`/auth/bootstrap` and persisted.

DKG peer-to-peer traffic is authenticated **and** confidential: dealers EIP-191-sign
their commitments and shares (verified against the dealer's config member address), and
each secret share travels **sealed** to the recipient's X25519 key — published and
self-bound on ``/status`` as ``encryptionPubkey`` / ``encryptionPubkeySig`` so a relayed
key is verified against the member address before anyone seals to it. A Feldman-VSS
complaint at ``/dkg/round2`` returns recipient-signed ``DKG-ACCUSE-v1`` accusations; the
accused dealer's ``/dkg/reveal_share`` discloses a share **only** on such an accusation
from that share's own recipient (so a caller can never harvest others' shares).
A complaint is then **repaired, not fatal**: ``/dkg/reveal_share`` re-seals the disputed
share straight to its recipient (never to the caller), the recipient accepts it only if it
verifies against the dealer's commitments, and round 2 is re-run for that keyper. The ceremony proceeds
as long as a quorum can publish, so no single member can veto key generation.

The server never trusts a decryption trigger — `/publish_decr_share` re-checks the
preconditions against the data layer (via :class:`KeyperService`). There is deliberately
no oracle that partial-decrypts a caller-supplied ciphertext.
"""

from __future__ import annotations

import json
import logging
import os
import threading

import requests
from flask import Flask, abort, jsonify, request

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.crypto.dkg import (
    KeyperDKGState,
    committee_keys,
    derive_joint_mpk,
    derive_mpk_share,
    qualified,
)
from shutter_governance_protocol.crypto.dkg import verify_share as dkg_verify_share
from shutter_governance_protocol.crypto.params import CURVE_ORDER
from shutter_governance_protocol.crypto.points import g2_from_compressed, g2_to_compressed
from shutter_governance_protocol.ports.data_layer import ImmutabilityError
from shutter_governance_protocol.services.common.auth import tokens_equal
from shutter_governance_protocol.services.data_layer.data_layer import MAX_CONTENT_LENGTH, PORT_READ_PREFIX
from . import keyper_bootstrap as boot
from . import keyper_persistence as persist
from .keyper import KeyperService

_OPEN = {"/status", "/health", "/auth/bootstrap"}
_PEER = {"/dkg/receive_commitments", "/dkg/receive_share"}
# Retention TTL for a keyper's per-election secrets, measured from voting_end
_DEFAULT_SECRET_RETENTION_S = 90 * 24 * 3600  # 90 days (== compose's 7776000)


def _parse_secret_ttl(raw: str | None) -> int | None:
    """Seconds to retain a per-election secret past ``voting_end``; ``never`` → ``None``.

    Not a plain ``getenv`` default: an env file or compose var that is *set but blank* yields
    ``""``, which ``int()`` rejects — the original code handled that too. ``never`` keeps the
    pre-fix indefinite behaviour available, but as a stated choice rather than a fallback.
    """
    value = (raw or "").strip()
    if value.lower() == "never":
        return None
    return int(value or _DEFAULT_SECRET_RETENTION_S)


_SECRET_RETENTION_S = _parse_secret_ttl(os.environ.get("KEYPER_SECRET_TTL_S"))


class _AccusationDenied(Exception):
    """Internal: an accusation-gated request failed a check.

    ``status`` is 400 for a malformed body (no state is leaked by saying "that isn't an
    accusation") and 401 for every gate failure — uniform, so a prober cannot learn *which*
    check failed, e.g. whether a share exists for that recipient. The reason is logged
    server-side only.
    """

    def __init__(self, reason: str, status: int = 401):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _is_benign_write_conflict(err: Exception) -> bool:
    """True if a keyper write lost a benign race: the artifact it is submitting is
    already canonical/recorded, so its (byte-identical) contribution wasn't needed.

    Happens when the ``t+1`` quorum finalizes the aggregate (or enough decryption
    shares land) just before this keyper's submission — expected with a committee
    larger than the threshold. A **direct** write raises :class:`ImmutabilityError`;
    a write **via the coordinator relay** surfaces the same as an HTTP ``409``. Either
    way it is not a fault — distinct from a real 4xx/5xx, which still propagates."""
    if isinstance(err, ImmutabilityError):
        return True
    resp = getattr(err, "response", None)  # requests.HTTPError from the relay
    return resp is not None and resp.status_code == 409


def build_keyper_app(signer, data_layer, trusted_identities, *, clock, state_dir,
                     submitter=None, logger=None):
    """Build a keyper Flask app bound to one committee identity (`signer`).

    ``trusted_identities`` is the pinned set of bootstrapper addresses the keyper
    accepts on ``/auth/bootstrap`` — a single 20-byte address or an iterable (the
    coordinator, the sole keyper bootstrapper). ``state_dir`` is this keyper's private
    encrypted-state directory. Reads go to
    ``data_layer``; **writes** (DKG result, aggregate, decryption shares) go to ``submitter`` —
    which defaults to ``data_layer`` (direct write, in-process/simple deployments) or
    is a :class:`~shutter_governance_protocol.services.coordinator.CoordinatorClient` that POSTs the signed
    artifacts to the coordinator relay (the multi-operator path). Either way the
    keyper only ever *signs* — the data layer / contract verifies authorship.
    """
    import pathlib

    submitter = submitter or data_layer
    trusted_identities = boot.as_identity_set(trusted_identities)
    log = logger or logging.getLogger("shutter_governance_protocol.keyper")
    state_dir = pathlib.Path(state_dir)
    app = Flask(__name__)
    # Bound the body every route buffers via get_json(force=True)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    lock = threading.Lock()

    @app.after_request
    def _cors(resp):
        # The admin browser app reads the open /status (GET, no custom headers → a
        # "simple" request, so no preflight) to resolve this keyper's address at
        # registration time. Expose it cross-origin. Auth'd routes still require the
        # bearer regardless of origin, so this only widens read access to /status,
        # /health, /auth/bootstrap.
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    fernet = persist.derive_fernet(signer.private_key)
    x25519 = persist.load_or_create_x25519(fernet, state_dir, log)
    # Self-sign this keyper's X25519 encryption pubkey, binding it to the keyper's
    # secp256k1 identity. Published on /status so the coordinator (before sealing a
    # bootstrap bundle) and dealers (before sealing a share) can verify a relayed key
    # against this keyper's config member address instead of trusting it blindly.
    enc_pubkey_bytes = x25519.public_key().public_bytes_raw()
    enc_pubkey_sig_hex = boot.sign_encryption_pubkey(signer, enc_pubkey_bytes).hex()
    completed: dict[str, persist.DkgEntry] = {}
    persist.load_dkg_secrets(fernet, completed, state_dir, log)
    dkg_states: dict[str, KeyperDKGState] = {}
    # election_id hex -> 'running' | 'submitted'. Guards the async /aggregate so a
    # re-trigger never starts a second computation (see the endpoint).
    aggregate_state: dict[str, str] = {}
    inbox: dict[str, dict] = {}
    nonce_tracker = boot.NonceTracker()

    tokens = persist.load_bootstrap_tokens(fernet, state_dir, log) or {}
    installed = {
        "api_token": tokens.get("api_token"),
        "peer_token": tokens.get("peer_token"),
        "relay_token": tokens.get("relay_token"),  # keyper→coordinator relay bearer (pushed via bootstrap)
        "peers": tokens.get("peers", {}),
    }

    def _apply_relay_token() -> None:
        # The relay bearer is pushed over /auth/bootstrap (not pre-shared), so point
        # the write client (CoordinatorClient) at it. Reloaded from state on restart.
        if submitter is not data_layer and hasattr(submitter, "token") and installed["relay_token"]:
            submitter.token = installed["relay_token"]

    _apply_relay_token()
    persist.start_prune_loop(completed, fernet, state_dir, log, lock)

    # -- helpers ------------------------------------------------------------ #

    def _eid(body) -> bytes:
        return bytes.fromhex(body["electionId"])

    def _config(election_id: bytes):
        return data_layer.get_election(election_id).config

    def _my_index(config) -> int:
        for i, k in enumerate(config.keypers, start=1):
            if k.signing_key == signer.identity:
                return i
        abort(403, "this keyper is not in the election's keyper set")

    def _members_addr(config, index: int) -> bytes | None:
        """The config member (signing) address for a 1-based keyper index — the trust
        anchor for verifying peer enc pubkeys and dealer/accuser signatures. Sourced
        from the data-layer config, so it is identical on the db and chain backends."""
        if 1 <= index <= len(config.keypers):
            return bytes(config.keypers[index - 1].signing_key)
        return None

    def _inbox(eid_hex: str) -> dict:
        return inbox.setdefault(eid_hex, {"commitments": {}, "shares": {}})

    def _peer(index: int) -> dict:
        return installed["peers"][str(index)]

    def _post_peer(index: int, path: str, body: dict) -> None:
        p = _peer(index)
        requests.post(p["url"].rstrip("/") + path, json=body,
                      headers={"Authorization": f"Bearer {p['token']}"}, timeout=10).raise_for_status()

    # -- auth --------------------------------------------------------------- #

    @app.before_request
    def _require_bearer():
        if request.path in _OPEN:
            return
        if installed["api_token"] is None:
            abort(503, "keyper not bootstrapped")
        tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        expected = installed["peer_token"] if request.path in _PEER else installed["api_token"]
        # Constant-time, and tolerant of a missing/None expected peer token.
        if not tokens_equal(tok, expected):
            abort(401, "bad bearer token")

    # -- status + bootstrap ------------------------------------------------- #

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.get("/status")
    def status():
        return jsonify(
            address="0x" + signer.identity.hex(),
            bootstrapped=installed["api_token"] is not None,
            encryptionPubkey=enc_pubkey_bytes.hex(),
            encryptionPubkeySig=enc_pubkey_sig_hex,  # binds the enc pubkey to this keyper's address
            elections=sorted(completed.keys()),
        )

    @app.post("/auth/bootstrap")
    def bootstrap():
        body = request.get_json(force=True)
        try:
            payload = json.loads(boot.x25519_unseal(bytes.fromhex(body["sealed"]), x25519).decode())
        except Exception:  # noqa: BLE001
            abort(400, "cannot unseal bootstrap payload")
        if not boot.verify_payload(trusted_identities, payload, bytes.fromhex(body["signature"])):
            abort(401, "untrusted bootstrapper signature")
        if not nonce_tracker.check_and_record(payload.get("nonce", ""), int(payload.get("timestamp", 0))):
            abort(401, "stale or replayed bootstrap")
        with lock:
            installed["api_token"] = str(payload["api_token"])
            installed["peer_token"] = str(payload["peer_token"])
            installed["peers"] = dict(payload["peers"])
            relay = payload.get("relay_token")
            if relay:  # pushed by the coordinator so keypers need no pre-shared relay token
                installed["relay_token"] = str(relay)
                _apply_relay_token()
            persist.save_bootstrap_tokens(fernet, installed["api_token"], installed["peer_token"],
                                          installed["peers"], state_dir, relay_token=installed["relay_token"])
        log.info("op=bootstrap status=installed peers=%d", len(installed["peers"]))
        return jsonify(ok=True)

    # -- DKG ---------------------------------------------------------------- #

    @app.post("/dkg/round1")
    def dkg_round1():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        # threshold.t IS the quorum; round1 derives the degree from it.
        n, quorum = config.threshold.n, config.threshold.quorum
        with lock:
            # A fresh round 1 draws a new polynomial, so it would replace the secret for a
            # key this keyper has already voted for. Votes are append-only, so that key
            # could then never be decrypted and this keyper could never vote for the new
            # one. The coordinator resumes with /dkg/publish instead.
            entry = completed.get(eid_hex)
            if entry is not None and entry.published:
                log.warning("op=dkg phase=round1 status=refused election=%s reason=already_published", eid_hex)
                abort(409, "this keyper already published a key for this election; resume with /dkg/publish")
            if entry is not None:
                # Unpublished key from an earlier attempt: drop it, or a later resume could
                # publish a key no other keyper holds if this attempt's round 2 fails.
                del completed[eid_hex]
                persist.save_dkg_secrets(fernet, completed, state_dir)
            st = KeyperDKGState()
            st.round1(idx, n, quorum)
            dkg_states[eid_hex] = st
            _inbox(eid_hex)  # reset/init
            inbox[eid_hex] = {"commitments": {idx: st.commitments}, "shares": {idx: st.shares_for_others[idx]},
                              "session": bytes.fromhex(str(body.get("session") or ""))}
        return jsonify(ok=True, index=idx)

    @app.post("/dkg/distribute_commitments")
    def dkg_distribute_commitments():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        commitments_c = [g2_to_compressed(c) for c in dkg_states[eid_hex].commitments]
        commitments_hex = [c.hex() for c in commitments_c]
        # Sign the commitments so a recipient can bind them to this dealer's member
        # address (defeats a peer injecting forged commitments for another dealer).
        session = _inbox(eid_hex).get("session", b"")
        sig = write_auth.sign_digest(signer.private_key,
                                     write_auth.dkg_commitments_digest(eid, idx, commitments_c, session))
        with lock:
            _inbox(eid_hex).setdefault("commitment_sigs", {})[idx] = "0x" + sig.hex()
        for peer_index in range(1, config.threshold.n + 1):
            if peer_index == idx:
                continue
            _post_peer(peer_index, "/dkg/receive_commitments",
                       {"electionId": eid_hex, "dealerIndex": idx, "commitments": commitments_hex,
                        "signature": "0x" + sig.hex()})
        return jsonify(ok=True)

    @app.post("/dkg/receive_commitments")
    def dkg_receive_commitments():
        body = request.get_json(force=True)
        eid_hex = body["electionId"]
        eid = bytes.fromhex(eid_hex)
        dealer = int(body["dealerIndex"])
        incoming = [bytes.fromhex(h) for h in body["commitments"]]
        # Verify the dealer's signature against its config member address before storing.
        config = _config(eid)
        dealer_addr = _members_addr(config, dealer)
        try:
            sig = bytes.fromhex(str(body["signature"]).removeprefix("0x"))
            ok = dealer_addr is not None and \
                write_auth.recover_digest(write_auth.dkg_commitments_digest(
                    eid, dealer, incoming, _inbox(eid_hex).get("session", b"")), sig) == dealer_addr
        except (KeyError, ValueError, TypeError):
            ok = False
        if not ok:
            log.warning("op=dkg phase=receive_commitments status=rejected election=%s dealer=%s reason=bad_signature",
                        eid_hex, dealer)
            abort(401, "bad dealer commitments signature")
        # A dealer must publish exactly t+1 commitments. A longer vector lets it deal a
        # degree-(t+1) polynomial whose shares still pass Feldman verification, so the DKG
        # finalizes and the decryption-share DLEQs verify — but no t+1 quorum can ever
        # Lagrange-interpolate the secret, leaving the election permanently untalliable.
        # Refuse at the door so a malformed vector is never stored. Unlike a bad share
        # this is publicly checkable (commitments are broadcast and dealer-signed), so
        # every honest keyper reaches this same verdict independently.
        expected_len = config.threshold.quorum  # one commitment per coefficient
        if len(incoming) != expected_len:
            log.warning("op=dkg phase=receive_commitments status=rejected election=%s dealer=%s "
                        "reason=bad_commitment_count got=%d want=%d",
                        eid_hex, dealer, len(incoming), expected_len)
            abort(400, f"dealer published {len(incoming)} commitments, expected {expected_len}")
        with lock:
            box = _inbox(eid_hex)["commitments"]
            if dealer in box:
                if [g2_to_compressed(c) for c in box[dealer]] != incoming:
                    abort(409, "different commitments already received from this dealer")
            else:
                box[dealer] = [g2_from_compressed(b) for b in incoming]
                # Kept as evidence: the coordinator compares every keyper's copy, and two
                # different vectors signed by one dealer prove it equivocated.
                _inbox(eid_hex).setdefault("commitment_sigs", {})[dealer] = "0x" + sig.hex()
        return jsonify(ok=True)

    @app.post("/dkg/commitments")
    def dkg_commitments():
        """Every dealer's commitments as this keyper received them, with the dealer's
        signature. Commitments are public; this lets the coordinator check that every
        keyper holds the same ones before any share is combined."""
        body = request.get_json(force=True)
        eid_hex = _eid(body).hex()
        with lock:
            box = _inbox(eid_hex)
            sigs = box.get("commitment_sigs", {})
            held = {
                str(dealer): {"commitments": [g2_to_compressed(c).hex() for c in comms],
                              "signature": sigs.get(dealer)}
                for dealer, comms in box["commitments"].items()
            }
        return jsonify(commitments=held)

    @app.post("/dkg/distribute_shares")
    def dkg_distribute_shares():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        st = dkg_states[eid_hex]
        for recipient in range(1, config.threshold.n + 1):
            if recipient == idx:
                continue
            # Seal each share to the recipient's X25519 key — but only after verifying that
            # key against the recipient's config member address, so a substituted key (via a
            # lying coordinator) can't redirect the plaintext; at worst it's a DoS. The
            # share is also signed (authenticity), verified over the unsealed scalar.
            enc_pub = _verified_peer_enc_key(config, eid_hex, recipient, "distribute_shares")
            _seal_and_send_share(eid, eid_hex, idx, recipient, st, enc_pub)
        return jsonify(ok=True)

    def _seal_and_send_share(eid, eid_hex, idx, recipient, st, enc_pub):
        """Seal this dealer's share for ``recipient`` and post it over the peer channel."""
        share_val = st.shares_for_others[recipient]
        sealed = boot.seal_share(share_val, enc_pub)
        sig = write_auth.sign_digest(
            signer.private_key, write_auth.dkg_share_digest(eid, idx, recipient, share_val))
        _post_peer(recipient, "/dkg/receive_share",
                   {"electionId": eid_hex, "dealerIndex": idx, "recipientIndex": recipient,
                    "sealedShare": sealed, "signature": "0x" + sig.hex()})

    def _verified_peer_enc_key(config, eid_hex, recipient, phase):
        """The recipient's X25519 key, verified against its config member address."""
        peer = _peer(recipient)
        member = _members_addr(config, recipient)
        enc_hex, enc_sig = peer.get("enc_pubkey"), peer.get("enc_pubkey_sig")
        if member is None or not enc_hex or not enc_sig:
            log.warning("op=dkg phase=%s status=error election=%s recipient=%s "
                        "reason=no_verified_enc_key (re-bootstrap needed)", phase, eid_hex, recipient)
            abort(500, f"no verified encryption key for keyper {recipient}; re-bootstrap")
        try:
            return boot.verify_encryption_pubkey(member, enc_hex, enc_sig)
        except Exception as e:  # noqa: BLE001
            log.warning("op=dkg phase=%s status=error election=%s recipient=%s "
                        "reason=enc_key_verify_failed err=%s", phase, eid_hex, recipient, e)
            abort(500, f"peer {recipient} encryption key failed verification: {e}")

    @app.post("/dkg/receive_share")
    def dkg_receive_share():
        """Receive a sealed+signed secret share from a dealer.

        The value travels sealed to this keyper's X25519 key (``sealedShare``) so a
        passive observer sees only ciphertext. Plaintext is not accepted on this path
        (multi-operator HTTP is always bootstrapped). Confidentiality (sealing) and
        authenticity (the dealer's signature over the *recovered* scalar) are independent.
        The dealer's signature is retained as evidence for a later complaint/reveal.
        """
        body = request.get_json(force=True)
        eid_hex = body["electionId"]
        eid = bytes.fromhex(eid_hex)
        config = _config(eid)
        try:
            dealer = int(body["dealerIndex"])
            recipient = int(body["recipientIndex"])
            sig_hex = str(body["signature"])
            if "sealedShare" not in body:
                log.warning("op=dkg phase=receive_share status=rejected election=%s reason=plaintext_share_refused",
                            eid_hex)
                abort(400, "sealedShare required")  # no plaintext downgrade on the HTTP path
            share = boot.unseal_share(body["sealedShare"], x25519)
        except (KeyError, ValueError, TypeError) as e:
            log.warning("op=dkg phase=receive_share status=rejected election=%s reason=bad_or_unsealable err=%s",
                        eid_hex, e)
            abort(400, f"bad share: {e}")
        if recipient != _my_index(config):
            log.warning("op=dkg phase=receive_share status=rejected election=%s dealer=%s recipient=%s "
                        "reason=recipient_mismatch", eid_hex, dealer, recipient)
            abort(400, "share recipient mismatch")
        # Verify the dealer's signature over the recovered scalar against its member address.
        dealer_addr = _members_addr(config, dealer)
        try:
            sig = bytes.fromhex(sig_hex.removeprefix("0x"))
            ok = dealer_addr is not None and \
                write_auth.recover_digest(write_auth.dkg_share_digest(eid, dealer, recipient, share), sig) == dealer_addr
        except (ValueError, TypeError):
            ok = False
        if not ok:
            log.warning("op=dkg phase=receive_share status=rejected election=%s dealer=%s reason=bad_signature",
                        eid_hex, dealer)
            abort(401, "bad dealer share signature")
        with lock:
            box = _inbox(eid_hex)
            shares = box["shares"]
            if dealer in shares and shares[dealer] != share:
                comms = box["commitments"].get(dealer)
                repairable = dealer in box.get("complained", set())
                if not (repairable and comms and dkg_verify_share(comms, recipient, share)):
                    log.warning("op=dkg phase=receive_share status=rejected election=%s dealer=%s "
                                "reason=equivocation repairable=%s", eid_hex, dealer, repairable)
                    abort(409, "different share already received from this dealer")
                log.warning("op=dkg phase=receive_share status=replaced election=%s dealer=%s "
                            "recipient=%s reason=repair_after_complaint", eid_hex, dealer, recipient)
            shares[dealer] = share
            # Retain the dealer's signed share as evidence for a complaint/reveal.
            box.setdefault("share_sigs", {})[dealer] = sig_hex
        return jsonify(ok=True)

    def _verified_exclusions(eid: bytes, config, requested: list) -> set[int]:
        """Dealers to leave out of the key, each checked against its evidence here.

        The coordinator proposes exclusions, but a keyper applies one only after verifying
        the evidence itself, so the coordinator cannot drop an honest dealer by assertion.
        Every keyper receives the same list; one that disagrees refuses (400) rather than
        silently deriving a different key. At least ``t`` dealers must remain: with fewer
        than ``t`` dishonest keypers, that keeps at least one honest dealer's randomness in
        the key, so the dishonest ones cannot know it.
        """
        out: set[int] = set()
        for item in requested:
            try:
                dealer, reason = int(item["dealer"]), str(item["reason"])
            except (KeyError, TypeError, ValueError):
                abort(400, "malformed exclusion")
            addr = _members_addr(config, dealer)
            if reason == "equivocation":
                proven = addr is not None and \
                    write_auth.proves_equivocation(eid, dealer, addr, item.get("evidence") or [],
                                                   _inbox(eid.hex()).get("session", b""))
            elif reason == "no_valid_reveal":
                # Not a proof that the dealer cheated, only a signed accusation it failed to
                # answer. That is enough: excluding a dealer drops only its contribution to
                # the key, and at least `t` dealers remain (checked below), so the key keeps
                # an honest dealer's randomness even if the accusation was false.
                proven = addr is not None and _is_member_accusation(eid, config, dealer, item.get("accusation"))
            else:
                proven = False
            if not proven:
                log.warning("op=dkg phase=round2 status=refused election=%s dealer=%s reason=unproven_exclusion",
                            eid.hex(), item.get("dealer"))
                abort(400, f"exclusion of dealer {dealer} is not backed by valid evidence")
            out.add(dealer)
        if config.threshold.n - len(out) < config.threshold.quorum:
            abort(409, "too many dealers excluded: fewer than the threshold would remain")
        if out:
            log.warning("op=dkg phase=round2 status=excluding election=%s dealers=%s", eid.hex(), sorted(out))
        return out

    def _is_member_accusation(eid: bytes, config, dealer: int, acc) -> bool:
        """Whether ``acc`` is a committee member's signed accusation of ``dealer`` for ``eid``."""
        try:
            recipient = int(acc["recipientIndex"])
            sig = bytes.fromhex(str(acc["signature"]).removeprefix("0x"))
            ok = (str(acc["electionId"]) == eid.hex() and int(acc["accusedDealerIndex"]) == dealer
                  and recipient != dealer)
            member = _members_addr(config, recipient)
            return ok and member is not None and \
                write_auth.recover_digest(write_auth.dkg_accusation_digest(eid, dealer, recipient), sig) == member
        except Exception:  # noqa: BLE001 — malformed accusation
            return False

    def _adopt_agreed_commitments(eid: bytes, config, box: dict, my_idx: int, agreed: dict) -> None:
        """Hold exactly the commitments every keyper agreed on, each checked against its
        dealer's signature for this session.

        A dealer could otherwise withhold its commitments from one keyper (which then can
        never accept a revealed share), or send it a second vector after the coordinator's
        equivocation check, so that keyper ends up on a different key.
        """
        session = box.get("session", b"")
        for dealer_s, row in agreed.items():
            try:
                dealer = int(dealer_s)
                vector = [bytes.fromhex(h) for h in row["commitments"]]
                sig = bytes.fromhex(str(row["signature"]).removeprefix("0x"))
                addr = _members_addr(config, dealer)
                ok = (dealer != my_idx and addr is not None and len(vector) == config.threshold.quorum
                      and write_auth.recover_digest(
                          write_auth.dkg_commitments_digest(eid, dealer, vector, session), sig) == addr)
                points = [g2_from_compressed(b) for b in vector] if ok else None
            except Exception:  # noqa: BLE001 — malformed: ignored, round 2 then complains
                ok = False
            if not ok:
                continue
            with lock:
                box["commitments"][dealer] = points
                box.setdefault("commitment_sigs", {})[dealer] = row["signature"]

    def _accept_revealed_shares(eid: bytes, config, box: dict, my_idx: int, revealed: list) -> None:
        """Store shares a dealer revealed publicly for this keyper, after checking them.

        Each must carry the dealer's signature over (election, dealer, this keyper, share)
        and pass the Feldman check against the commitments this keyper holds, so the
        coordinator relaying it cannot substitute a share of its own.
        """
        for item in revealed:
            try:
                dealer, share = int(item["dealer"]), int(str(item["share"]), 16)
                sig = bytes.fromhex(str(item["signature"]).removeprefix("0x"))
                comms = box["commitments"].get(dealer)
                ok = (0 <= share < CURVE_ORDER and comms is not None
                      and write_auth.recover_digest(write_auth.dkg_share_digest(eid, dealer, my_idx, share), sig)
                      == _members_addr(config, dealer)
                      and dkg_verify_share(comms, my_idx, share))
            except Exception:  # noqa: BLE001 — malformed: ignored like an invalid one
                ok = False
            if not ok:
                log.warning("op=dkg phase=round2 status=revealed_share_rejected election=%s dealer=%s",
                            eid.hex(), item.get("dealer"))
                continue
            with lock:
                box["shares"][dealer] = share
            log.info("op=dkg phase=round2 status=revealed_share_accepted election=%s dealer=%d", eid.hex(), dealer)

    @app.post("/dkg/round2")
    def dkg_round2():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        st = dkg_states[eid_hex]
        box = _inbox(eid_hex)
        my_idx = _my_index(config)
        excluded = _verified_exclusions(eid, config, body.get("excluded") or [])
        _adopt_agreed_commitments(eid, config, box, my_idx, body.get("agreed") or {})
        _accept_revealed_shares(eid, config, box, my_idx, body.get("revealed") or [])
        n, quorum = config.threshold.n, config.threshold.quorum
        dealers = [d for d in range(1, n + 1) if d not in excluded]
        try:
            st.round2(box["commitments"], box["shares"], dealers=dealers)
        except ValueError as err:
            bad = getattr(err, "bad_dealers", [])
            # Security-relevant: this keyper's VSS verification rejected a dealer's shares.
            log.warning("op=dkg phase=round2 status=verify_failed election=%s complaints=%s err=%s",
                        eid_hex, bad, err)
            # Record who we complained about. `receive_share` consults this to decide whether
            # a *replacement* share from that dealer may override the one already stored —
            # the narrow, self-owned relaxation of the anti-equivocation guard.
            with lock:
                box.setdefault("complained", set()).update(int(d) for d in bad)
            # Sign one accusation per bad dealer. This recipient-signed DKG-ACCUSE-v1 is the
            # evidence the accused dealer's gated /dkg/reveal_share requires before disclosing
            # a share, and that the coordinator surfaces on halt. We are the complaining
            # recipient (my_idx); the accusation names the accused dealer, bound to this election.
            accusations = [
                {
                    "electionId": eid_hex,
                    "accusedDealerIndex": int(bad_dealer),
                    "recipientIndex": my_idx,
                    "signature": "0x" + write_auth.sign_digest(
                        signer.private_key,
                        write_auth.dkg_accusation_digest(eid, int(bad_dealer), my_idx),
                    ).hex(),
                }
                for bad_dealer in bad
            ]
            return jsonify(verified=False, complaints=bad, accusations=accusations), 200
        # Fix the key here, next to the secret it belongs to, so every later publish (a
        # retry, or after a restart that lost the in-memory inbox) sends the same one.
        commitments = qualified(box["commitments"], excluded)
        pk_b = g2_to_compressed(derive_joint_mpk(commitments, quorum))
        committee_b = tuple(g2_to_compressed(c) for c in committee_keys(n, commitments, quorum))
        # Never vote for a key this keyper cannot decrypt under: its own entry in the
        # published committee keys must be the public half of the secret it just formed.
        # Round 2 should already guarantee this; the check makes sure no future path can
        # break it silently, since the mismatch would otherwise surface only at tally.
        if g2_to_compressed(derive_mpk_share(my_idx, commitments, quorum)) != g2_to_compressed(st.public_key_share):
            log.error("op=dkg phase=round2 status=self_check_failed election=%s keyper=%d", eid_hex, my_idx)
            return jsonify(verified=False, complaints=[], accusations=[]), 200
        with lock:
            completed[eid_hex] = persist.DkgEntry(
                combined_share=st.combined_share,
                expires_at=(int(config.voting_end) + _SECRET_RETENTION_S
                            if _SECRET_RETENTION_S is not None else None),
                pk_election=pk_b,
                committee_pks=committee_b,
            )
            persist.save_dkg_secrets(fernet, completed, state_dir)
        return jsonify(verified=True)

    @app.post("/dkg/reveal_share")
    def dkg_reveal_share():
        """Accusation-gated Feldman-VSS rebuttal: re-deal the share THIS dealer dealt to a
        recipient, *only* on a valid recipient-signed ``DKG-ACCUSE-v1`` naming this dealer
        for the pinned election. Since only recipient ``j`` can sign as ``j``, ``j`` can
        unlock only its own share ``f_i(j)`` — which it is already entitled to — so this
        discloses nothing new. The gate lives here in the handler (not ``before_request``).

        **The share is sealed to the recipient and posted directly to it; it is never
        returned to the caller.** The endpoint used to hand the plaintext scalar back in the
        response, which meant the coordinator — the party that triggers this — learned a
        share whenever a genuine complaint existed. One share is harmless, but harvesting a
        quorum of one dealer's reveals reconstructs that dealer's polynomial, and it broke
        the rule that shares never traverse the coordinator. The caller now learns only
        *that* a re-deal happened.

        The recipient accepts the re-dealt share as a replacement only if it verifies
        against this dealer's published commitments, so this cannot be used to inject a bad
        share, and only a recipient that actually complained will accept one at all.

        All gate failures return a uniform 401 so a prober cannot learn which check failed
        (e.g. whether a share exists for that recipient).
        """
        body = request.get_json(silent=True) or {}
        try:
            eid, eid_hex, config, my_idx, recipient, st = _gate_accusation(
                body.get("accusation"), "reveal_share")
        except _AccusationDenied as denied:
            return jsonify(error="unauthorized" if denied.status == 401 else denied.reason), denied.status

        if body.get("public"):
            # Last step of a dispute the sealed re-send did not settle: hand the share,
            # signed, to the coordinator, which checks it against this dealer's agreed
            # commitments and forwards it to the accuser. A dealer that cannot produce a
            # valid share here is excluded from the key. Only the accuser was entitled to
            # this share; see run_dkg_http for why disclosing it is acceptable.
            share_val = st.shares_for_others[recipient]
            sig = write_auth.sign_digest(
                signer.private_key, write_auth.dkg_share_digest(eid, my_idx, recipient, share_val))
            log.warning("op=dkg phase=reveal_share status=revealed_public election=%s dealer=%s recipient=%s",
                        eid_hex, my_idx, recipient)
            return jsonify(ok=True, dealerIndex=my_idx, recipientIndex=recipient,
                           share=hex(share_val), signature="0x" + sig.hex())
        enc_pub = _verified_peer_enc_key(config, eid_hex, recipient, "reveal_share")
        _seal_and_send_share(eid, eid_hex, my_idx, recipient, st, enc_pub)
        # A genuine disclosure — significant security event; record the who/what.
        log.warning("op=dkg phase=reveal_share status=revealed election=%s dealer=%s recipient=%s "
                    "(recipient-accusation-gated, sealed direct to recipient)",
                    eid_hex, my_idx, recipient)
        return jsonify(ok=True, dealerIndex=my_idx, recipientIndex=recipient)

    def _gate_accusation(acc, phase: str):
        """Validate a recipient-signed ``DKG-ACCUSE-v1`` naming *this* keyper as dealer.

        Returns ``(eid, eid_hex, config, my_idx, recipient, st)``; raises
        :class:`_AccusationDenied` otherwise.
        """
        if not isinstance(acc, dict):
            log.info("op=dkg phase=%s status=rejected reason=missing_accusation", phase)
            raise _AccusationDenied("missing_accusation", 400)
        try:
            acc_eid_hex = str(acc["electionId"])
            accused_dealer = int(acc["accusedDealerIndex"])
            recipient = int(acc["recipientIndex"])
            acc_sig = bytes.fromhex(str(acc["signature"]).removeprefix("0x"))
        except (KeyError, ValueError, TypeError):
            log.info("op=dkg phase=%s status=rejected reason=bad_accusation", phase)
            raise _AccusationDenied("bad_accusation", 400) from None

        def _deny(reason: str):
            # The specific reason is server-side only, so an operator can see *why* a
            # request was refused without leaking it to a prober.
            log.warning("op=dkg phase=%s status=denied election=%s accused_dealer=%s recipient=%s reason=%s",
                        phase, acc_eid_hex, accused_dealer, recipient, reason)
            return _AccusationDenied(reason)

        st = dkg_states.get(acc_eid_hex)
        if st is None:  # not mid-ceremony for this election
            raise _deny("not_in_ceremony")
        try:
            eid = bytes.fromhex(acc_eid_hex)
            config = _config(eid)
            my_idx = _my_index(config)
        except Exception:  # noqa: BLE001
            raise _deny("not_committee_member") from None
        # Must name THIS dealer, and we must actually still hold a share dealt to that
        # recipient. (`shares_for_others` survives round 2 now precisely so this works —
        # see KeyperDKGState.zeroize_dealing.)
        if accused_dealer != my_idx or recipient not in st.shares_for_others:
            raise _deny("wrong_dealer_or_recipient")
        # Signed by the recipient itself → it can only ever unlock its own share.
        expected = _members_addr(config, recipient)
        try:
            recovered = write_auth.recover_digest(
                write_auth.dkg_accusation_digest(eid, accused_dealer, recipient), acc_sig)
        except Exception:  # noqa: BLE001
            recovered = None
        if expected is None or recovered != expected:
            raise _deny("bad_accusation_signer")
        return eid, acc_eid_hex, config, my_idx, recipient, st

    @app.post("/dkg/publish")
    def dkg_publish():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        # Never trust the trigger: publish only a key this keyper actually completed
        # round 2 for. Without this, a keyper that rejected a dealer (bad share, or a
        # malformed commitment vector) would still derive a joint key from
        # whatever commitments happened to be in its inbox and submit it, even though it
        # holds no combined share for that key. If such a key reached the t+1 quorum the
        # election would finalize with a key nobody can decrypt.
        entry = completed.get(eid_hex)
        if entry is None:
            log.warning("op=dkg phase=publish status=refused election=%s reason=round2_not_completed", eid_hex)
            abort(409, "round 2 has not completed for this election; refusing to publish a key")
        if entry.pk_election is None:
            # Completed by an older version, which did not record the key; derive it from
            # the in-memory commitments as that version did.
            commitments = _inbox(eid_hex)["commitments"]
            quorum = _config(eid).threshold.quorum
            entry.pk_election = g2_to_compressed(derive_joint_mpk(commitments, quorum))
            entry.committee_pks = tuple(g2_to_compressed(c)
                                        for c in committee_keys(_config(eid).threshold.n, commitments, quorum))
        pk_b, committee_b = entry.pk_election, list(entry.committee_pks)
        sig = write_auth.sign_dkg_result(signer.private_key, eid, pk_b, committee_b)
        # Re-sending the same vote is a no-op on every backend, so this is safe to retry.
        submitter.submit_dkg_result(eid, pk_b, committee_b, sig)  # direct or via coordinator relay
        with lock:
            if not entry.published:
                entry.published = True
                persist.save_dkg_secrets(fernet, completed, state_dir)
        # Now — and not at the end of round 2 — drop the dealing material. The complaint
        # window is closed once we are publishing, so no recipient can still need a re-deal
        # from us. `combined_share` is untouched: decryption needs it.
        with lock:
            st = dkg_states.get(eid_hex)
            if st is not None:
                st.zeroize_dealing()
        return jsonify(ok=True)

    # -- aggregation (keyper-quorum; deterministic re-derivation from ballots) #

    def _run_aggregate(eid: bytes, eid_hex: str, ks) -> None:
        """Compute and submit this keyper's aggregate. Runs on a worker thread."""
        try:
            produced = ks.produce_aggregate(eid)
            if produced is not None:
                artifact, sig = produced
                try:
                    submitter.submit_aggregate(eid, artifact, sig)  # direct or via the relay
                except Exception as err:  # noqa: BLE001
                    if not _is_benign_write_conflict(err):
                        raise
                    # The t+1 quorum finalized the (identical) aggregate first — canonical
                    # already, so this keyper's contribution simply wasn't needed.
                    log.info("op=tally phase=aggregate status=already_finalized election=%s", eid_hex)
            with lock:
                aggregate_state[eid_hex] = "submitted"
            log.info("op=tally phase=aggregate status=submitted election=%s", eid_hex)
        except Exception as err:  # noqa: BLE001
            # Drop back to "not started" so a later trigger retries rather than the
            # election being stuck reporting in_progress forever.
            with lock:
                aggregate_state.pop(eid_hex, None)
            log.error("op=tally phase=aggregate status=error election=%s err=%s", eid_hex, err)

    @app.post("/aggregate")
    def aggregate():
        """Trigger this keyper's aggregate. **Asynchronous** — returns immediately.

        Aggregation re-verifies every ballot (~3 ms per proof branch, so minutes for a
        large election). Doing that inline blocked the coordinator's 30 s trigger, which
        it then read as a failed attempt and, after five polls, as a stalled tally — on a
        keyper that was working perfectly. It also blocked every *other* election, because
        the coordinator scans sequentially.

        So: preconditions are checked synchronously (cheap, and a real refusal should still
        be a 409), then the work moves to a background thread. The status tells the
        coordinator whether to keep waiting:

        * ``200 submitted``   — this keyper has already contributed
        * ``202 started``     — accepted, now computing
        * ``202 in_progress`` — already computing; **no second worker is started**
        * ``409 refused``     — a precondition failed (not tallying, no key)

        ``{"recompute": true}`` discards a previous ``submitted`` and re-derives. That is
        the committee's convergence path: a keyper's aggregate is **overridable until the
        quorum finalizes** precisely so honest keypers can re-converge after a transient
        divergence (one keyper read the ballot list a moment earlier than another — common
        on chain while a late vote is still confirming). Only the coordinator can see "all
        submitted, still no quorum", so only it asks; a keyper re-deriving on its own every
        poll would burn minutes of CPU merely waiting for slower peers. Work already in
        flight is never interrupted.
        """
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        # No persisted DKG secret needed — aggregation only reads the ordered ballot list.
        ks = KeyperService(_my_index(config), signer, data_layer, clock=clock)
        try:
            ks.check_can_aggregate(eid)
        except Exception as err:  # noqa: BLE001 — refusal / precondition failure
            log.debug("op=tally phase=aggregate status=refused election=%s reason=%s", eid_hex, err)
            return jsonify(ok=False, status="refused", reason=str(err)), 409

        recompute = bool(body.get("recompute"))
        with lock:
            state = aggregate_state.get(eid_hex)
            if state == "submitted" and not recompute:
                return jsonify(ok=True, status="submitted"), 200
            if state == "running":
                # Critical: the coordinator re-triggers every poll. Without this guard each
                # poll would spawn another worker re-verifying every ballot, and the keyper
                # would collapse under its own retries long before finishing one pass.
                return jsonify(ok=True, status="in_progress"), 202
            aggregate_state[eid_hex] = "running"

        threading.Thread(target=_run_aggregate, args=(eid, eid_hex, ks), daemon=True).start()
        log.info("op=tally phase=aggregate status=started election=%s recompute=%s", eid_hex, recompute)
        return jsonify(ok=True, status="started"), 202

    # -- partial decryption -- #

    @app.post("/publish_decr_share")
    def publish_decr_share():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        entry = completed.get(eid_hex)
        if entry is None:
            log.warning("op=tally phase=decrypt status=refused election=%s reason=no_persisted_dkg_share", eid_hex)
            abort(409, "no persisted DKG share for this election")
        config = _config(eid)
        ks = KeyperService(_my_index(config), signer, data_layer, clock=clock)  # data_layer = reads
        ks.dkg.combined_share = entry.combined_share
        ks.dkg.public_key_share = entry.public_key_share
        try:
            produced = ks.produce_decryption_share(eid)
        except Exception as err:  # noqa: BLE001 — refusal / precondition failure
            log.debug("op=tally phase=decrypt status=refused election=%s reason=%s", eid_hex, err)
            return jsonify(ok=False, reason=str(err)), 409
        if produced is not None:  # None = already submitted (idempotent)
            share, sig = produced
            try:
                submitter.submit_decryption_share(eid, share, sig)  # direct or via coordinator relay
            except Exception as err:  # noqa: BLE001
                if not _is_benign_write_conflict(err):
                    raise
                # Enough shares already recorded before this one landed — benign.
                return jsonify(ok=True, note="decryption share already recorded"), 200
        return jsonify(ok=True)

    return app


def resolve_read_url(env) -> str:
    """Resolve the keyper's read endpoint from the environment.

    A keyper only **reads** the election data (its writes go to the coordinator relay),
    and it reads them from the public API's port surface — not from the data-layer
    service, which is internal-only because its ballot write path is unauthenticated.

    ``SHUTTER_GOVERNANCE_PROTOCOL_API_URL`` is therefore the API's **base** URL (e.g. ``https://vote.example.org``
    or ``http://host.docker.internal:8500``); the keyper appends the port-surface path
    itself, so an operator never has to know or spell it.
    """
    api_url = (env.get("SHUTTER_GOVERNANCE_PROTOCOL_API_URL") or "").strip()
    if api_url:
        return api_url.rstrip("/") + PORT_READ_PREFIX

    raise SystemExit(
        "set SHUTTER_GOVERNANCE_PROTOCOL_API_URL to the public API's base URL (e.g. http://host.docker.internal:8500); "
        f"the keyper reads through its port surface at {PORT_READ_PREFIX}"
    )


def main() -> None:
    """Run one keyper process, reading through the public API's port surface.

    Env: ``KEYPER_SIGNING_KEY`` (hex secp256k1 scalar — this keyper's Ethereum
    identity, whose 20-byte address is its committee identity), ``COORDINATOR_IDENTITY``
    (hex 20-byte address the keyper pins for bootstrap auth — the coordinator is the
    **sole** bootstrapper), ``SHUTTER_GOVERNANCE_PROTOCOL_API_URL`` (the public API's **base** URL — the keyper
    appends the port read surface itself; see :func:`resolve_read_url`),
    ``COORDINATOR_URL`` (where the keyper POSTs its signed DKG result / decryption
    shares — the coordinator relays them; if unset, writes go directly to the read
    handle, which will fail against a read-only surface). The relay bearer token is
    **not** an env var: the coordinator pushes it over ``/auth/bootstrap`` and it
    persists in state. ``KEYPER_STATE_DIR``, ``KEYPER_HOST``/``KEYPER_PORT``.
    """
    import os
    import time

    from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient
    from shutter_governance_protocol.core.authz import Signer
    from shutter_governance_protocol.services.coordinator import CoordinatorClient

    logging.basicConfig(level=logging.INFO)
    signer = Signer.from_sk(int(os.environ["KEYPER_SIGNING_KEY"], 16))
    # The coordinator is the sole keyper bootstrapper; pin only its identity.
    trusted_identities = {bytes.fromhex(os.environ["COORDINATOR_IDENTITY"].removeprefix("0x"))}
    data_layer = HttpDataLayerClient(resolve_read_url(os.environ))
    state_dir = os.environ.get("KEYPER_STATE_DIR", "/keyper-state")

    # Writes go to the coordinator relay when configured; otherwise directly to the
    # data layer (reads always use the data-layer handle). The relay bearer token is
    # NOT pre-shared — the coordinator pushes it over /auth/bootstrap, and the keyper
    # applies it to this client (persisted, so it survives restart). Start empty.
    coordinator_url = os.environ.get("COORDINATOR_URL")
    submitter = CoordinatorClient(coordinator_url, "") if coordinator_url else None

    port = int(os.environ.get("KEYPER_PORT", "8100"))
    logging.getLogger("shutter_governance_protocol.keyper").info(
        "op=start service=keyper port=%d keyper_identity=%s", port, signer.identity.hex())
    app = build_keyper_app(signer, data_layer, trusted_identities,
                           clock=lambda: int(time.time()), state_dir=state_dir, submitter=submitter)
    app.run(host=os.environ.get("KEYPER_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
