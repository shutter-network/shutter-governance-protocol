"""Election admin service.

The sole writer of election config: registers elections with full parameter
validation (including the DKG lead-time gate), cancels strictly before
``voting_start``, and triggers tallying. Config becomes immutable after
``voting_start`` (enforced by the data layer).

Exposed three ways over the same pure functions: a CLI (``register`` / ``cancel``),
and an admin-only HTTP service (``serve``) a frontend can drive. The committee for
an election — keyper identities **and their URLs** — is part of the register config,
so a new election can name a different or partly-replaced keyper set (k1,k2,k3 vs
k2,k3,k4); on the database backend those URLs are stored and read back by the
coordinator (no env needed).

Auth is model **B**: the admin authorizes each write with a **wallet signature** from
the admin EOA (the frontend signs; there is no shared bearer token). The admin EOA is
one identity shared across the wallet, ``config.admin_key``, and the service's
``ADMIN_SIGNING_KEY``. The HTTP service **relays** the frontend's signature: the
database data layer ``ecrecover``s it against ``config.admin_key``; on the blockchain
backend the service fires the tx with that same EOA (so ``msg.sender == adminAddr``),
and the frontend signature is the gate the service verifies before firing.
"""

from __future__ import annotations

import logging
import threading

from shutter_governance_protocol.core import authz
from shutter_governance_protocol.core.authz import Signer, verify_register, verify_request
from shutter_governance_protocol.core.config import ElectionConfig
from shutter_governance_protocol.services.data_layer.data_layer import MAX_CONTENT_LENGTH
from shutter_governance_protocol.ports.data_layer import ElectionDataLayer, WriteAuthorizationError

_LOG = logging.getLogger("shutter_governance_protocol.admin")


class RegistrationError(ValueError):
    """Config rejected before the data layer is touched. ``code`` is a stable machine id
    for HTTP clients (e.g. ``InsufficientDkgLeadTime``); ``str(self)`` is human-readable."""

    def __init__(self, message: str, *, code: str = "RegistrationError"):
        super().__init__(message)
        self.code = code


def _short(addr: bytes) -> str:
    """Short 0x address (0xabcd…1234) for human-readable, actionable error messages."""
    h = addr.hex()
    return f"0x{h[:4]}…{h[-4:]}" if len(h) >= 8 else f"0x{h}"


def register_election(
    dl: ElectionDataLayer,
    config: ElectionConfig,
    admin_sig: bytes,
    *,
    admin_identity: bytes,
    clock,
    dkg_lead_time: int,
) -> bytes:
    """Register an election, authorized by a relayed admin **signature**.

    ``admin_sig`` is the admin EOA's EIP-191 signature over the config (from the wallet,
    or the CLI signing locally). We enforce ``config.admin_key == admin_identity`` (so
    the on-chain ``adminAddr`` the service will set as the tx sender matches the config's
    admin) and verify the signature recovers to it. Then the same signature is relayed to
    the data layer (the database backend re-``ecrecover``s it; the chain adapter fires the
    tx as this EOA). Rejected unless ``voting_start - now >= dkg_lead_time``.
    """
    if config.admin_key != admin_identity:
        raise RegistrationError(
            f"This wallet is not the election administrator, so it "
            f"cannot register elections. Connect the admin wallet and try again.",
            code="NotAdminWallet",
        )
    if not verify_register(config.admin_key, admin_sig, config):
        raise WriteAuthorizationError(
            "Could not verify your admin signature on this registration. Reconnect your wallet and sign again.")
    now = clock()
    lead = config.voting_start - now
    if lead < dkg_lead_time:
        raise RegistrationError(
            f"Voting start is too soon for DKG: only {lead}s until voting starts, "
            f"but at least {dkg_lead_time}s is required. Choose a later voting start.",
            code="InsufficientDkgLeadTime",
        )
    eid = dl.register_election(config, admin_sig)
    _LOG.info("op=register status=ok election=%s keypers=%d voting_start=%d self_submit_fee_wei=%d",
              eid.hex(), len(config.keypers), config.voting_start, config.self_submit_fee_wei)
    return eid


def cancel_election(dl: ElectionDataLayer, election_id: bytes, admin_sig: bytes, *, admin_identity: bytes) -> None:
    """Cancel before ``voting_start``, authorized by a relayed admin signature.

    Verifies ``admin_sig`` recovers to *this election's* admin and that it is our admin
    identity, then relays it (the data layer rejects a cancel once voting has started)."""
    admin_key = dl.get_election(election_id).config.admin_key
    if admin_key != admin_identity:
        raise WriteAuthorizationError(
            f"This wallet is not the admin wallet, so it cannot cancel this election.")
    if not verify_request(admin_key, admin_sig, "cancel", election_id):
        raise WriteAuthorizationError(
            "Could not verify that you are this election's administrator. Connect the admin wallet that "
            "registered it and sign again.")
    dl.cancel_election(election_id, admin_sig)
    _LOG.info("op=cancel status=ok election=%s", election_id.hex())


class RetryRequests:
    """Retry requests this admin service has already relayed, so each is used once.

    The memory and database data layers refuse a reused or stale request themselves; the
    chain adapter sends ``clearTallyStalled`` as the admin's own account and checks
    neither, so this service is the only gate there. Without it, anyone who saw one retry
    request could resend it after every later stall, un-stalling the tally and spending
    the admin's gas each time. Held in memory: after a restart a request could be reused
    only within what remains of its freshness window.
    """

    def __init__(self) -> None:
        self._used: set[tuple[bytes, int]] = set()
        self._lock = threading.Lock()

    def reserve(self, election_id: bytes, issued_at: int) -> bool:
        with self._lock:
            key = (bytes(election_id), int(issued_at))
            if key in self._used:
                return False
            self._used.add(key)
            return True

    def release(self, election_id: bytes, issued_at: int) -> None:
        with self._lock:
            self._used.discard((bytes(election_id), int(issued_at)))


def retry_tally(dl: ElectionDataLayer, election_id: bytes, admin_sig: bytes, *, admin_identity: bytes,
                issued_at: int, now: int | None = None, used: RetryRequests | None = None) -> None:
    """Clear a stalled tally (the admin **retry**), authorized by a relayed admin signature.

    Verifies ``admin_sig`` (op ``"tally_resume"``) recovers to this election's admin and that
    it is our admin identity, then relays the clear. Only the admin can clear; the coordinator
    resumes driving on its next poll with a fresh attempt budget. Bring the keypers back first
    — retrying while they are still down just re-stalls."""
    admin_key = dl.get_election(election_id).config.admin_key
    if admin_key != admin_identity:
        raise WriteAuthorizationError(
            "This wallet is not the admin wallet, so it cannot retry this election's tally.")
    # The signature binds when it was made, so a captured retry cannot be replayed to
    # un-stall a tally the coordinator has since legitimately stalled again.
    if not verify_request(admin_key, admin_sig, "tally_resume", election_id,
                          authz.request_nonce_payload(issued_at)):
        raise WriteAuthorizationError(
            "Could not verify that you are this election's administrator. Connect the admin wallet that "
            "registered it and sign again.")
    # Checked after the signature, so unauthenticated requests cannot fill `used`.
    if now is not None and not authz.request_is_fresh(issued_at, now):
        raise WriteAuthorizationError("This retry request has expired. Click Retry again to sign a new one.")
    if used is not None and not used.reserve(election_id, issued_at):
        raise WriteAuthorizationError("This retry request has already been used. Click Retry again to sign a new one.")
    try:
        dl.set_tally_stalled(election_id, False, admin_sig, issued_at)
    except Exception:
        if used is not None:
            used.release(election_id, issued_at)  # not applied, so not spent
        raise
    _LOG.info("op=retry_tally status=ok election=%s", election_id.hex())


# --------------------------------------------------------------------------- #
#  Admin HTTP service (wallet-signature authorized, admin-only, fail-closed)
# --------------------------------------------------------------------------- #

def build_admin_app(dl: ElectionDataLayer, admin_identity: bytes, *, clock):
    """Flask app exposing register/cancel, authorized by a relayed admin **signature**
    (no bearer token). ``admin_identity`` is the admin EOA's 20-byte address
    (the shared identity every request must sign as). The DKG lead-time gate is set
    per-election by the admin frontend (required ``dkgLeadTime`` body field on register);
    the service holds no default. ``/health`` is open."""
    from flask import Flask, jsonify, request

    from shutter_governance_protocol.envelopes import codecs
    from shutter_governance_protocol.ports.data_layer import ImmutabilityError

    app = Flask(__name__)
    # Bound the body every route buffers via get_json(force=True).
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    @app.after_request
    def _cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    @app.errorhandler(KeyError)
    def _not_found(e):
        return jsonify(error="NotFound", message="No election found with that id."), 404

    @app.errorhandler(WriteAuthorizationError)
    def _unauthorized(e):
        # A bad/missing admin signature is the model-B authorization failure.
        _LOG.warning("op=admin status=unauthorized reason=%s", e)
        return jsonify(error="Unauthorized", message=str(e)), 401

    @app.errorhandler(ImmutabilityError)
    def _conflict(e):
        return jsonify(error="ImmutabilityError", message=str(e)), 409

    @app.errorhandler(RegistrationError)
    def _registration(e):
        _LOG.warning("op=admin status=rejected code=%s reason=%s", e.code, e)
        return jsonify(error=e.code, message=str(e)), 400

    @app.errorhandler(ValueError)
    def _bad_request(e):
        _LOG.warning("op=admin status=rejected reason=%s", e)
        return jsonify(error="ValueError", message=str(e)), 400

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.post("/elections")
    def register():
        body = request.get_json(force=True)
        config = codecs.dec_config(body["config"])
        admin_sig = codecs.dec_bytes(body["signature"], name="signature")
        # DKG lead time is set by the admin per-election (frontend field). It gates
        # registration but is not part of the config; there is no service-side default.
        if body.get("dkgLeadTime") is None:
            raise RegistrationError(
                "DKG lead time is required — set how many seconds the key setup needs before voting opens.",
                code="MissingDkgLeadTime")
        lead = int(body["dkgLeadTime"])
        # selfSubmitFee now travels inside the signed config (config.selfSubmitFee) — it is a
        # chain-contract parameter, so unlike dkgLeadTime it is covered by the admin signature.
        eid = register_election(dl, config, admin_sig, admin_identity=admin_identity,
                                clock=clock, dkg_lead_time=lead)
        return jsonify(electionId=codecs.enc_bytes(eid)), 200

    @app.post("/elections/<eid>/cancel")
    def cancel(eid):
        body = request.get_json(force=True)
        admin_sig = codecs.dec_bytes(body["signature"], name="signature")
        cancel_election(dl, bytes.fromhex(eid), admin_sig, admin_identity=admin_identity)
        return "", 204

    retry_requests = RetryRequests()

    @app.post("/elections/<eid>/tally/retry")
    def retry_tally_route(eid):
        body = request.get_json(force=True)
        # A missing field must not reach the KeyError handler, which answers "no election".
        if "signature" not in body or "issuedAt" not in body:
            raise ValueError("A retry needs both 'signature' and 'issuedAt' (the signing time).")
        issued_at = body["issuedAt"]
        if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 0:
            raise ValueError("'issuedAt' must be a non-negative integer (unix seconds).")
        admin_sig = codecs.dec_bytes(body["signature"], name="signature")
        retry_tally(dl, bytes.fromhex(eid), admin_sig, admin_identity=admin_identity,
                    issued_at=issued_at, now=int(clock()), used=retry_requests)
        return "", 204

    return app


def main() -> None:
    """Election Admin — CLI or HTTP service. The committee
    (keyper identities + URLs) is provided in the register config.

    Commands:
      register --config <config.json>   register an election (JSON = config envelope)
      cancel   --election-id <hex>       cancel before voting_start
      serve                              run the admin HTTP service (register/cancel)

    The DKG lead-time gate (seconds of headroom required before ``voting_start``) is set
    per-election by the caller: the HTTP register takes it from the required ``dkgLeadTime``
    body field (the admin frontend), and the CLI ``register`` from ``--dkg-lead-time``
    (default 0). The service holds no default.

    Env: ``ADMIN_SIGNING_KEY`` (hex secp256k1 — the adminKey identity; the CLI signs with
    it, and on the blockchain backend it is the tx sender / on-chain ``adminAddr``),
    ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` + ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL`` (http backends). For ``serve``
    the admin **signature** authorizes each write (no bearer token); the frontend wallet
    signs and the service relays. ``ADMIN_HOST``/``ADMIN_PORT`` (default 8300).
    """
    import argparse
    import json
    import logging
    import os
    import time

    from shutter_governance_protocol.envelopes import codecs
    from shutter_governance_protocol.services.common.backend import data_layer_for_service

    parser = argparse.ArgumentParser(prog="shutter-governance-protocol-admin")
    sub = parser.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register", help="register an election from a config JSON envelope")
    reg.add_argument("--config", required=True)
    reg.add_argument("--dkg-lead-time", type=int, default=0,
                     help="seconds of headroom required before voting_start (default 0)")
    can = sub.add_parser("cancel", help="cancel an election before voting_start")
    can.add_argument("--election-id", required=True)
    sub.add_parser("serve", help="run the admin HTTP service")
    args = parser.parse_args()

    admin_key = os.environ["ADMIN_SIGNING_KEY"]
    admin = Signer.from_sk(int(admin_key, 16))
    dl = data_layer_for_service(admin_key)

    if args.command == "register":
        config = codecs.dec_config(json.loads(open(args.config).read()))
        eid = register_election(dl, config, admin.sign_register(config), admin_identity=admin.identity,
                                clock=lambda: int(time.time()), dkg_lead_time=args.dkg_lead_time)
        print("registered election", eid.hex())
    elif args.command == "cancel":
        eid = bytes.fromhex(args.election_id.removeprefix("0x"))
        cancel_election(dl, eid, admin.sign("cancel", eid), admin_identity=admin.identity)
        print("cancelled election", args.election_id)
    elif args.command == "serve":
        logging.basicConfig(level=logging.INFO)
        port = int(os.environ.get("ADMIN_PORT", "8300"))
        _LOG.info(
            "op=start service=admin port=%d admin_identity=%s auth=model-B-signature",
            port, admin.identity.hex(),
        )
        app = build_admin_app(dl, admin.identity, clock=lambda: int(time.time()))
        app.run(host=os.environ.get("ADMIN_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
