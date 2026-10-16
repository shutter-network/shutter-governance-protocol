"""Uniform data-layer HTTP service.

One Flask microservice that exposes the ``ElectionDataLayer`` port over HTTP (the
JSON envelopes) wrapping **any** backend adapter — in-memory, Postgres, or
blockchain. A deployment picks the backend with ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` and every
component (keypers, gateway, coordinator, admin) speaks the same HTTP
to it via :class:`shutter_governance_protocol.adapters.db.client.HttpDataLayerClient`, unchanged. The
routes call only port methods, so the service is genuinely backend-agnostic.

All reads are public and unauthenticated; writes carry the actor's signature
which the backend verifies. Contract violations surface as typed HTTP statuses
the client maps back to the port's exception types:

    404 KeyError · 403 WriteAuthorizationError · 409 ImmutabilityError ·
    422 VotingWindowError · 400 ValueError

Backend semantics (``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER``):

* ``memory`` / ``database`` — the store verifies each write's signature (request
  sig for admin/gateway and the coordinator's result write; content sig +
  ``ecrecover`` for keyper writes) and writes. Every route is a usable write path.
* ``blockchain`` — the service is the **public read surface** on chain, wrapping a
  read-only :class:`~shutter_governance_protocol.adapters.chain.client.BlockchainDataLayer` (no write account).
  Keyper writes are relayed by the **coordinator** (whose ``COORDINATOR_SIGNING_KEY``
  account sends the ``...Signed`` meta-tx and pays gas; the contract ``ecrecover``s the
  keyper), and admin/gateway submit their own txs directly (``msg.sender`` authz). So
  on-chain identity is never impersonated here.
"""

from __future__ import annotations

import json

from flask import Blueprint, Flask, Response, jsonify, request

from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    FinalizedKey,
    ImmutabilityError,
    QuorumConflictError,
    VotingWindowError,
    WriteAuthorizationError,
)


def _finalized_key_json(fk: FinalizedKey | None):
    if fk is None:
        return None
    return {
        "pkElection": codecs.enc_bytes(fk.pk_election),
        "committeePKs": [codecs.enc_bytes(p) for p in fk.committee_pks],
    }


# Where `api` mounts the port read surface. Shared so the mount point and the clients
# that target it (keypers) cannot drift apart.
PORT_READ_PREFIX = "/port"

# Hard cap on rows per ballot page. Without it one request streams an entire election
# — and this surface is public, since `api` mounts it. Consumers that need
# the whole list page through it via `services.common.reads.read_all_ballots`, which
# verifies it got a complete, contiguous 0..total-1 read rather than a short one.
MAX_BALLOT_PAGE = 1000

# A page also stops once its JSON passes this size (it always holds at least one row).
# The row cap alone allowed 1,000 ballots of any size: ~157 MB at three candidates and
# budget 100, ~1.3 GB at the form's 2,500-branch limit. Built in memory, held twice on
# the DB stack (the API's /port proxies this service) and slower than the 10 s client
# timeout, such a page stalled the tally. Readers page on the rows actually returned.
MAX_BALLOT_PAGE_BYTES = 8 * 1024 * 1024
# Rows read from the store per step while filling a page, so a large-ballot page never
# loads more than this many ballots past the byte budget.
_BALLOT_READ_BATCH = 100

# Largest request body any shutter_governance_protocol Flask app will buffer. `get_json(force=True)` would
# otherwise read an arbitrarily large payload into memory before any validation — and the
# ballot POST is public and unauthenticated.
#
# Sized against the biggest *ballot* the config bounds permit: MAX_PROOF_BRANCHES (2500)
# x 256 bytes x 2 (hex) ~= 1.25 MiB, so 2 MiB leaves headroom. This is an inbound-body
# limit only — read responses are bounded separately by MAX_BALLOT_PAGE(_BYTES).
MAX_CONTENT_LENGTH = 2 * 1024 * 1024


def _register_error_handlers(bp: Blueprint) -> None:
    """Map port exceptions onto the typed statuses ``HttpDataLayerClient`` expects.

    Registered on the blueprint rather than the app so the port surface keeps its own
    error contract when it is mounted inside a host app (``api``) that maps the same
    exceptions differently for browsers.
    """

    @bp.errorhandler(KeyError)
    def _not_found(e):
        return jsonify(error="KeyError", message=str(e)), 404

    @bp.errorhandler(WriteAuthorizationError)
    def _forbidden(e):
        return jsonify(error="WriteAuthorizationError", message=str(e)), 403

    @bp.errorhandler(ImmutabilityError)
    def _conflict(e):
        return jsonify(error="ImmutabilityError", message=str(e)), 409

    @bp.errorhandler(VotingWindowError)
    def _wrong_window(e):
        return jsonify(error="VotingWindowError", message=str(e)), 422

    @bp.errorhandler(QuorumConflictError)
    def _quorum_conflict(e):
        # 409, not 500: the store is healthy and the request well-formed — the *election*
        # is in an irreconcilable state (two artifacts both reached quorum).
        return jsonify(error="QuorumConflictError", message=str(e)), 409

    @bp.errorhandler(ValueError)
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400


def _eid() -> bytes:
    return bytes.fromhex(request.view_args["eid"])


def _register_error_handlers_on_app(app: Flask) -> None:
    """Same port error contract as the blueprint, for this app's write routes."""
    app.register_error_handler(KeyError, lambda e: (jsonify(error="KeyError", message=str(e)), 404))
    app.register_error_handler(
        WriteAuthorizationError, lambda e: (jsonify(error="WriteAuthorizationError", message=str(e)), 403)
    )
    app.register_error_handler(
        ImmutabilityError, lambda e: (jsonify(error="ImmutabilityError", message=str(e)), 409)
    )
    app.register_error_handler(
        VotingWindowError, lambda e: (jsonify(error="VotingWindowError", message=str(e)), 422)
    )
    app.register_error_handler(ValueError, lambda e: (jsonify(error="ValueError", message=str(e)), 400))


def port_read_blueprint(dl: ElectionDataLayer, *, name: str = "port_read",
                        url_prefix: str | None = None) -> Blueprint:
    """The **read-only** half of the port over HTTP.

    Split out so a public-facing service can host the port's read surface without also
    hosting its writes. The ``api`` service mounts this under ``/port`` so remote keyper
    operators — which read the data layer but write through the coordinator relay — can
    point ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL`` at the public API instead of requiring the data-layer
    service itself to be reachable.

    Unlike ``api``'s browser routes this is byte-faithful to the port: bare-hex election
    ids (no decimalization), envelope JSON verbatim, and storage metadata on ballots.

    Ballot pages are capped at ``MAX_BALLOT_PAGE`` rows and ``MAX_BALLOT_PAGE_BYTES`` of
    JSON — this surface is public, so an uncapped page would let one request stream an
    entire election. A page may therefore hold fewer rows than asked for. A
    consumer needing the whole list pages through it with
    ``services.common.reads.read_all_ballots``, which verifies it recovered a complete
    contiguous read: a *silently* short list would make each keyper aggregate a different
    subset, so the t+1 byte-identical quorum would never form.
    """
    bp = Blueprint(name, __name__, url_prefix=url_prefix)
    _register_error_handlers(bp)

    @bp.get("/elections/<eid>")
    def get_election(eid):
        rec = dl.get_election(_eid())
        return jsonify(
            config=codecs.enc_config(rec.config),
            cancelled=rec.cancelled,
            tallyStalled=rec.tally_stalled,
            finalizedKey=_finalized_key_json(rec.finalized_key),
        )

    @bp.get("/elections")
    def list_elections():
        admin_key = request.args.get("adminKey")
        filt = ElectionFilter(admin_key=codecs.dec_bytes(admin_key, name="adminKey")) if admin_key else None
        return jsonify(electionIds=[codecs.enc_bytes(e) for e in dl.list_elections(filt)])

    @bp.get("/elections/<eid>/dkg")
    def get_dkg(eid):
        return jsonify(submissions=[codecs.enc_dkg_result(s) for s in dl.get_dkg_submissions(_eid())])

    @bp.get("/elections/<eid>/dkg/finalized")
    def get_finalized(eid):
        return jsonify(finalizedKey=_finalized_key_json(dl.get_finalized_key(_eid())))

    @bp.get("/elections/<eid>/ballots")
    def list_ballots(eid):
        eid_b = _eid()
        start = int(request.args.get("start", 0))
        count = min(int(request.args.get("count", 0)), MAX_BALLOT_PAGE)
        # Storage metadata rides alongside the envelope, never inside it: the ballot
        # JSON is the voter-signed artifact and the conformance-vector surface.
        # A record that could not be decoded is served as ``"ballot": null`` plus its
        # reason, keeping its sequence number, so every reader excludes it the same way.
        # Each row is encoded once, here, so the page can stop at the byte budget.
        parts: list[str] = []
        size, at = 0, start
        while len(parts) < count and (not parts or size < MAX_BALLOT_PAGE_BYTES):
            want = min(_BALLOT_READ_BATCH, count - len(parts))
            batch = dl.list_ballots(eid_b, at, want)
            for sb in batch:
                row = {
                    "ballot": None if sb.envelope is None else codecs.enc_ballot(sb.envelope),
                    "sequenceNumber": sb.sequence_number,
                    "submittedAt": sb.submitted_at,
                }
                if sb.envelope is None:
                    row["malformed"] = sb.malformed_reason
                parts.append(json.dumps(row, separators=(",", ":")))
                size += len(parts[-1])
                if size >= MAX_BALLOT_PAGE_BYTES:
                    break
            if len(batch) < want:
                break  # end of the list
            at += len(batch)
        return Response('{"ballots":[' + ",".join(parts) + "]}", mimetype="application/json")

    @bp.get("/elections/<eid>/ballots/count")
    def count_ballots(eid):
        return jsonify(count=dl.count_ballots(_eid()))

    @bp.get("/elections/<eid>/aggregate")
    def get_aggregate(eid):
        agg = dl.get_aggregate(_eid())
        return jsonify(aggregate=codecs.enc_aggregate(agg) if agg else None)

    @bp.get("/elections/<eid>/shares")
    def list_shares(eid):
        return jsonify(shares=[codecs.enc_decryption_share(s) for s in dl.list_decryption_shares(_eid())])

    @bp.get("/elections/<eid>/result")
    def get_result(eid):
        res = dl.get_result(_eid())
        return jsonify(result=codecs.enc_result(res) if res else None)

    @bp.get("/capability")
    def capability():
        return jsonify(verifiabilityTier=dl.verifiability_tier())

    return bp


def build_app(dl: ElectionDataLayer) -> Flask:
    """Build the Flask app mapping the port onto HTTP routes over any adapter."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.register_blueprint(port_read_blueprint(dl))

    _register_error_handlers_on_app(app)

    # -- election lifecycle ------------------------------------------------- #

    @app.post("/elections")
    def register():
        body = request.get_json(force=True)
        config = codecs.dec_config(body["config"])
        sig = codecs.dec_bytes(body["adminSig"], name="adminSig")
        eid = dl.register_election(config, sig)
        return jsonify(electionId=codecs.enc_bytes(eid)), 200

    @app.post("/elections/<eid>/cancel")
    def cancel(eid):
        body = request.get_json(force=True)
        dl.cancel_election(_eid(), codecs.dec_bytes(body["adminSig"], name="adminSig"))
        return "", 204

    # -- DKG ---------------------------------------------------------------- #

    @app.post("/elections/<eid>/dkg")
    def submit_dkg(eid):
        body = request.get_json(force=True)
        dl.submit_dkg_result(
            _eid(),
            codecs.dec_bytes(body["pkElection"], name="pkElection"),
            [codecs.dec_bytes(p, name="committeePKs[]") for p in body["committeePKs"]],
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    # -- ballots ------------------------------------------------------------ #

    @app.post("/elections/<eid>/ballots")
    def submit_ballot(eid):
        body = request.get_json(force=True)
        gateway_sig = codecs.dec_bytes(body["gatewaySig"], name="gatewaySig") if body.get("gatewaySig") else b""
        seq = dl.submit_ballot(_eid(), codecs.dec_ballot(body["ballot"]), gateway_sig)
        return jsonify(sequenceNumber=seq), 200

    # -- tally artifacts ---------------------------------------------------- #

    @app.post("/elections/<eid>/aggregate")
    def submit_aggregate(eid):
        body = request.get_json(force=True)
        dl.submit_aggregate(
            _eid(), codecs.dec_aggregate(body["aggregate"]),
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.post("/elections/<eid>/shares")
    def submit_share(eid):
        body = request.get_json(force=True)
        dl.submit_decryption_share(
            _eid(), codecs.dec_decryption_share(body["share"]),
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.post("/elections/<eid>/result")
    def publish_result(eid):
        body = request.get_json(force=True)
        dl.publish_result(
            _eid(), codecs.dec_result(body["result"]),
            codecs.dec_bytes(body["resultPublisherSig"], name="resultPublisherSig"),
        )
        return "", 204

    @app.post("/elections/<eid>/tally-stalled")
    def set_tally_stalled(eid):
        body = request.get_json(force=True)
        dl.set_tally_stalled(
            _eid(), bool(body["stalled"]),
            codecs.dec_bytes(body["resultPublisherSig"], name="resultPublisherSig"),
            int(body["issuedAt"]),
        )
        return "", 204

    return app


def _build_backend(clock):
    """Construct the backend adapter selected by ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` (default database)."""
    import os

    backend = os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER", "database").strip().lower()

    if backend in ("memory", "in-memory", "inmemory"):
        from shutter_governance_protocol.adapters.memory import InMemoryDataLayer

        return InMemoryDataLayer(clock=clock)

    if backend in ("database", "db", "postgres", "postgresql"):
        from shutter_governance_protocol.adapters.db import DEFAULT_DSN
        from shutter_governance_protocol.adapters.db.store import PostgresStore

        store = PostgresStore(os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_DSN", DEFAULT_DSN), clock=clock)
        store.init_schema()
        return store

    if backend in ("blockchain", "chain", "eth"):
        from web3 import Web3

        from shutter_governance_protocol.adapters.chain.client import BlockchainDataLayer

        rpc = os.environ["SHUTTER_GOVERNANCE_PROTOCOL_CHAIN_RPC"]
        registry = os.environ["SHUTTER_GOVERNANCE_PROTOCOL_REGISTRY_ADDRESS"]
        # The data-layer service is the READ-ONLY public read surface on chain (no
        # write account): admin/gateway submit their own txs, and keyper writes are
        # relayed by the coordinator.
        w3 = Web3(Web3.HTTPProvider(rpc))
        return BlockchainDataLayer(w3, registry, account=None)

    raise SystemExit(f"unknown SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER={backend!r} (want memory|database|blockchain)")


def main() -> None:
    """Run the uniform data-layer microservice for the ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` backend.

    Env: ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` (memory|database|blockchain); ``DATA_LAYER_HOST`` /
    ``DATA_LAYER_PORT``. Backend-specific: ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_DSN`` (database);
    ``SHUTTER_GOVERNANCE_PROTOCOL_CHAIN_RPC`` / ``SHUTTER_GOVERNANCE_PROTOCOL_REGISTRY_ADDRESS`` (blockchain, read-only).
    Uses wall-clock (NTP-disciplined in deployment) as the adapter's authoritative
    time for immutability + voting-window enforcement.
    """
    import logging
    import os
    import time

    logging.basicConfig(level=logging.INFO)
    backend = os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER", "database").strip().lower()
    port = int(os.environ.get("DATA_LAYER_PORT", "8000"))
    logging.getLogger("shutter_governance_protocol.data_layer").info("op=start service=data-layer backend=%s port=%d", backend, port)
    dl = _build_backend(lambda: int(time.time()))
    app = build_app(dl)
    app.run(host=os.environ.get("DATA_LAYER_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
