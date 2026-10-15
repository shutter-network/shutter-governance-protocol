"""Public election API (frontend / external integrators).

A CORS-enabled HTTP surface over the ``ElectionDataLayer``, deliberately separate
from the internal data-layer service. **Reads are backend-blind**: they go through
an ``ElectionDataLayer`` (in deployment, an
:class:`~shutter_governance_protocol.adapters.db.client.HttpDataLayerClient` pointing at the uniform
data-layer service), so identical JSON is served whether the backend is database
or blockchain — the frontend sees one contract either way.

This service also hosts the **ballot ingest** (``POST /elections/<eid>/ballots``,
formerly the standalone gateway): the voter's frontend-built envelope is filtered
(UX + spam; no bearing on tally correctness) and written via a separate ``write_dl``.
On the database backend that write is keyless (the data-layer service verifies the
relayed signature); on the blockchain backend it is a ``submitVote`` transaction
sent by this service's own funded key (``GATEWAY_SIGNING_KEY``, ``msg.sender`` authz).

Responses are the raw JSON envelopes today (the same shapes the data-layer
service returns); shaping/enrichment can be layered on later without changing the
transport.
"""

from __future__ import annotations

import time

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    FinalizedKey,
    QuorumConflictError,
    VotingWindowError,
)
from shutter_governance_protocol.services.data_layer.data_layer import MAX_CONTENT_LENGTH, PORT_READ_PREFIX, port_read_blueprint
from shutter_governance_protocol.services.gateway.gateway import GatewayRejection, submit_ballot

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200

# Human-readable text for a rejected ballot, keyed by the admission/gateway reason. The
# machine `reason` code stays on the response for programmatic clients; `message` is what
# a voter reads.
_REJECTION_HELP = {
    "voting is not open": "Voting is not open for this election right now.",
    "no finalized key": "The election key is not ready yet — the committee is still finalizing it.",
    "OUT_OF_WINDOW": "Voting is not open for this election right now.",
    "INVALID_PROOF": "The ballot's validity (range) proof did not check out.",
    "INVALID_SIGNATURE": "The ballot's voter signature did not verify.",
    "INVALID_ATTESTATION": "Your eligibility credential could not be verified for this election.",
    "DUPLICATE_PSEUDONYM": "A ballot from this voter has already been recorded.",
    "STALE_OR_REPLAYED": "This ballot is stale — a newer vote from you is already recorded. Re-vote to change it.",
    "MALFORMED": "The ballot was malformed.",
}


def _parse_eid(seg: str) -> bytes:
    """Parse an election id from a URL segment to its canonical 32-byte form.

    **Strict** — exactly the two forms the system emits, nothing else:

    * friendly **decimal** id — ``1``, ``42`` (no prefix, all digits); or
    * canonical **64-char hex** — ``0x0000…0001`` or bare ``0000…0001`` (32 bytes).

    Everything else (short/loose hex like ``0x1`` / ``0x10``, non-64 ``0x`` values)
    is rejected with a ``ValueError`` → HTTP 400, so ``0x`` is never silently read
    as decimal and there are no coincidental matches.
    """
    hex_part = seg[2:] if seg[:2].lower() == "0x" else seg
    if len(hex_part) == 64:
        return bytes.fromhex(hex_part)  # canonical 32-byte hex (0x optional)
    if seg[:2].lower() != "0x" and seg.isdigit():
        n = int(seg)  # friendly sequential id
        if n >> 256:
            raise ValueError(f"election id {seg} out of range (> 2^256)")
        return n.to_bytes(32, "big")
    raise ValueError(f"bad election id {seg!r}: use a decimal id (e.g. 1) or a 64-char hex value")


def _eid_num(election_id: bytes) -> int:
    """Render a 32-byte election id as its decimal (sequential) value."""
    return int.from_bytes(election_id, "big")


def _decimalize_election_ids(obj):
    """Recursively rewrite every ``electionId`` hex field to its decimal id.

    The public API speaks **decimal** election ids uniformly (top-level,
    lists, and inside every returned envelope); cryptographic byte-strings (keys,
    ciphertexts, proofs, signatures) stay ``0x``-hex. Lossless — a client rebuilds
    the canonical 32 bytes from the integer. (Envelopes returned here are therefore
    display-shaped, not byte-verbatim; the internal data-layer service serves the
    raw hex artifacts for verification.)
    """
    if isinstance(obj, dict):
        return {
            k: (int(v, 16) if k == "electionId" and isinstance(v, str)
                else _decimalize_election_ids(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_decimalize_election_ids(x) for x in obj]
    return obj


def _finalized_key_json(fk: FinalizedKey | None):
    if fk is None:
        return None
    return {
        "pkElection": codecs.enc_bytes(fk.pk_election),
        "committeePKs": [codecs.enc_bytes(p) for p in fk.committee_pks],
    }


def build_api_app(
    dl: ElectionDataLayer,
    *,
    write_dl: ElectionDataLayer | None = None,
    clock=None,
    filter_on: bool = True,
    data_store: str = "database",
    gateway_signer=None,
) -> Flask:
    """Build the public API app over any ``ElectionDataLayer``.

    ``dl`` serves every read route. ``write_dl`` (defaults to ``dl``) receives the
    ballot ingest write — in deployment it is the actor-bound data layer (keyless on
    db, the funded chain sender on blockchain), while ``dl`` stays the backend-blind
    read proxy. ``clock`` (defaults to wall time) and ``filter_on`` gate the ballot.
    ``data_store`` (``"database"`` | ``"blockchain"``) is reported on ``/capability`` as
    ``dataStore`` so the frontend can show/hide chain-only options (vote-proxy, self-submit
    fee). ``gateway_signer`` authorizes the ballot *write* when the election declares a
    closed writer set (``config.gateway_keys``)."""
    app = Flask(__name__)
    # Bound the body every route buffers via get_json(force=True).
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    write = write_dl if write_dl is not None else dl
    _clock = clock if clock is not None else (lambda: int(time.time()))

    # The port's read surface, mounted verbatim under /port (bare-hex ids, envelope
    # JSON, ballot storage metadata; ballot pages capped at MAX_BALLOT_PAGE — consumers
    # needing the whole list page via reads.read_all_ballots). This is what remote keyper
    # operators point SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL at: they read the data layer but write through
    # the coordinator relay, so exposing reads here keeps the data-layer service itself
    # off the public network. The browser routes below are a separate, friendlier shape;
    # the blueprint carries its own error handlers so the two contracts don't mix.
    app.register_blueprint(port_read_blueprint(dl, url_prefix=PORT_READ_PREFIX))

    @app.errorhandler(KeyError)
    def _not_found(e):
        return jsonify(error="KeyError", message=str(e)), 404

    @app.errorhandler(ValueError)
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400

    @app.errorhandler(QuorumConflictError)
    def _quorum_conflict(e):
        # See the data-layer service: a split committee is a 409, not a server fault.
        return jsonify(error="QuorumConflictError", message=str(e)), 409

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(e):
        return jsonify(error="PAYLOAD_TOO_LARGE",
                       message="That request body is too large."), 413

    @app.after_request
    def _cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    def _eid() -> bytes:
        return _parse_eid(request.view_args["eid"])

    def _reply(payload: dict):
        """Serialize a response, decimalizing every election id."""
        return jsonify(_decimalize_election_ids(payload))

    def _int_arg(name: str, default: int) -> int:
        raw = request.args.get(name)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            raise ValueError(f"query param {name!r} must be an integer")

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    # -- election lifecycle ------------------------------------------------- #

    @app.get("/elections")
    def list_elections():
        admin = request.args.get("admin")
        # Accept the admin address as plain or 0x-prefixed hex (public-API leniency,
        # matching how election ids are parsed in the path).
        filt = ElectionFilter(admin_key=bytes.fromhex(admin.removeprefix("0x"))) if admin else None
        ids = dl.list_elections(filt)
        offset = max(0, _int_arg("offset", 0))
        limit = min(_MAX_LIMIT, max(1, _int_arg("limit", _DEFAULT_LIMIT)))
        page = ids[offset:offset + limit]
        return jsonify(
            electionIds=[_eid_num(e) for e in page],  # friendly decimal (sequential) ids
            total=len(ids), limit=limit, offset=offset,
        )

    @app.get("/elections/<eid>")
    def get_election(eid):
        eid_b = _eid()
        rec = dl.get_election(eid_b)
        return _reply({
            "electionId": _eid_num(eid_b),
            "config": codecs.enc_config(rec.config),
            "cancelled": rec.cancelled,
            "tallyStalled": rec.tally_stalled,
            "finalizedKey": _finalized_key_json(rec.finalized_key),
        })

    # -- DKG ---------------------------------------------------------------- #

    @app.get("/elections/<eid>/dkg")
    def get_dkg(eid):
        return _reply({"submissions": [codecs.enc_dkg_result(s) for s in dl.get_dkg_submissions(_eid())]})

    @app.get("/elections/<eid>/dkg/finalized")
    def get_finalized(eid):
        return jsonify(finalizedKey=_finalized_key_json(dl.get_finalized_key(_eid())))

    # -- ballots ------------------------------------------------------------ #

    @app.get("/elections/<eid>/ballots")
    def list_ballots(eid):
        # Paginated like /elections (limit/offset). The port's list_ballots(start,
        # count) treats count as a hard cap, so a bare call must pass a real limit —
        # defaulting count to 0 would return nothing. Default to a page, expose total.
        eid_b = _eid()
        total = dl.count_ballots(eid_b)
        offset = max(0, _int_arg("offset", 0))
        limit = min(_MAX_LIMIT, max(1, _int_arg("limit", _DEFAULT_LIMIT)))
        ballots = dl.list_ballots(eid_b, offset, limit)
        # Public browser shape is the bare ballot envelope (unchanged): the storage
        # metadata the port now carries is for tally/audit, and auditors read it through
        # the data-layer port, not this presentation surface.
        return _reply({
            # A malformed record keeps its slot, because the dashboard addresses ballots
            # by position within the page.
            "ballots": [
                {"malformed": sb.malformed_reason} if sb.envelope is None
                else codecs.enc_ballot(sb.envelope)
                for sb in ballots
            ],
            "total": total, "limit": limit, "offset": offset,
        })

    @app.get("/elections/<eid>/ballots/count")
    def count_ballots(eid):
        return jsonify(count=dl.count_ballots(_eid()))

    # -- ballot ingest (formerly the gateway; filtered, non-authoritative) -- #

    @app.post("/elections/<eid>/ballots")
    def submit_ballot_route(eid):
        election_id = _eid()
        try:
            ballot = codecs.dec_ballot(request.get_json(force=True)["ballot"])
        except RequestEntityTooLarge:
            # Distinct from MALFORMED: the body exceeded MAX_CONTENT_LENGTH and was never
            # read, so calling it a bad ballot would send the voter looking in the wrong
            # place. Let the app's 413 handler answer.
            raise
        except Exception as exc:  # noqa: BLE001
            return jsonify(error="MALFORMED",
                           message="The ballot could not be read — it's malformed or missing fields.",
                           detail=str(exc)), 400
        try:
            seq = submit_ballot(write, election_id, ballot, clock=_clock, filter_on=filter_on,
                                gateway_signer=gateway_signer)
        except GatewayRejection as rej:
            reason = str(rej)
            return jsonify(error="REJECTED", reason=reason,
                           message=_REJECTION_HELP.get(reason, "This ballot was rejected.")), 400
        except VotingWindowError as e:
            # The chain rejected the ballot as outside the window (its clock vs
            # block.timestamp differ by a second at the boundary) — a client error.
            return jsonify(error="OUTSIDE_VOTING_WINDOW",
                           message="Voting is not open for this election right now.", detail=str(e)), 400
        except KeyError:
            return jsonify(error="UNKNOWN_ELECTION", message="No election found with that id."), 404
        return jsonify(sequenceNumber=seq), 200

    # -- tally artifacts ---------------------------------------------------- #

    @app.get("/elections/<eid>/aggregate")
    def get_aggregate(eid):
        agg = dl.get_aggregate(_eid())
        return _reply({"aggregate": codecs.enc_aggregate(agg) if agg else None})

    @app.get("/elections/<eid>/shares")
    def list_shares(eid):
        return _reply({"shares": [codecs.enc_decryption_share(s) for s in dl.list_decryption_shares(_eid())]})

    @app.get("/elections/<eid>/result")
    def get_result(eid):
        res = dl.get_result(_eid())
        return _reply({"result": codecs.enc_result(res) if res else None})

    # -- capability --------------------------------------------------------- #

    @app.get("/capability")
    def capability():
        # `dataStore` lets the frontend tailor the UI (e.g. hide the on-chain-only vote-proxy
        # and self-submit-fee fields on the database backend).
        return jsonify(verifiabilityTier=dl.verifiability_tier(), dataStore=data_store)

    return app


def main() -> None:
    """Run the public election API (reads + ballot ingest).

    **Reads** go through the uniform data-layer service (backend-blind), so the same
    process serves the database and blockchain backends unchanged. The **ballot write**
    uses the actor-bound data layer: keyless on db (the data-layer service verifies the
    relayed signature), or — on blockchain — this service's own funded key sends the
    ``submitVote`` tx (``GATEWAY_SIGNING_KEY``, ``msg.sender`` authz).

    Env: ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL`` (read proxy); ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` + backend vars
    (``SHUTTER_GOVERNANCE_PROTOCOL_CHAIN_RPC`` / ``SHUTTER_GOVERNANCE_PROTOCOL_REGISTRY_ADDRESS`` + ``GATEWAY_SIGNING_KEY`` on chain) for
    the write; ``GATEWAY_FILTER`` (default 1 = on); ``API_HOST`` / ``API_PORT`` (default 8500).
    """
    import logging
    import os

    from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient
    from shutter_governance_protocol.core.authz import Signer
    from shutter_governance_protocol.services.common.backend import _CHAIN_BACKENDS, data_layer_for_service

    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("API_PORT", "8500"))
    filter_on = os.environ.get("GATEWAY_FILTER", "1") != "0"
    # Normalize the data-store selector to the two values the frontend keys off of.
    data_store = "blockchain" if os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER", "database").lower() in _CHAIN_BACKENDS else "database"
    read_dl = HttpDataLayerClient(os.environ["SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL"])
    gateway_key = os.environ.get("GATEWAY_SIGNING_KEY")
    write_dl = data_layer_for_service(gateway_key)
    # On chain the key is the ballot tx sender; on memory/DB it signs the ballot write so
    # the data layer can honour config.gateway_keys. Same key, two roles.
    gateway_signer = Signer.from_sk(int(gateway_key, 16)) if gateway_key else None
    logging.getLogger("shutter_governance_protocol.api").info("op=start service=api port=%d data_layer=%s data_store=%s filter=%s",
                                      port, os.environ["SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL"], data_store, "on" if filter_on else "off")
    app = build_api_app(read_dl, write_dl=write_dl, clock=lambda: int(time.time()), filter_on=filter_on,
                        data_store=data_store, gateway_signer=gateway_signer)
    app.run(host=os.environ.get("API_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
