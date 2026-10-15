"""Wallet-authenticated eligibility-attestation HTTP service.

Exposes the issuing side over HTTP so a browser voter client can obtain an
``ATTESTATION_V1`` credential for its ballot:

    ``POST /attest``  {electionId, vk, signature}  ->  {attestation, pseudonym}

The identity gate — *one wallet, one vote* — lives here, not in the ballot/gateway/tally,
and needs **no chain**: proving control of an address is just a signature.

  1. The voter **personal-signs** (EIP-191) a human-readable challenge binding
     ``(electionId, vk)``. We ``ecrecover`` the address (a bad/missing signature is a 401).
     This is chain-agnostic — no EIP-712 domain, no chainId, no network to configure or
     switch. Binding ``vk`` makes the signature non-transferable to another ballot key.
  2. The pseudonym is derived from the address:
     ``pseudonym = HMAC-SHA256(secret, electionId ‖ address)[:32]`` — **stable** per
     (wallet, election) so two ballots from one wallet share a pseudonym and the tally's
     ``last-wins`` dedup keeps the latest (a voter can change their vote until close), and
     **private** (only this service, holding ``secret``, can link pseudonym ↔ wallet).

This is a **dummy** issuer: it grants a fixed weight (``ELIGIBILITY_DUMMY_WEIGHT``) to any
recovered address; a real deployment authenticates differently and reads voting power from
a registry. To exercise the **deny path**, an optional ``ELIGIBILITY_ALLOWLIST`` JSON file
(address → weight, re-read per request so edits are live) gates issuance: a listed wallet
gets its weight, an unlisted one is refused with a 403. Unset → allow all (the default, and
what a bare dev run does). The returned ``attestation`` is the exact
:func:`shutter_governance_protocol.envelopes.codecs.enc_attestation` envelope the gateway / tally verify against
``config.eligibility_key`` — swapping issuers needs no client change. CORS-enabled (the
browser calls it directly).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
from typing import Callable

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
from flask import Flask, jsonify, request

from shutter_governance_protocol.adapters.eligibility_stub import StubEligibilityService
from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.ports.eligibility import AttestationRequest
from shutter_governance_protocol.services.data_layer.data_layer import MAX_CONTENT_LENGTH

_LOG = logging.getLogger("shutter_governance_protocol.eligibility")

# A nonce allocator returns the next monotonic re-vote counter for an (election, pseudonym):
# 1 for a first vote, then 2, 3, … on each subsequent /attest for the same voter.
NonceAllocator = Callable[[bytes, bytes], int]
# Whether an election is weighted, read from its registered config. Per election: the same
# voter may hold weight 79 in a weighted election and must get 1 in an unweighted one.
WeightedLookup = Callable[[bytes], bool]


def challenge_message(election_id: bytes, vk: bytes) -> str:
    """The human-readable EIP-191 message the voter's wallet signs. Wallets show this text
    verbatim, and both the browser and this service reconstruct the identical UTF-8 bytes
    (ASCII: fixed labels + lowercase 0x-hex), so ``ecrecover`` matches."""
    return (
        "Shutter Governance Protocol eligibility attestation\n"
        f"electionId: {codecs.enc_bytes(election_id)}\n"
        f"vk: {codecs.enc_bytes(vk)}"
    )


def derive_pseudonym(secret: bytes, election_id: bytes, address: bytes) -> bytes:
    """Deterministic, private per-(wallet, election) pseudonym (see module docstring)."""
    return hmac.new(secret, bytes(election_id) + bytes(address), hashlib.sha256).digest()[:32]


def _norm_addr(a: str) -> str:
    """Normalize an address to lowercase, 0x-less, 40-hex (checksum-insensitive)."""
    h = a.strip().lower().removeprefix("0x")
    if len(h) != 40:
        raise ValueError(f"bad address in allowlist: {a!r} (want 20-byte hex)")
    bytes.fromhex(h)  # validate hex
    return h


def load_allowlist(path: str, default_weight: int) -> dict[str, int]:
    """Read the (dev) eligibility allowlist into ``{normalized_address: weight}``.

    Two shapes are accepted: a JSON **object** ``{address: weight}`` (per-wallet voting
    power) or a bare JSON **array** ``[address, ...]`` (each listed wallet gets
    ``default_weight``). Called once per ``/attest`` so the file is hot-editable — no
    restart needed to change who is eligible. Raises ``ValueError`` on a malformed file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return {_norm_addr(a): default_weight for a in data}
    if isinstance(data, dict):
        return {_norm_addr(a): int(w) for a, w in data.items()}
    raise ValueError("allowlist must be a JSON object {address: weight} or array [address]")


class SqliteNonceStore:
    """Durable monotonic re-vote counter, one sequence per (election, pseudonym).

    The nonce goes into the (eligibility-signed) attestation, and the tally keeps the
    highest-nonce ballot per pseudonym — so it MUST be strictly increasing across a voter's
    successive attestations and MUST survive restarts (a reset that regressed the nonce would
    make a genuine re-vote lose to an already-stored ballot). SQLite gives durability +
    atomic increment; a process-wide lock serializes concurrent /attest calls (the dev server
    may be threaded). ``next(...)`` returns 1 on the first call for a voter, then 2, 3, …
    """

    def __init__(self, path: str):
        self._lock = threading.Lock()
        # check_same_thread=False: the lock (not sqlite's thread affinity) serializes access.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS revote_nonce ("
            "election_id TEXT NOT NULL, pseudonym TEXT NOT NULL, last INTEGER NOT NULL, "
            "PRIMARY KEY (election_id, pseudonym))"
        )
        self._conn.commit()

    def next(self, election_id: bytes, pseudonym: bytes) -> int:
        eid, ps = election_id.hex(), pseudonym.hex()
        with self._lock, self._conn:  # `with conn` = one atomic transaction
            row = self._conn.execute(
                "SELECT last FROM revote_nonce WHERE election_id=? AND pseudonym=?", (eid, ps)
            ).fetchone()
            n = (row[0] if row else 0) + 1
            self._conn.execute(
                "INSERT INTO revote_nonce (election_id, pseudonym, last) VALUES (?,?,?) "
                "ON CONFLICT(election_id, pseudonym) DO UPDATE SET last=excluded.last",
                (eid, ps, n),
            )
            return n


def _in_memory_nonce_allocator() -> NonceAllocator:
    """A non-durable per-(election, pseudonym) counter for tests / non-persistent dev runs.
    Resets on restart — do NOT use where re-votes must survive a restart (main() uses the
    durable SQLite store instead)."""
    counts: dict[tuple[bytes, bytes], int] = {}
    lock = threading.Lock()

    def alloc(election_id: bytes, pseudonym: bytes) -> int:
        key = (bytes(election_id), bytes(pseudonym))
        with lock:
            counts[key] = counts.get(key, 0) + 1
            return counts[key]

    return alloc


def build_eligibility_app(service: StubEligibilityService, *, pseudonym_secret: bytes,
                          weight: int = 1, allowlist_path: str | None = None,
                          next_nonce: NonceAllocator | None = None,
                          weighted_for: WeightedLookup | None = None) -> Flask:
    """Build the wallet-authenticated eligibility HTTP app. ``pseudonym_secret`` keys the
    pseudonym; ``weight`` is the (dummy) default voting weight. If ``allowlist_path`` is
    given, that JSON file gates issuance (re-read per request): a listed wallet gets its
    weight, an unlisted wallet is denied (403). If ``None``, every wallet is granted
    ``weight`` — the original allow-all dummy behavior. ``next_nonce`` allocates the monotonic
    per-(election, pseudonym) re-vote counter bound into each attestation; it defaults to an
    in-memory counter (fine for tests; ``main()`` supplies a durable SQLite store).

    ``weighted_for(election_id) -> bool`` reads whether the target election is weighted.
    For an unweighted (one per voter) election every credential is issued at weight 1,
    because admission excludes any other weight there and the voter's ballot would be
    lost. A weighted election gets the weight as held. ``main()`` reads it from the
    registered config; when ``None`` the weight is issued as held (tests that need no
    election)."""
    app = Flask(__name__)
    # Bound the body every route buffers via get_json(force=True).
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    alloc_nonce = next_nonce if next_nonce is not None else _in_memory_nonce_allocator()

    @app.errorhandler(ValueError)
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400

    @app.after_request
    def _cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    @app.get("/health")
    def health():
        return jsonify(ok=True, eligibilityKey=codecs.enc_bytes(service.eligibility_key))

    @app.post("/attest")
    def attest():
        body = request.get_json(force=True)
        if not body.get("signature"):
            return jsonify(error="Unauthorized", message="Connect your wallet to vote."), 401
        election_id = codecs.dec_bytes(body["electionId"], name="electionId")
        vk = codecs.dec_bytes(body["vk"], name="vk")

        # Authenticate the wallet over the exact (electionId, vk) it is attesting.
        message = encode_defunct(text=challenge_message(election_id, vk))
        try:
            recovered = Account.recover_message(
                message, signature=codecs.dec_bytes(body["signature"], name="signature"))
        except Exception:
            return jsonify(error="Unauthorized",
                           message="Could not verify your wallet signature."), 401
        address = bytes.fromhex(recovered[2:])
        addr_hex = recovered[2:].lower()

        # Eligibility policy (dev stub). No allowlist → grant the default weight to any
        # authenticated wallet (allow-all). With one configured, the file is re-read here
        # (hot-editable): a listed wallet gets its weight, an unlisted one is denied. A real
        # issuer replaces this with its own registry / voting-power lookup.
        voter_weight = weight
        if allowlist_path is not None:
            try:
                allow = load_allowlist(allowlist_path, weight)
            except (OSError, ValueError) as exc:
                _LOG.error("op=attest status=error allowlist=%s err=%s", allowlist_path, exc)
                return jsonify(error="ServerError",
                               message="The eligibility allowlist is misconfigured — contact the operator."), 500
            if addr_hex not in allow:
                _LOG.info("op=attest status=denied election=%s addr=0x%s", election_id.hex(), addr_hex)
                return jsonify(error="Forbidden",
                               message="This wallet isn't eligible for this election."), 403
            voter_weight = allow[addr_hex]

        # One per voter: issue weight 1 for an unweighted election. Fails closed when the
        # election cannot be read, because a guessed weight could be one the tally rejects.
        if weighted_for is not None:
            try:
                weighted = bool(weighted_for(election_id))
            except KeyError:
                return jsonify(error="NotFound", message="Unknown election."), 404
            except Exception as exc:  # noqa: BLE001
                _LOG.error("op=attest status=error election=%s reason=config_unavailable err=%s",
                           election_id.hex(), exc)
                return jsonify(error="ServerError",
                               message="Could not read the election's settings — try again shortly."), 503
            if not weighted and voter_weight != 1:
                _LOG.info("op=attest status=clamped election=%s addr=0x%s weight=%d reason=unweighted",
                          election_id.hex(), addr_hex, voter_weight)
                voter_weight = 1

        pseudonym = derive_pseudonym(pseudonym_secret, election_id, address)
        # Monotonic re-vote nonce for THIS (election, pseudonym): a first vote gets 1, each
        # re-vote a higher value. Bound into the attestation so the tally keeps the latest
        # genuine ballot and a replayed old ballot (lower nonce) can never override it.
        nonce = alloc_nonce(election_id, pseudonym)
        att = service.issue_attestation(AttestationRequest(
            election_id=election_id, pseudonym=pseudonym, vk=vk, weight=voter_weight, nonce=nonce))
        _LOG.info("op=attest status=ok election=%s weight=%d nonce=%d", election_id.hex(), att.weight, att.nonce)
        return jsonify(attestation=codecs.enc_attestation(att),
                       pseudonym=codecs.enc_bytes(pseudonym))

    return app


def _pseudonym_secret(elig_sk_hex: str) -> bytes:
    """HMAC secret keying the private pseudonym: ``ELIGIBILITY_PSEUDONYM_SECRET`` if set,
    else a stable value derived from the issuing key (so dev needs no extra config)."""
    env = os.environ.get("ELIGIBILITY_PSEUDONYM_SECRET")
    if env:
        return bytes.fromhex(env.removeprefix("0x"))
    _LOG.warning("ELIGIBILITY_PSEUDONYM_SECRET unset — deriving from the issuing key (dev default)")
    return keccak(b"shutter-governance-protocol-pseudonym-v1" + int(elig_sk_hex, 16).to_bytes(32, "big"))


def config_weighted_lookup(api_url: str) -> WeightedLookup:
    """Resolve whether an election is weighted from its **registered config**, cached per id.

    Reads go through the API's port surface (the one keypers use); the data-layer service is
    internal-only. Caching is safe because the config is immutable once registered. An
    unknown election raises ``KeyError``; any other failure propagates, so the caller fails
    closed.
    """
    from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient
    from shutter_governance_protocol.services.data_layer.data_layer import PORT_READ_PREFIX

    dl = HttpDataLayerClient(api_url.rstrip("/") + PORT_READ_PREFIX)
    cache: dict[bytes, bool] = {}
    lock = threading.Lock()

    def lookup(election_id: bytes) -> bool:
        key = bytes(election_id)
        with lock:
            hit = cache.get(key)
        if hit is not None:
            return hit
        weighted = bool(dl.get_election(key).config.weighted)
        with lock:
            cache[key] = weighted
        return weighted

    return lookup


def main() -> None:
    """Run the wallet-authenticated (dummy) eligibility service.

    Env: ``ELIGIBILITY_PRIVATE_KEY`` (issuing key; its public key is ``eligibility_key``),
    ``ELIGIBILITY_PSEUDONYM_SECRET`` (hex; optional — derived from the issuing key if unset),
    ``ELIGIBILITY_DUMMY_WEIGHT`` (default weight granted to an eligible wallet; default 1),
    ``ELIGIBILITY_ALLOWLIST`` (optional path to a JSON allowlist gating issuance; unset →
    allow all), ``ELIGIBILITY_NONCE_DB`` (SQLite path for the durable per-(election,
    pseudonym) re-vote counter; default ``eligibility-nonces.db`` — mount it on a volume so
    re-votes survive restarts), ``ELIGIBILITY_HOST`` / ``ELIGIBILITY_PORT`` (default 8600),
    ``SHUTTER_GOVERNANCE_PROTOCOL_API_URL`` (required: the public API's base URL, read for
    each election's ``weighted`` setting).
    """
    logging.basicConfig(level=logging.INFO)
    elig_sk_hex = os.environ["ELIGIBILITY_PRIVATE_KEY"]
    service = StubEligibilityService(int(elig_sk_hex, 16))
    port = int(os.environ.get("ELIGIBILITY_PORT", "8600"))
    allowlist_path = os.environ.get("ELIGIBILITY_ALLOWLIST") or None
    nonce_db = os.environ.get("ELIGIBILITY_NONCE_DB", "eligibility-nonces.db")
    api_url = (os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_API_URL") or "").strip()
    if not api_url:
        raise SystemExit(
            "set SHUTTER_GOVERNANCE_PROTOCOL_API_URL to the public API's base URL (e.g. "
            "http://host.docker.internal:8500): the issuer reads each election's weighted setting")
    _LOG.info("op=start service=eligibility port=%d eligibility_key=%s auth=wallet-personal-sign policy=%s nonce_db=%s",
              port, codecs.enc_bytes(service.eligibility_key),
              f"allowlist:{allowlist_path}" if allowlist_path else "allow-all", nonce_db)
    app = build_eligibility_app(
        service,
        pseudonym_secret=_pseudonym_secret(elig_sk_hex),
        weight=int(os.environ.get("ELIGIBILITY_DUMMY_WEIGHT", "1")),
        allowlist_path=allowlist_path,
        next_nonce=SqliteNonceStore(nonce_db).next,
        weighted_for=config_weighted_lookup(api_url),
    )
    app.run(host=os.environ.get("ELIGIBILITY_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
