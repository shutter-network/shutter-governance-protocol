"""DKG coordinator daemon.

A standing watcher that drives the keyper ceremony for ``Registered`` elections
lacking a finalized key, sequencing ``round1 → distribute_commitments →
distribute_shares → round2 → submit_dkg_result``. It holds no secrets; its
compromise affects liveness only.

Retry/backoff to a hard lead-time deadline: attempts are bounded and must complete before
``voting_start`` minus a margin. Sleeping is injected (``sleep``) so tests drive
the schedule deterministically; wall-clock is read via ``clock``.
"""

from __future__ import annotations

import logging
import secrets
import time

import requests

from shutter_governance_protocol.crypto.dkg import derive_joint_mpk
from shutter_governance_protocol.crypto.points import g2_to_compressed
from shutter_governance_protocol.ports.data_layer import ElectionDataLayer
from shutter_governance_protocol.services.keyper import keyper_bootstrap as boot
from shutter_governance_protocol.services.keyper import KeyperService

# Shared with AutoDKG (same logger name), so the ceremony/trigger driver and the
# lifecycle watcher interleave under one "shutter_governance_protocol.coordinator" stream — the operator sees
# per-phase progress and *which* keyper/phase failed, not just a terminal error.
_LOG = logging.getLogger("shutter_governance_protocol.coordinator")


class DKGError(RuntimeError):
    pass


# How many times the coordinator will drive accuse → reveal → re-verify before giving up
# and publishing with whoever is able. Bounded because a malicious accuser can keep
# returning verified:false even after receiving a share that provably verifies, and an
# unbounded loop would hand it the very DoS this repair path exists to remove.
_MAX_REPAIR_ROUNDS = 2


class DKGComplaint(DKGError):
    """Complaints survived the repair attempts *and* cost the quorum.

    Raised only when the key did **not** finalize — i.e. fewer keypers ended up able to
    publish than the threshold requires. A complaint on its own is no longer terminal:
    the coordinator asks the accused dealer to re-deal, re-runs round 2 for the accuser,
    and then publishes with whoever holds a verified share, so a single member returning
    ``verified:false`` excludes only itself. Carries the signed accusations."""

    def __init__(self, message: str, accusations: list[dict]):
        super().__init__(message)
        self.accusations = accusations


class DKGEquivocation(DKGComplaint):
    """Dealers signed different commitment vectors for different keypers, and excluding
    them would leave fewer dealers than the threshold. (A smaller number is excluded and
    the ceremony continues.) Carries the signed vectors as ``evidence``."""

    def __init__(self, message: str, evidence: list[dict]):
        super().__init__(message, [])
        self.evidence = evidence


def keyper_urls_from(config, overrides: dict[str, str] | None = None) -> dict[int, str]:
    """Map keyper index (1-based) → HTTP URL for the ceremony/trigger.

    URLs come from the election config on every backend — including blockchain,
    where the KeyperSet contract stores per-member URLs (read back via the port).
    ``overrides`` (address-keyed, lowercase hex) is a vestigial escape hatch and is
    normally empty.
    """
    overrides = overrides or {}
    return {
        i: (k.url or overrides.get(bytes(k.signing_key).hex().lower(), ""))
        for i, k in enumerate(config.keypers, start=1)
    }


def run_dkg_once(election_id: bytes, keypers: list[KeyperService], n: int, t: int) -> bool:
    """One full ceremony attempt over the given keypers, **in-process (single-process
    test/simulation transport only)**.

    This is the DKG twin of ``tally_aggregator.run_tally``: it drives live
    ``KeyperService`` objects in the same process (rounds + submit) instead of the
    deployed HTTP path (:func:`run_dkg_http`, keyper ``/dkg/*`` endpoints, confidential
    keyper→keyper share exchange). Used only by the protocol-level e2e tests via
    :func:`ensure_dkg`; no production caller. The multi-operator deployment always uses
    :func:`run_dkg_http`.

    Returns whether the data layer's quorum rule now reports a finalized key.
    """
    if len(keypers) != n:
        raise DKGError(f"expected {n} keypers, got {len(keypers)}")

    # Round 1: each keyper produces commitments + shares for every recipient.
    all_commitments: dict[int, list] = {}
    all_shares: dict[int, dict[int, int]] = {}
    for k in keypers:
        comms, shares = k.dkg_round1(n, t)
        all_commitments[k.index] = comms
        all_shares[k.index] = shares

    # Distribute + Round 2: each keyper verifies the shares addressed to it.
    for k in keypers:
        received = {dealer: all_shares[dealer][k.index] for dealer in all_commitments}
        k.dkg_round2(all_commitments, received)

    # Submit: each keyper derives and submits the (byte-identical) joint result.
    for k in keypers:
        k.submit_dkg_result(election_id, all_commitments)

    return keypers[0].dl.get_finalized_key(election_id) is not None


def ensure_dkg(
    election_id: bytes,
    keypers: list[KeyperService],
    data_layer: ElectionDataLayer,
    *,
    n: int,
    t: int,
    clock,
    deadline: int,
    max_attempts: int = 5,
    sleep=lambda _s: None,
    backoff_base: float = 10.0,
) -> bool:
    """Drive the ceremony with retry/backoff until finalized or the deadline.

    **In-process test/simulation harness only** (wraps :func:`run_dkg_once`); the
    deployed coordinator uses the HTTP watcher (:class:`AutoDKG` → :func:`run_dkg_http`).

    ``deadline`` is the hard cutoff (e.g. ``voting_start - margin``). Returns
    ``True`` if the key finalized in time; ``False`` if attempts/ deadline were
    exhausted (the election then derives to ``DKGFailed`` at ``voting_start``).
    """
    if data_layer.get_finalized_key(election_id) is not None:
        return True
    for attempt in range(max_attempts):
        if clock() >= deadline:
            return False
        try:
            if run_dkg_once(election_id, keypers, n, t):
                return True
        except Exception:  # noqa: BLE001 — a failed attempt is retried, not fatal
            pass
        if attempt < max_attempts - 1:
            sleep(backoff_base * (2 ** attempt))
    return data_layer.get_finalized_key(election_id) is not None


# --------------------------------------------------------------------------- #
#  HTTP driver — drive a multi-operator keyper deployment over the wire
# --------------------------------------------------------------------------- #

def bootstrap_keypers(coordinator, keyper_urls: dict[int, str], *, member_addrs: dict[int, bytes],
                      relay_token: str | None = None, token_store=None, install: set[int] | None = None,
                      require: set[int] | None = None, timeout: float = 10.0):
    """Install per-keyper channel credentials via each keyper's /auth/bootstrap.

    Each keyper's ``{api_token, peer_token}`` is a **stable per-(coordinator, keyper)
    credential**: reused from ``token_store`` if present, else freshly minted and
    persisted. Only the per-committee peer *map* differs between bootstraps — so a
    keyper that sits in two overlapping committees keeps the same token slot and never
    gets churned (the concurrent-election bug). Tokens for *every* member are computed
    (the peer map needs them), but /auth/bootstrap is POSTed only to the members in
    ``install`` (default: all) — pass a subset to re-install a single keyper on a 401.

    Fetches each keyper's X25519 encryption pubkey (/status) and VERIFIES it against
    that keyper's ``member_addrs`` entry (its config signing address) before use, then
    seals a per-keyper token bundle to the verified key, signs it with the coordinator
    identity, and posts it. Every *other* keyper's verified ``{enc_pubkey,
    enc_pubkey_sig}`` is embedded in the peer map so dealers can seal shares to it.
    ``relay_token`` (the coordinator's write-relay bearer) rides inside the same
    sealed+signed payload so keypers need not pre-share it. Returns
    ``(api_tokens, peer_tokens)`` keyed by keyper index (all members).

    ``require`` (default: every member) names the keypers that must answer. Any other
    keyper that does not is logged and left out: of the peer map, and of the install.
    The DKG keeps the default, because dealers seal a share to every member. The tally
    needs only the api tokens, so one keyper being down must not stop the others.
    """
    api_tokens: dict[int, str] = {}
    peer_tokens: dict[int, str] = {}
    reused: dict[int, bool] = {}
    for i, url in keyper_urls.items():
        cred = token_store.get(url) if token_store is not None else None
        reused[i] = cred is not None
        if cred is None:  # first time this keyper is seen by this coordinator → mint + persist
            cred = {"api_token": secrets.token_urlsafe(32), "peer_token": secrets.token_urlsafe(32)}
            if token_store is not None:
                token_store.put(url, cred["api_token"], cred["peer_token"])
        api_tokens[i] = cred["api_token"]
        peer_tokens[i] = cred["peer_token"]

    # Fetch every keyper's X25519 encryption pubkey (+ self-binding signature) and VERIFY
    # it against that keyper's config member address before use. The verified key object
    # seals the keyper's own bootstrap bundle (closing a blind-trust MITM on /status); the
    # raw {enc_pubkey, enc_pubkey_sig} rides in every *other* keyper's peer map so dealers
    # can seal shares to it (re-verifying against the peer's member address at send time).
    enc_raw: dict[int, dict[str, str]] = {}
    enc_pub: dict[int, object] = {}
    for i, url in keyper_urls.items():
        try:
            st = requests.get(url.rstrip("/") + "/status", timeout=timeout).json()
            enc_hex, enc_sig = st["encryptionPubkey"], st["encryptionPubkeySig"]
            enc_pub[i] = boot.verify_encryption_pubkey(member_addrs[i], enc_hex, enc_sig)
            enc_raw[i] = {"enc_pubkey": enc_hex, "enc_pubkey_sig": enc_sig}
        except Exception as err:  # noqa: BLE001 — re-raised; caller backs off and retries
            if require is not None and i not in require:
                _LOG.warning("op=bootstrap keyper=%d url=%s status=skipped err=%s", i, url, err)
                continue
            _LOG.error("op=bootstrap keyper=%d url=%s status=enc_pubkey_error err=%s", i, url, err)
            raise

    targets = keyper_urls if install is None else {i: keyper_urls[i] for i in install}
    for i, url in targets.items():
        if i not in enc_pub:  # unreachable and not required (skipped above)
            continue
        # Seal+sign this keyper's bundle and install it — attributing any failure to the
        # specific keyper so a stuck committee names the culprit, not a generic error.
        try:
            payload = {
                "api_token": api_tokens[i],
                "peer_token": peer_tokens[i],
                "relay_token": relay_token,
                # Each peer entry: where to reach it, what to authenticate with, and the
                # X25519 key to seal shares to (the dealer re-verifies it before sealing).
                "peers": {str(j): {"url": keyper_urls[j], "token": peer_tokens[j], **enc_raw[j]}
                          for j in keyper_urls if j != i and j in enc_raw},
                "nonce": secrets.token_hex(16),
                "timestamp": int(time.time()),
            }
            sig = boot.sign_payload(coordinator, payload)
            sealed = boot.x25519_seal(boot.canonical_payload_bytes(payload), enc_pub[i])
            requests.post(url.rstrip("/") + "/auth/bootstrap",
                          json={"sealed": sealed.hex(), "signature": sig.hex()}, timeout=timeout).raise_for_status()
        except Exception as err:  # noqa: BLE001 — re-raised; caller backs off and retries
            if require is not None and i not in require:
                _LOG.warning("op=bootstrap keyper=%d url=%s status=skipped err=%s", i, url, err)
                continue
            _LOG.error("op=bootstrap keyper=%d url=%s status=error err=%s", i, url, err)
            raise
        _LOG.debug("op=bootstrap keyper=%d url=%s status=installed token=%s",
                   i, url, "reused" if reused[i] else "minted")
    return api_tokens, peer_tokens


def _needs_token(r) -> bool:
    """The keyper does not hold our token: a ``401``, or the ``503`` a keyper answers when
    it has no token at all (restarted after losing its saved tokens). Both are fixed by
    re-installing the keyper's stable token."""
    return r.status_code == 401 or (r.status_code == 503 and "keyper not bootstrapped" in r.text)


def _post_keyper(url: str, path: str, election_id: bytes, api_tokens: dict[int, str], i: int,
                 *, rebootstrap=None, timeout: float, op: str | None = None, extra: dict | None = None):
    """POST a coordinator→keyper trigger, recovering from a stale-token 401.

    On ``401`` or "not bootstrapped" ``503`` (see ``_needs_token``) — the keyper doesn't
    hold the token we presented (state loss, or a credential the coordinator minted but
    never installed on this keyper) — call
    ``rebootstrap(i)`` to re-install this keyper's *stable* credential and retry once
    with the returned token. Because credentials are per-keyper (Option D), re-installing
    keyper ``i`` never disturbs any other keyper, so this can't ping-pong between
    concurrent elections. Returns the response, or ``None`` if the call errored out.

    A trigger is best-effort (the data-layer quorum is the real success gate and the
    next poll retries), but failures are **logged** — an unreachable keyper or a 5xx
    during tally would otherwise be invisible, leaving the operator staring at a stalled
    election with no clue which keyper is down.
    """
    op = op or path.lstrip("/")
    eid_hex = election_id.hex()
    body = {"electionId": eid_hex, **(extra or {})}
    try:
        r = requests.post(url.rstrip("/") + path, json=body,
                          headers={"Authorization": f"Bearer {api_tokens[i]}"}, timeout=timeout)
        if _needs_token(r) and rebootstrap is not None:
            _LOG.info("op=%s keyper=%d status=reauth election=%s (http=%d → re-bootstrap + retry)", op, i, eid_hex, r.status_code)
            token = rebootstrap(i)  # re-install stable token; returns it (unchanged) or None
            if token:
                api_tokens[i] = token
                r = requests.post(url.rstrip("/") + path, json=body,
                                  headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        if r.status_code >= 500:
            _LOG.warning("op=%s keyper=%d status=error http=%d election=%s", op, i, r.status_code, eid_hex)
        return r
    except Exception as err:  # noqa: BLE001 — best-effort; retried next poll
        _LOG.warning("op=%s keyper=%d status=unreachable election=%s err=%s", op, i, eid_hex, err)
        return None


def run_dkg_http(election_id: bytes, keyper_urls: dict[int, str], api_tokens: dict[int, str],
                 data_layer: ElectionDataLayer, *, rebootstrap=None, timeout: float = 30.0) -> bool:
    """Sequence the DKG ceremony over HTTP; return whether the key finalized.

    ``rebootstrap(i)`` (optional) re-installs keyper ``i``'s stable credential and
    returns its token; used to recover a phase call that needs a token (``_needs_token``)."""
    eid_hex = election_id.hex()

    def call(i: int, phase: str, extra: dict | None = None):
        path = "/dkg/" + phase
        body = {"electionId": eid_hex, **(extra or {})}
        try:
            r = requests.post(keyper_urls[i].rstrip("/") + path, json=body,
                              headers={"Authorization": f"Bearer {api_tokens[i]}"}, timeout=timeout)
            if _needs_token(r) and rebootstrap is not None:
                _LOG.info("op=dkg phase=%s keyper=%d status=reauth election=%s", phase, i, eid_hex)
                token = rebootstrap(i)
                if token:
                    api_tokens[i] = token
                    r = requests.post(keyper_urls[i].rstrip("/") + path, json=body,
                                      headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as err:  # noqa: BLE001 — re-raised; _drive_dkg backs off + retries
            _LOG.error("op=dkg phase=%s keyper=%d status=error election=%s err=%s", phase, i, eid_hex, err)
            raise

    idxs = sorted(keyper_urls)

    # Resume, never restart, once any keyper has voted. A new round 1 would give every
    # keyper a fresh polynomial and so a different key, but DKG votes are append-only per
    # keyper: those who already voted could never vote for the new key, and their secret
    # for the old one would be gone. Each keyper keeps the key it fixed at round 2, so
    # asking the rest to publish completes the original key. (A failure before anyone
    # published leaves no vote, and the full ceremony below is safe to rerun.)
    if data_layer.get_dkg_submissions(election_id):
        _LOG.info("op=dkg status=resuming election=%s reason=votes_already_published", eid_hex)
        for i in idxs:
            try:
                call(i, "publish")
            except Exception:  # noqa: BLE001 — logged by call(); retried on the next attempt
                pass
        finalized = data_layer.get_finalized_key(election_id) is not None
        _LOG.log(logging.INFO if finalized else logging.WARNING,
                 "op=dkg status=%s election=%s", "finalized" if finalized else "resume_incomplete", eid_hex)
        return finalized

    for phase in ("round1", "distribute_commitments"):
        for i in idxs:
            call(i, phase)
        _LOG.info("op=dkg phase=%s status=ok election=%s keypers=%d", phase, eid_hex, len(idxs))

    # Each keyper checks shares only against the commitments *it* received, so a dealer
    # that sends one set to some keypers and another set to the rest passes every check.
    # The key then finalizes from one set, and the keypers holding the other set can
    # never decrypt. Compare every keyper's copy before any share is sent; a dealer
    # caught signing two sets is left out of the key, with the proof attached so each
    # keyper can check it.
    config_cache: list = []

    def config():
        if not config_cache:
            config_cache.append(data_layer.get_election(election_id).config)
        return config_cache[0]

    exclusions, agreed = _equivocation_exclusions(election_id, idxs, call, data_layer)
    remaining = len(idxs) - len(exclusions)
    if exclusions and remaining < config().threshold.quorum:
        raise DKGEquivocation(
            f"DKG halted: dealer(s) {[x['dealer'] for x in exclusions]} signed different commitments, "
            f"and excluding them would leave fewer dealers than the threshold.",
            [rep for x in exclusions for rep in x["evidence"]])
    round2_body = {"excluded": exclusions} if exclusions else None

    for i in idxs:
        call(i, "distribute_shares")
    _LOG.info("op=dkg phase=distribute_shares status=ok election=%s keypers=%d", eid_hex, len(idxs))

    # round2 — collect complaints. A verified:false response carries recipient-signed
    # accusations (DKG-ACCUSE-v1).
    def round2_complaints(targets, body_for=lambda _i: round2_body):
        """Run round 2 on `targets`; return {accuser: [accusation, ...]} for the failures."""
        out = {}
        for i in targets:
            resp = call(i, "round2", body_for(i))
            if isinstance(resp, dict) and resp.get("verified") is False:
                out[i] = resp.get("accusations", [])
        return out

    complaints = round2_complaints(idxs)
    _LOG.info("op=dkg phase=round2 status=ok election=%s keypers=%d complaining=%d",
              eid_hex, len(idxs), len(complaints))

    attempts = 0
    while complaints and attempts < _MAX_REPAIR_ROUNDS:
        attempts += 1
        for accuser, accusations in sorted(complaints.items()):
            for acc in accusations:
                dealer = acc.get("accusedDealerIndex")
                _LOG.warning("op=dkg_complaint accuser_kid=%s accused_dealer=%s election=%s signature=%s",
                             acc.get("recipientIndex"), dealer, acc.get("electionId"), acc.get("signature"))
                if dealer not in keyper_urls:
                    continue
                # Best-effort by design: a dealer that refuses (or is unreachable) is exactly
                # the case the loop must survive, so a failure here is logged, not raised.
                resp = _post_keyper(keyper_urls[dealer], "/dkg/reveal_share", election_id, api_tokens,
                                    dealer, rebootstrap=rebootstrap, timeout=timeout, op="reveal_share",
                                    extra={"accusation": acc})
                ok = resp is not None and getattr(resp, "status_code", 0) == 200
                _LOG.log(
                    logging.INFO if ok else logging.ERROR,
                    "op=dkg phase=repair status=%s election=%s dealer=%s recipient=%s attempt=%d",
                    "redealt" if ok else "reveal_refused", eid_hex, dealer, accuser, attempts)
        # Only the accusers need re-running; everyone else already holds a valid share.
        complaints = round2_complaints(sorted(complaints))
        _LOG.info("op=dkg phase=repair status=rechecked election=%s attempt=%d still_complaining=%d",
                  eid_hex, attempts, len(complaints))

    if complaints:
        # Settle what the sealed re-send did not. The accused dealer must now hand the
        # disputed share, signed, to this coordinator, which checks it against the dealer's
        # agreed commitments. A valid share goes to the accuser; a dealer that cannot
        # produce one is excluded from the key. Without this, a dealer withholding one
        # recipient's share and refusing to repair kept a veto over decryption, and a
        # counter-accusation made the two sides indistinguishable.
        #
        # The coordinator learns that one share. Only the accuser was entitled to it: if
        # the accuser lied, it already held the share; if the dealer lied, its secret
        # does not matter. It discloses anything new only when both are honest and the
        # sealed re-send kept failing. Each reveal needs that share's own recipient's
        # signed accusation, so a coordinator cannot gather enough shares of one dealer's
        # polynomial without colluding with a quorum of keypers.
        revealed: dict[int, list[dict]] = {}
        newly_excluded: dict[int, dict] = {}
        already = {x["dealer"] for x in exclusions}
        for accuser, accusations in sorted(complaints.items()):
            for acc in accusations:
                dealer = acc.get("accusedDealerIndex")
                if dealer not in keyper_urls or dealer in already or dealer in newly_excluded \
                        or acc.get("recipientIndex") != accuser:
                    continue
                share = _public_reveal(election_id, keyper_urls[dealer], api_tokens, dealer, accuser, acc,
                                       agreed.get(dealer), config(), rebootstrap=rebootstrap, timeout=timeout)
                if share is not None:
                    revealed.setdefault(accuser, []).append(share)
                else:
                    newly_excluded[dealer] = {"dealer": dealer, "reason": "no_valid_reveal", "accusation": acc}
        if len(idxs) - len(exclusions) - len(newly_excluded) < config().threshold.quorum:
            _LOG.error("op=dkg phase=dispute status=cannot_exclude election=%s dealers=%s "
                       "reason=fewer_than_threshold_would_remain", eid_hex, sorted(newly_excluded))
            newly_excluded = {}
        if revealed or newly_excluded:
            exclusions = exclusions + list(newly_excluded.values())
            _LOG.warning("op=dkg phase=dispute status=settled election=%s revealed_for=%s excluded=%s",
                         eid_hex, sorted(revealed), sorted(newly_excluded))
            # Everyone re-runs round 2: an exclusion changes every keyper's share and key.
            complaints = round2_complaints(
                idxs, lambda i: {"excluded": exclusions, **({"revealed": revealed[i]} if i in revealed else {})})

    if complaints:
        # Every accusation was given its repair attempt and some keyper still cannot verify.
        # Publish anyway if a quorum can: a keyper that still refuses only excludes *itself*
        # from decryption, and the data layer finalizes on the t-quorum. Halting here is what
        # handed one member a veto.
        _LOG.error("op=dkg phase=repair status=unresolved election=%s keypers=%s "
                   "reason=still_complaining_after_%d_attempts", eid_hex, sorted(complaints), attempts)

    publishers = []
    for i in idxs:
        if i in complaints:
            _LOG.warning("op=dkg phase=publish status=skipped election=%s keyper=%d "
                         "reason=no_verified_share", eid_hex, i)
            continue
        try:
            call(i, "publish")
            publishers.append(i)
        except Exception as err:  # noqa: BLE001 — one keyper failing must not end the ceremony
            _LOG.error("op=dkg phase=publish status=error election=%s keyper=%d err=%s", eid_hex, i, err)
    _LOG.info("op=dkg phase=publish status=ok election=%s published=%d/%d",
              eid_hex, len(publishers), len(idxs))

    finalized = data_layer.get_finalized_key(election_id) is not None
    if finalized and len(publishers) < len(idxs):
        # Finalized, but with less decryption redundancy than the committee was sized for:
        # every publisher must now be reachable at tally. Operators should see this.
        _LOG.error("op=dkg status=finalized_degraded election=%s published=%s absent=%s "
                   "reason=no_spare_decryption_capacity",
                   eid_hex, publishers, sorted(set(idxs) - set(publishers)))
    if not finalized and complaints:
        accusations = [acc for accs in complaints.values() for acc in accs]
        accused = sorted({acc.get("accusedDealerIndex") for acc in accusations})
        raise DKGComplaint(
            f"DKG did not finalize: unrepaired complaint(s) against dealer(s) {accused} left "
            f"fewer than the quorum able to publish. Signed accusations logged above.",
            accusations)
    return finalized


def _equivocation_exclusions(election_id: bytes, idxs, call, data_layer: ElectionDataLayer):
    """Find dealers that signed two different commitment vectors.

    Returns ``(exclusions, agreed)``: the exclusions for the equivocating dealers, and,
    for every other dealer, the one commitment vector (hex) the keypers agree on, which
    a publicly revealed share is later checked against.

    Each exclusion is ``{"dealer", "reason": "equivocation", "evidence": [report, ...]}``,
    the form ``/dkg/round2`` verifies. Only dealer-signed vectors count, so a keyper
    cannot frame an honest dealer by reporting a vector the dealer never signed; such a
    report is logged and ignored. A keyper that holds no vector for some dealer is left
    to round 2, which complains about it.
    """
    from shutter_governance_protocol.core import write_auth

    eid_hex = election_id.hex()
    members: dict[int, bytes] | None = None  # committee addresses, read on first use
    seen: dict[int, dict[tuple[bytes, ...], dict]] = {}  # dealer -> {vector: first report}
    for i in idxs:
        held = call(i, "commitments").get("commitments", {})
        if held and members is None:
            members = {j: bytes(k.signing_key)
                       for j, k in enumerate(data_layer.get_election(election_id).config.keypers, start=1)}
        for dealer_s, row in held.items():
            dealer = int(dealer_s)
            try:
                vector = tuple(bytes.fromhex(h) for h in row["commitments"])
                sig = bytes.fromhex(str(row["signature"]).removeprefix("0x"))
                signed = write_auth.recover_digest(
                    write_auth.dkg_commitments_digest(election_id, dealer, list(vector)), sig) == members.get(dealer)
            except Exception:  # noqa: BLE001 — malformed report: treated as unsigned
                signed = False
            if not signed:
                _LOG.warning("op=dkg phase=check_commitments status=ignored election=%s reporter=%d dealer=%d "
                             "reason=not_signed_by_dealer", eid_hex, i, dealer)
                continue
            seen.setdefault(dealer, {}).setdefault(
                vector, {"reporter": i, "dealer": dealer, "commitments": row["commitments"],
                         "signature": row["signature"]})
    exclusions = []
    for dealer in sorted(d for d, vectors in seen.items() if len(vectors) > 1):
        evidence = list(seen[dealer].values())
        for rep in evidence:
            _LOG.error("op=dkg_equivocation election=%s dealer=%d reporter=%d signature=%s",
                       eid_hex, dealer, rep["reporter"], rep["signature"])
        exclusions.append({"dealer": dealer, "reason": "equivocation", "evidence": evidence})
    _LOG.log(logging.WARNING if exclusions else logging.INFO,
             "op=dkg phase=check_commitments status=%s election=%s dealers=%d excluded=%s",
             "excluding" if exclusions else "ok", eid_hex, len(seen), [x["dealer"] for x in exclusions])
    agreed = {d: next(iter(v.values()))["commitments"] for d, v in seen.items() if len(v) == 1}
    return exclusions, agreed


def _public_reveal(election_id: bytes, url: str, api_tokens, dealer: int, accuser: int, accusation: dict,
                   vector, config, *, rebootstrap, timeout: float) -> dict | None:
    """Ask ``dealer`` for the share it owes ``accuser``, signed; return it if it checks out.

    Returns ``{"dealer", "share", "signature"}`` for the accuser's round 2, or ``None``
    when the dealer refused, was unreachable, or produced a share that does not match its
    signature or its agreed commitments; the caller then excludes the dealer.
    """
    from shutter_governance_protocol.core import write_auth
    from shutter_governance_protocol.crypto.dkg import verify_share
    from shutter_governance_protocol.crypto.params import CURVE_ORDER
    from shutter_governance_protocol.crypto.points import g2_from_compressed

    eid_hex = election_id.hex()
    resp = _post_keyper(url, "/dkg/reveal_share", election_id, api_tokens, dealer, rebootstrap=rebootstrap,
                        timeout=timeout, op="reveal_public", extra={"accusation": accusation, "public": True})
    try:
        if resp is None or resp.status_code != 200 or vector is None:
            raise ValueError("no reveal" if vector is not None else "no agreed commitments")
        data = resp.json()
        share = int(str(data["share"]), 16)
        sig = bytes.fromhex(str(data["signature"]).removeprefix("0x"))
        dealer_addr = bytes(config.keypers[dealer - 1].signing_key)
        if not 0 <= share < CURVE_ORDER:
            raise ValueError("share out of range")
        if write_auth.recover_digest(write_auth.dkg_share_digest(election_id, dealer, accuser, share), sig) != dealer_addr:
            raise ValueError("not signed by the dealer")
        if not verify_share([g2_from_compressed(bytes.fromhex(h)) for h in vector], accuser, share):
            raise ValueError("does not match the dealer's commitments")
    except Exception as err:  # noqa: BLE001 — any failure means the dealer did not clear itself
        _LOG.error("op=dkg phase=dispute status=dealer_failed election=%s dealer=%d accuser=%d reason=%s",
                   eid_hex, dealer, accuser, err)
        return None
    _LOG.warning("op=dkg phase=dispute status=dealer_cleared election=%s dealer=%d accuser=%d",
                 eid_hex, dealer, accuser)
    return {"dealer": dealer, "share": hex(share), "signature": "0x" + sig.hex()}


def trigger_decrypt_http(election_id: bytes, keyper_urls: dict[int, str], api_tokens: dict[int, str],
                         *, rebootstrap=None, timeout: float = 30.0) -> None:
    """Trigger each keyper's /publish_decr_share (keypers self-guard on their preconditions). A ``401`` is
    recovered via ``rebootstrap`` (Option D safety net); other failures are best-effort
    (the share-count quorum is the real gate and the next poll retries)."""
    for i, url in keyper_urls.items():
        _post_keyper(url, "/publish_decr_share", election_id, api_tokens, i, rebootstrap=rebootstrap, timeout=timeout, op="decrypt")


def trigger_aggregate_http(election_id: bytes, keyper_urls: dict[int, str], api_tokens: dict[int, str],
                           *, rebootstrap=None, timeout: float = 10.0,
                           recompute: bool = False) -> dict[int, str]:
    """Trigger each keyper's /aggregate and report what each one said.

    Each keyper re-derives the same deterministic aggregate from the ordered ballots and
    submits it signed; the data layer makes it canonical at the t+1 quorum.

    ``/aggregate`` is **asynchronous** — it accepts and computes on a worker thread — so
    this returns near-instantly and the per-keyper status is what tells the caller whether
    to keep waiting. Returns ``{keyper_index: status}`` where status is one of:

    * ``"submitted"``   — that keyper has already contributed
    * ``"started"`` / ``"in_progress"`` — accepted, still computing
    * ``"refused"``     — a precondition failed (409); the keyper self-guarded
    * ``"failed"``      — unreachable or 5xx

    ``recompute=True`` asks keypers to discard a previous submission and re-derive — the
    coordinator sends it when every keyper reports ``submitted`` yet no quorum formed, since
    a keyper's aggregate stays overridable until the quorum freezes precisely so honest
    keypers can re-converge.

    The distinction matters: treating "still computing" as a failed attempt is what used
    to stall healthy elections (a large aggregate takes minutes). The 10 s timeout is
    ample now that the call only *accepts* work — and keeps a hanging keyper from holding
    up the coordinator's other elections, which it scans sequentially.
    """
    out: dict[int, str] = {}
    for i, url in keyper_urls.items():
        r = _post_keyper(url, "/aggregate", election_id, api_tokens, i,
                         rebootstrap=rebootstrap, timeout=timeout, op="aggregate",
                         extra={"recompute": True} if recompute else None)
        if r is None or r.status_code >= 500:
            out[i] = "failed"
        elif r.status_code == 409:
            out[i] = "refused"
        else:
            try:
                out[i] = str(r.json().get("status", "started"))
            except Exception:  # noqa: BLE001 — a 2xx without the field: treat as accepted
                out[i] = "started"
    return out
