"""Ballot admission (gateway) — library.

The single-ballot admission filter used by the public API's ballot ingest
(``POST /elections/<eid>/ballots``). Runs the standard admission verification as a
**filter (on by default)** and writes accepted ballots to the data layer. The
filter is for UX (a voter learns immediately that a ballot is malformed) and
spam/storage protection; its accept/reject decision has **no bearing on tally
correctness** — verification is authoritative at tally time, and a compromised
ingress (or a direct-submission path) can inject unverified rows without affecting
the tally.

Duplicate handling is NOT done here (it is evaluated at tally time over the full
ordered list); this only checks single-ballot validity and the voting window.

This module has no HTTP surface of its own: the ingest endpoint lives on the
``api`` service (``shutter_governance_protocol.services.api``), which imports :func:`submit_ballot`.
"""

from __future__ import annotations

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.admission import StoredBallot, validate_ballot
from shutter_governance_protocol.crypto.points import g2_from_compressed
from shutter_governance_protocol.envelopes.types import AttestationScheme, BallotEnvelope
from shutter_governance_protocol.ports.data_layer import ElectionDataLayer
from shutter_governance_protocol.core.state import ElectionState, StateFacts, derive_state

# Page size for scanning stored ballots when computing a pseudonym's max nonce.
_NONCE_SCAN_PAGE = 200
# How far back that scan reaches. Bounds the per-submission cost to O(1) instead of O(n)
# at the price of making the filter best-effort — see _max_stored_nonce.
_NONCE_SCAN_LIMIT = 1000


class GatewayRejection(ValueError):
    """Raised when the (on-by-default) admission filter rejects a ballot."""


def _max_stored_nonce(dl: ElectionDataLayer, election_id: bytes, pseudonym: bytes) -> int:
    """Highest attestation nonce stored for ``pseudonym`` among the most recent ballots.

    Scans **backwards from the newest ballot**, at most ``_NONCE_SCAN_LIMIT`` rows.
    The old full scan was O(n) per accepted submission — O(n²) to fill an election,
    and on the HTTP backend that is ``n/page`` network round trips *per vote*, which is a
    self-inflicted amplifier on a public endpoint.

    Backwards is the right direction: the issuer allocates nonces monotonically and voters
    submit in order, so a pseudonym's highest nonce is overwhelmingly among its latest
    ballots. Bounding the walk makes this **best-effort**, which it already was — a
    determined replayer could bury the newest ballot under ``_NONCE_SCAN_LIMIT`` others and
    slip a stale one past *this filter*. That costs nothing in integrity: the tally ranks
    duplicates by ``(nonce, sequence_number)`` in ``admit`` regardless of what got stored,
    which is the authoritative ordering. This is a funds/DoS guard on the ingest path, not
    the integrity boundary."""
    total = dl.count_ballots(election_id)
    best = 0
    floor = max(0, total - _NONCE_SCAN_LIMIT)
    off = max(floor, ((total - 1) // _NONCE_SCAN_PAGE) * _NONCE_SCAN_PAGE) if total else 0
    while off >= floor and total:
        for sb in dl.list_ballots(election_id, off, min(_NONCE_SCAN_PAGE, total - off)):
            env = sb.envelope
            if env is None:  # malformed record: it carries no nonce to compare
                continue
            if env.pseudonym == pseudonym and env.attestation.nonce > best:
                best = env.attestation.nonce
        if off == floor:
            break
        off = max(floor, off - _NONCE_SCAN_PAGE)
    return best


def submit_ballot(
    dl: ElectionDataLayer,
    election_id: bytes,
    ballot: BallotEnvelope,
    *,
    clock,
    filter_on: bool = True,
    gateway_signer=None,
) -> int:
    """Accept a ballot iff the election is ``Voting``; filter it first if enabled.

    Returns the assigned sequence number. Raises :class:`GatewayRejection` if the
    window is closed or (when ``filter_on``) the ballot fails verification.

    ``gateway_signer`` (a :class:`~shutter_governance_protocol.core.authz.Signer`) authorizes the *write* when the
    election declares a closed writer set (``config.gateway_keys``). It is
    unrelated to the filter above: the filter is UX, this is authorization, and the data
    layer is what enforces it. Unnecessary when ``gateway_keys`` is empty (open writes) or
    on the chain backend (the transaction sender is the writer).
    """
    rec = dl.get_election(election_id)
    cfg = rec.config
    now = clock()

    facts = StateFacts(
        cancelled=rec.cancelled,
        key_finalized=rec.finalized_key is not None,
        result_published=dl.get_result(election_id) is not None,
    )
    if derive_state(cfg, facts, now) is not ElectionState.VOTING:
        raise GatewayRejection("voting is not open")

    if filter_on:
        if rec.finalized_key is None:  # cannot verify proofs without the key
            raise GatewayRejection("no finalized key")
        mpk = g2_from_compressed(rec.finalized_key.pk_election)
        # submitted_at=now so the window check is exercised by the same predicate.
        reason = validate_ballot(StoredBallot(-1, ballot, submitted_at=now), cfg, mpk)
        if reason is not None:
            raise GatewayRejection(reason.value)

        # Replay filter (funds/DoS defense, NOT the integrity boundary): reject a ballot
        # whose signed re-vote nonce is not strictly greater than the highest already stored
        # for this pseudonym, so a replayed old ballot never becomes a (sponsored,
        # gas-paying) on-chain submitVote. The tally's nonce ordering remains
        # authoritative regardless of what got stored.
        att = ballot.attestation
        if att.scheme is AttestationScheme.V1:
            if att.nonce <= _max_stored_nonce(dl, election_id, ballot.pseudonym):
                raise GatewayRejection("STALE_OR_REPLAYED")

    gateway_sig = write_auth.sign_ballot(gateway_signer.private_key, election_id, ballot) \
        if gateway_signer is not None else b""
    return dl.submit_ballot(election_id, ballot, gateway_sig)
