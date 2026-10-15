"""Auditor procedure.

Anyone can audit an election from public reads alone: recompute DKG finalization
from the stored submissions, independently re-derive the admitted set and the
weighted aggregate, re-verify every decryption share's DLEQ, and recombine to
check the published result. Any mismatch is publishable evidence.
Detection is guaranteed even against a malicious data layer / gateway /
coordinator (v1 has no in-protocol challenge).

The result is **checked, not re-solved**: each published total is multiplied by the
generator and compared to the ``τ`` this audit derives itself. That is exactly as
conclusive as re-running BSGS — the discrete log is unique, so only the true total
satisfies the equality — and it costs one scalar multiplication per candidate
instead of an ``O(√bound)`` search holding a √bound-entry table. An auditor obliged
to re-solve could not audit a large election at all; see
``docs/COORDINATOR_SIZING.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.admission import admit
from shutter_governance_protocol.services.common.reads import read_all_ballots
from shutter_governance_protocol.core.aggregation import bsgs_bound, build_aggregate_artifact, check_result
from shutter_governance_protocol.ports.data_layer import ElectionDataLayer


@dataclass
class AuditReport:
    dkg_ok: bool = False
    aggregate_ok: bool = False
    shares_ok: bool = False
    result_ok: bool = False
    discrepancies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.dkg_ok and self.aggregate_ok and self.shares_ok and self.result_ok and not self.discrepancies


def _submitter_index(cfg, election_id: bytes, submission) -> int | None:
    """Recover the DKG submitter from its content signature (see shutter_governance_protocol.write_auth).

    A vote with no signature can still carry the address its backend authenticated
    (``submission.submitter``: on chain, the contract's ``msg.sender`` for a keyper that
    sent its own transaction). That is used only when there is no signature to check.
    """
    if not submission.keyper_signature:
        recovered = submission.submitter
    else:
        try:
            recovered = write_auth.recover_digest(
                write_auth.dkg_result_digest(election_id, submission.pk_election, list(submission.committee_pks)),
                submission.keyper_signature,
            )
        except Exception:  # noqa: BLE001
            return None
    if recovered is None:
        return None
    for i, k in enumerate(cfg.keypers, start=1):
        if k.signing_key == recovered:
            return i
    return None


def audit(dl: ElectionDataLayer, election_id: bytes) -> AuditReport:
    report = AuditReport()
    rec = dl.get_election(election_id)
    cfg = rec.config

    # 1. Recompute DKG finalization from the stored submissions (quorum rule).
    submissions = dl.get_dkg_submissions(election_id)
    groups: dict[tuple, set[int]] = {}
    for sub in submissions:
        idx = _submitter_index(cfg, election_id, sub)
        if idx is None:
            report.discrepancies.append("dkg: a submission is signed by no registered keyper")
            continue
        groups.setdefault((sub.pk_election, sub.committee_pks), set()).add(idx)
    finalized = next((k for k, v in groups.items() if len(v) >= cfg.threshold.quorum), None)
    published_key = dl.get_finalized_key(election_id)
    if finalized is None:
        report.discrepancies.append("dkg: no quorum among submissions")
    elif published_key is None or (published_key.pk_election, published_key.committee_pks) != finalized:
        report.discrepancies.append("dkg: published finalized key disagrees with recomputation")
    else:
        report.dkg_ok = True

    if published_key is None:
        return report  # cannot proceed without a key

    # 2. Independently re-derive the admitted set + weighted aggregate; compare.
    # Paged and verified complete: a short read would make the auditor
    # "detect" a discrepancy that is really its own truncated view. Each row carries the
    # authoritative submitted_at, so the voting-window exclusions are re-derived too.
    stored = read_all_ballots(dl, election_id)
    admission = admit(stored, cfg, published_key.pk_election)
    recomputed_agg = build_aggregate_artifact(cfg, admission)
    published_agg = dl.get_aggregate(election_id)
    if published_agg is None:
        report.discrepancies.append("aggregate: none published")
        return report
    if recomputed_agg == published_agg:
        report.aggregate_ok = True
    else:
        if recomputed_agg.admitted != published_agg.admitted:
            report.discrepancies.append("aggregate: admitted set differs from recomputation")
        if recomputed_agg.aggregates != published_agg.aggregates:
            report.discrepancies.append("aggregate: ciphertexts differ from recomputation")
        if recomputed_agg.exclusions != published_agg.exclusions:
            report.discrepancies.append("aggregate: exclusions differ from recomputation")
        if recomputed_agg.total_admitted_weight != published_agg.total_admitted_weight:
            report.discrepancies.append("aggregate: total admitted weight differs")

    # 3 + 4. Re-verify shares' DLEQs and check the published result against them.
    shares = dl.list_decryption_shares(election_id)
    published_result = dl.get_result(election_id)
    if published_result is None:
        # Nothing to check against. Deliberately *not* an occasion to solve it here:
        # recovering a withheld result is an escalation someone chooses, with
        # `recover_result` and a machine sized for it, not a side effect of auditing.
        report.discrepancies.append("result: none published")
        return report

    ok, reason = check_result(
        cfg,
        published_agg,
        shares,
        published_key.committee_pks,
        cfg.threshold.t,
        tuple(published_result.totals),
    )
    # A `shares:` reason means the committee never produced a verifiable quorum;
    # any other reason means the shares were fine and the totals were not.
    report.shares_ok = ok or not reason.startswith("shares:")
    if not ok:
        report.discrepancies.append(reason)
        return report

    # Advisory, not load-bearing: the check above already establishes the totals.
    # The bound is derivable from the aggregate, so a mismatch here narrows a
    # discrepancy to "published against a different admitted set" instead of leaving
    # it as a bare disagreement.
    # The scaled total: the tally searches budget × Σ(scaled weights), and the raw total
    # differs from it whenever scale > 1.
    expected_bound = bsgs_bound(cfg, published_agg.total_scaled_weight)
    if published_result.bsgs_bound != expected_bound:
        report.discrepancies.append(
            f"result: published BSGS bound {published_result.bsgs_bound} "
            f"!= derived {expected_bound}"
        )
        return report

    report.result_ok = True
    return report
