/* Ported voting-dashboard (technical mode) rendered inside the shutter_governance_protocol dashboard body.
 * Sourced from shutter_governance_protocol's public API via ./eth/client. Easy-mode, language/complexity toggles,
 * registry/find-my-vote/AI, and the standalone top bar are dropped (our app supplies the
 * topbar + election dropdown). Live crypto verification is deferred: automatic ballot
 * verification and per-share DLEQ verify are disabled; the "Verify yourself" guide panels
 * (instructional + fixture download) stay. */
import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import "./i18n";
import "./styles.css";
import {
  fetchAggregate, fetchBallotsPage, fetchDecryptionShares, fetchElectionOverview, fetchResult,
} from "./eth/client";
import type {
  Ballot, DecryptionShare, DkgResultView, ElectionConfigView, ElectionResult, EncryptedTally,
} from "./eth/types";
import { CopyTextButton, Hex } from "./ui/Hex";
import { formatUnixUtc } from "./ui/formatUnixUtc";
import { ResultPie2D } from "./ui/ResultPie2D";
import { computeElectionOutcome, formatOutcomeOverviewTitle, formatOutcomeStageTitle, formatVotes } from "./ui/electionOutcome";
import { BallotDetail } from "./ui/BallotDetail";
import { VerifyBallotPanel } from "./ui/VerifyBallotPanel";
import { VerifyAggregatePanel } from "./ui/VerifyAggregatePanel";
import { VerifySharesPanel } from "./ui/VerifySharesPanel";
import { VerifyResultPanel } from "./ui/VerifyResultPanel";
import { Term } from "./ui/Term";
import { StageLifecycleBadge } from "./ui/StageLifecycleBadge";
import { StageLockedPanel, type WaitingOnStage } from "./ui/StageLockedPanel";
import { getStageLifecycle, getWaitingOnStageNums, isStageVerificationAvailable, type StageStatusContext } from "./ui/stageLifecycle";
import { StatusIcon } from "./ui/StatusIcon";
import { verifyBallotLocal, verifySharesLocal } from "./verify";

/** On-demand verification state for a stage or a single ballot. */
type VState = { status: "idle" } | { status: "verifying" } | { status: "ok" } | { status: "bad"; reason: string };

type Overview = { config: ElectionConfigView; dkg: DkgResultView; phase: number; cancelled: boolean; isDKGFinalized: boolean; isResultFinalized: boolean; tallyStalled: boolean };
type Tab = "overview" | "dkg" | "ballots" | "aggregate" | "shares" | "result";

const STAGE_ITEMS = [
  { num: 1, tab: "dkg", title: "Encryption Keys Set Up", subLabel: "Distributed Key Generation (DKG)", desc: "An independent committee of guardians (keypers) jointly generates the election's encryption key. No single party ever holds the key. Only a threshold of them, acting together, can decrypt anything." },
  { num: 2, tab: "ballots", title: "Voters Cast Encrypted Ballots", subLabel: "Encrypted Ballot Submission", desc: "Each voter encrypts their choices on their own device. The ciphertext goes to the registry together with proofs that the voter is eligible and stayed within budget. Their actual choices are never revealed." },
  { num: 3, tab: "aggregate", title: "Encrypted Vote Counting", subLabel: "Homomorphic Aggregation", desc: "All encrypted ballots are added together without ever decrypting any of them. The combined ciphertext per candidate is still fully encrypted, so nothing about individual votes is revealed." },
  { num: 4, tab: "shares", title: "Threshold Decryption", subLabel: "Keyper Decryption Shares (DLEQ-proven)", desc: "A threshold of keypers each contribute one piece of the decryption, with a cryptographic proof that their piece is correct. Only together do these pieces reveal the count. No keyper ever sees the votes alone." },
  { num: 5, tab: "result", title: "Final Tally Published", subLabel: "Decrypted Result", desc: "Once enough keyper shares are combined, the encrypted aggregate decrypts to plain vote counts per candidate, and the winner is determined." },
] as const;

const STAGE_TECH: Record<Tab, ReactNode> = {
  overview: null,
  dkg: (<Trans i18nKey="STAGE_TECH_DKG" components={[<Term id="t-of-n threshold" />, <Term id="DKG" />, <Term id="keyper" />, <Term id="BLS12-381" />]}>A <Term id="t-of-n threshold">t-of-n threshold</Term> <Term id="DKG">DKG</Term> produces a shared public key in G₂ whose private counterpart is split into n secret shares, one per <Term id="keyper">keyper</Term>. Any t of them together can decrypt; fewer cannot. Committee keys and ballots use <Term id="BLS12-381">BLS12-381</Term>.</Trans>),
  ballots: (<Trans i18nKey="STAGE_TECH_BALLOTS" components={[<Term id="ElGamal" />, <Term id="ciphertext" />, <Term id="Schnorr signature" />, <Term id="Whitelist Registrar" />, <Term id="zero-knowledge proof" />, <Term id="budget" />, <Term id="BLS12-381" />]}>Ballots carry <Term id="ElGamal">ElGamal</Term> <Term id="ciphertext">ciphertexts</Term> per candidate, a G₁ <Term id="Schnorr signature">Schnorr signature</Term> over the ballot bytes, a G₁ <Term id="Whitelist Registrar">Whitelist Registrar</Term> attestation that the voter is on the registered list, and <Term id="zero-knowledge proof">ZK range proofs</Term> that each vote is within the election <Term id="budget">budget</Term>. All on <Term id="BLS12-381">BLS12-381</Term>.</Trans>),
  aggregate: (<Trans i18nKey="STAGE_TECH_AGGREGATE" components={[<Term id="ciphertext" />, <Term id="BLS12-381" />]}>Component-wise addition of every accepted ballot <Term id="ciphertext">ciphertext</Term> on <Term id="BLS12-381">BLS12-381</Term> G₂ (each c1 and c2 is point-added separately). The aggregate is one (c1, c2) pair per candidate. No private key material is touched.</Trans>),
  shares: (<Trans i18nKey="STAGE_TECH_SHARES" components={[<Term id="keyper" />, <Term id="DLEQ" />, <Term id="Lagrange interpolation" />]}>Each <Term id="keyper">keyper</Term> publishes a partial decryption σ_i = s_i · C₁ on the aggregate ciphertext per candidate, where s_i is their secret share. A non-interactive <Term id="DLEQ">DLEQ proof</Term> binds σ_i to their committee public key (G₂). Any t valid shares are <Term id="Lagrange interpolation">Lagrange-combined</Term> into the decryption factor without ever assembling a private key.</Trans>),
  result: (<Trans i18nKey="STAGE_TECH_RESULT" components={[<Term id="Lagrange interpolation" />, <Term id="ciphertext" />, <Term id="baby-step / giant-step" />]}>The <Term id="Lagrange interpolation">Lagrange-combined</Term> decryption factor removes the encryption mask from each candidate&apos;s aggregate <Term id="ciphertext">ciphertext</Term> (G₂). A bounded <Term id="baby-step / giant-step">baby-step / giant-step</Term> in G₂ recovers the integer vote count per candidate.</Trans>),
};

/** Adaptive "time until" label: days while ≥ 1 day out, then hours, then minutes as the
 * target approaches, and a sub-minute fallback. Returns null once the target has passed
 * (callers phrase their own imminent-/passed message). */
function countdownLabel(t: TFunction, unixSec: bigint): string | null {
  const secs = Number(unixSec) - Date.now() / 1000;
  if (secs <= 0) return null;
  if (secs < 60) return t("less than a minute");
  if (secs < 3_600) { const n = Math.ceil(secs / 60); return n === 1 ? t("1 minute") : t("{{n}} minutes", { n }); }
  if (secs < 86_400) { const n = Math.ceil(secs / 3_600); return n === 1 ? t("1 hour") : t("{{n}} hours", { n }); }
  const n = Math.ceil(secs / 86_400);
  return n === 1 ? t("1 day") : t("{{n}} days", { n });
}
function stageProgressLabel(t: TFunction, n: number, inProgress: boolean): string {
  return inProgress ? t("Stage {{n}} of 5 in progress", { n }) : t("Stage {{n}} of 5 up next", { n });
}

type OverviewDisplay = {
  leftLabel: "CURRENTLY" | "ELECTION FINALIZED" | "ELECTION CANCELLED"; showCurrentlyDot: boolean; mainTitle: string; mainSub?: string;
  stageHeading?: string; stageDesc?: string; footerDesc?: string;
  rightLabel: "WHAT COMES NEXT" | "WHAT YOU CAN DO NOW"; rightDesc: string;
};

/** "5,100 points · 51 voting power · 51 ballots counted".
 *
 * One word ("votes") used to stand for three different quantities, which is unreadable as
 * soon as weighting is on: points are budget x weight, voting power is the sum of the
 * admitted ballots' weights, and ballots are people. Falls back to points alone before the
 * aggregate has loaded. */
function formatTallySummary(totalPoints: bigint, agg: EncryptedTally | null, t: TFunction): string {
  const points = t("Total: {{n}} points", { n: totalPoints.toLocaleString() });
  if (!agg) return points;
  // "Votes" must be the *scaled* weight, not the raw one: it is what the points
  // reconcile against (points = budget x scaled weight in exact mode), and reading
  // it from the aggregate keeps that true if at-most mode ever ships.
  //
  // This used to read `totalAdmittedWeight`, which is the weight as *held*. At scale 1
  // the two are equal and nothing showed. Above it they diverge by the scale factor and
  // the line contradicted itself — election 3 of the chain run displayed
  // "Total: 1 points · 80 votes" at budget 1, where 80 votes should mean 80 points.
  const parts = [
    points,
    t("{{n}} votes", { n: agg.totalScaledWeight.toLocaleString() }),
    t("{{n}} ballots counted", { n: agg.admittedCount.toLocaleString() }),
  ];
  // Only when scaling actually moved the number. Showing "80 held" beside "80 votes"
  // would be noise; showing it beside "1 vote" is the whole explanation.
  if (agg.totalScaledWeight !== agg.totalAdmittedWeight) {
    parts.push(
      t("from {{n}} voting power held", {
        n: agg.totalAdmittedWeight.toLocaleString(),
      }),
    );
  }
  return parts.join(" · ");
}

function computeOverviewDisplay(p: {
  overview: Overview; result: ElectionResult | null; aggregate: EncryptedTally | null;
  shares: DecryptionShare[] | null; ballotTotal: bigint; ballotCounted: number; ballotSuperseded: number; t: TFunction;
}): OverviewDisplay {
  const { overview, result, aggregate, shares, ballotTotal, ballotCounted, ballotSuperseded, t } = p;
  const thresholdT = Number(overview.config.thresholdT);
  const thresholdN = Number(overview.config.thresholdN);
  const sharesCount = shares?.length ?? 0;
  const stageDesc = (idx: number) => t(STAGE_ITEMS[Math.min(idx, STAGE_ITEMS.length) - 1]!.desc);

  // Cancelled is terminal and takes precedence over every timing/phase branch: the
  // election was called off before voting, so no stage will ever run.
  if (overview.cancelled) {
    return {
      leftLabel: "ELECTION CANCELLED", showCurrentlyDot: false,
      mainTitle: t("This election was cancelled"),
      mainSub: t("The admin cancelled it before voting opened. No key setup, voting, counting, or decryption will take place."),
      rightLabel: "WHAT COMES NEXT", rightDesc: t("Nothing further will happen on this election."),
    };
  }
  if (overview.isResultFinalized && result) {
    const outcome = computeElectionOutcome(result.tally);
    return {
      leftLabel: "ELECTION FINALIZED", showCurrentlyDot: false,
      mainTitle: formatOutcomeOverviewTitle(outcome, t, Number(overview.config.budget)),
      mainSub: formatTallySummary(outcome.totalVotes, aggregate, t),
      footerDesc: t("Every stage has completed. The result is published and fully verifiable."),
      rightLabel: "WHAT YOU CAN DO NOW",
      rightDesc: t("Open any stage below to inspect what happened, then use the right column to re-run that step yourself."),
    };
  }
  if (!overview.isDKGFinalized) {
    return { leftLabel: "CURRENTLY", showCurrentlyDot: true, mainTitle: stageProgressLabel(t, 1, false), stageDesc: stageDesc(1), rightLabel: "WHAT COMES NEXT", rightDesc: stageDesc(2) };
  }
  if (overview.phase < 3) {
    const label = countdownLabel(t, overview.config.votingStart);
    return { leftLabel: "CURRENTLY", showCurrentlyDot: true, mainTitle: t("Voting hasn't opened yet"), mainSub: label ? t("Opens in {{label}}", { label }) : t("Opening now"), stageHeading: stageProgressLabel(t, 2, false), stageDesc: stageDesc(2), rightLabel: "WHAT COMES NEXT", rightDesc: stageDesc(3) };
  }
  if (overview.phase === 3) {
    const label = countdownLabel(t, overview.config.votingEnd);
    return { leftLabel: "CURRENTLY", showCurrentlyDot: true, mainTitle: t("{{n}} ballots cast so far", { n: ballotTotal.toString() }), mainSub: label ? t("Closes in {{label}}", { label }) : t("Voting closing now"), stageHeading: stageProgressLabel(t, 2, true), stageDesc: stageDesc(2), rightLabel: "WHAT COMES NEXT", rightDesc: stageDesc(3) };
  }
  if (!aggregate) {
    const mainSub = ballotSuperseded > 0
      ? t("{{c}} ballots counted · {{s}} superseded by re-votes", { c: ballotCounted, s: ballotSuperseded })
      : t("{{n}} ballots accepted", { n: ballotTotal.toString() });
    return { leftLabel: "CURRENTLY", showCurrentlyDot: true, mainTitle: t("Voting has closed"), mainSub, stageHeading: stageProgressLabel(t, 3, true), stageDesc: stageDesc(3), rightLabel: "WHAT COMES NEXT", rightDesc: stageDesc(4) };
  }
  if (sharesCount < thresholdT) {
    return { leftLabel: "CURRENTLY", showCurrentlyDot: true, mainTitle: t("{{count}} of {{total}} keyper shares received", { count: sharesCount, total: thresholdN }), mainSub: t("Need {{n}} valid shares to decrypt", { n: thresholdT }), stageHeading: stageProgressLabel(t, 4, true), stageDesc: stageDesc(4), rightLabel: "WHAT COMES NEXT", rightDesc: stageDesc(5) };
  }
  return { leftLabel: "CURRENTLY", showCurrentlyDot: true, mainTitle: t("Final tally being published"), mainSub: t("Threshold met · decrypting vote counts"), stageHeading: stageProgressLabel(t, 5, true), stageDesc: stageDesc(5), rightLabel: "WHAT COMES NEXT", rightDesc: stageDesc(5) };
}

const PAGE_SIZE = 10;

/** Client-side re-vote dedup, mirroring the tally's `last-wins` admission (a wallet may
 * re-cast until close; only the latest same-pseudonym ballot is counted). The winner per
 * pseudonym is the highest attestation **nonce** (tie-break: later index), exactly as
 * `admit()` orders by `(nonce, sequence)` — so a replayed old ballot (lower nonce) is shown
 * superseded regardless of when it was submitted. Computed over the FULL ordered ballot list
 * (the data layer stores every submission on both backends, so a duplicate can span pages).
 * Returns the absolute indexes that are superseded, the pseudonyms re-voted at all, and
 * `counted` = distinct pseudonyms (what actually enters the aggregate). */
export interface BallotDedup { superseded: Set<number>; revoted: Set<string>; counted: number }

const EMPTY_DEDUP: BallotDedup = { superseded: new Set(), revoted: new Set(), counted: 0 };

async function fetchAllBallotsFor(electionId: number, total: number): Promise<Ballot[]> {
  const all: Ballot[] = [];
  for (let off = 0; off < total; off += PAGE_SIZE) {
    const { ballots: pg } = await fetchBallotsPage(electionId, off, PAGE_SIZE);
    if (pg.length === 0) break;
    all.push(...pg);
  }
  return all;
}

function computeBallotDedup(all: Ballot[]): BallotDedup {
  const winnerIdx = new Map<string, number>(); // pseudonym -> winning (highest-nonce) index
  const seen = new Map<string, number>();        // pseudonym -> occurrence count
  all.forEach((b, i) => {
    if (b.malformed !== undefined) return; // never counted, and has no real pseudonym
    seen.set(b.pseudonym, (seen.get(b.pseudonym) ?? 0) + 1);
    const cur = winnerIdx.get(b.pseudonym);
    // last-wins by (nonce, index): higher nonce wins; equal nonce → later index.
    if (cur === undefined || b.nonce >= all[cur].nonce) winnerIdx.set(b.pseudonym, i);
  });
  const superseded = new Set<number>();
  all.forEach((b, i) => { if (b.malformed === undefined && winnerIdx.get(b.pseudonym) !== i) superseded.add(i); });
  const revoted = new Set<string>();
  seen.forEach((n, p) => { if (n > 1) revoted.add(p); });
  return { superseded, revoted, counted: winnerIdx.size };
}

export function VotingDashboard({ electionId, elections, onSelectElection, headerAction, audience = "voter" }: {
  electionId: number;
  elections: number[];
  onSelectElection: (id: number) => void;
  headerAction?: ReactNode;
  /** Tailors advisory copy (e.g. the tally-stalled notice) to who's reading. Defaults to
   *  the voter view — the one that must never tell a reader to take an admin-only action. */
  audience?: "admin" | "voter";
}) {
  const { t } = useTranslation();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [aggregate, setAggregate] = useState<EncryptedTally | null>(null);
  const [shares, setShares] = useState<DecryptionShare[] | null>(null);
  const [result, setResult] = useState<ElectionResult | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [tab, setTab] = useState<Tab>("overview");
  const [showTech, setShowTech] = useState(false);
  const [showVerifyGuide, setShowVerifyGuide] = useState(false);
  const [showVerifyPanel, setShowVerifyPanel] = useState(false);

  const [page, setPage] = useState(0);
  // The poll below reads the page the user is on through this ref, so it refreshes that
  // page instead of overwriting it with page 0 every 5 s.
  const pageRef = useRef(0);
  pageRef.current = page;
  const [ballotsTotal, setBallotsTotal] = useState<bigint>(0n);
  const [ballots, setBallots] = useState<Ballot[]>([]);
  const [ballotsLoading, setBallotsLoading] = useState(false);
  const [gotoPageInput, setGotoPageInput] = useState("");
  const [overviewBallotTotal, setOverviewBallotTotal] = useState<bigint>(0n);
  const [detailView, setDetailView] = useState<{ pseudonym: string; globalIndex: number } | null>(null);
  const [downloadingAggFixture, setDownloadingAggFixture] = useState(false);
  const [exportingFixture, setExportingFixture] = useState(false);
  // Re-vote dedup over the full ballot list (last-wins), for the counted-vs-recorded counts
  // and the per-row superseded/counted badges.
  const [dedup, setDedup] = useState<BallotDedup>(EMPTY_DEDUP);
  // On-demand verification: per-ballot (by absolute index — a pseudonym is NOT unique once a
  // wallet re-votes) and per-keyper share (by keyperIndex).
  const [ballotVerify, setBallotVerify] = useState<Record<number, VState>>({});
  const [shareVerify, setShareVerify] = useState<Record<number, VState>>({});

  const selectedElection = String(electionId);

  // ── data loading (initial + poll) ──
  useEffect(() => {
    let alive = true;
    setTab("overview"); setPage(0); pageRef.current = 0; setDetailView(null); setShowVerifyGuide(false); setShowVerifyPanel(false);
    setOverview(null); setAggregate(null); setShares(null); setResult(null);
    setBallotVerify({}); setShareVerify({}); setDedup(EMPTY_DEDUP);
    async function load() {
      try {
        const shownPage = pageRef.current;
        const [ov, agg, sh, res, current] = await Promise.all([
          fetchElectionOverview(electionId), fetchAggregate(electionId), fetchDecryptionShares(electionId),
          fetchResult(electionId), fetchBallotsPage(electionId, shownPage * PAGE_SIZE, PAGE_SIZE),
        ]);
        if (!alive) return;
        setLoadError(null); setOverview(ov); setAggregate(agg); setShares(sh); setResult(res);
        setBallotsTotal(current.total); setOverviewBallotTotal(current.total);
        // Only if the user is still on the page this poll fetched; a page change in the
        // meantime has its own fetch (the effect below).
        if (pageRef.current === shownPage) setBallots(current.ballots);
        // Dedup needs the whole ordered list (a re-vote may span pages). One page suffices
        // when it already holds everything; otherwise fetch the rest.
        const total = Number(current.total);
        const all = total <= PAGE_SIZE && shownPage === 0 ? current.ballots : await fetchAllBallotsFor(electionId, total);
        if (alive) setDedup(computeBallotDedup(all));
      } catch (e) { if (alive) setLoadError(e instanceof Error ? e.message : String(e)); }
    }
    void load();
    const h = setInterval(load, 5000);
    return () => { alive = false; clearInterval(h); };
  }, [electionId]);

  // ── ballots page loading ──
  useEffect(() => {
    if (tab !== "ballots") return;
    let alive = true;
    setBallotsLoading(true);
    fetchBallotsPage(electionId, page * PAGE_SIZE, PAGE_SIZE)
      .then((r) => { if (!alive) return; setBallots(r.ballots); setBallotsTotal(r.total); })
      .finally(() => { if (alive) setBallotsLoading(false); });
    return () => { alive = false; };
  }, [electionId, tab, page]);

  const statusCtx: StageStatusContext | null = overview
    ? { isDKGFinalized: overview.isDKGFinalized, phase: overview.phase, isResultFinalized: overview.isResultFinalized, thresholdT: Number(overview.config.thresholdT), aggregate, shares, cancelled: overview.cancelled, tallyStalled: overview.tallyStalled }
    : null;
  const stageLifecycle = (n: number) => (statusCtx ? getStageLifecycle(n, statusCtx) : "pending");

  const currentStageNum = tab === "dkg" ? 1 : tab === "ballots" ? 2 : tab === "aggregate" ? 3 : tab === "shares" ? 4 : tab === "result" ? 5 : null;
  const isStageView = tab !== "overview";
  // Resolve the open ballot by its ABSOLUTE index within the current page — a pseudonym is
  // not unique once a wallet re-votes, so a pseudonym lookup would return the wrong ballot.
  const detailBallot = detailView ? (ballots[detailView.globalIndex - page * PAGE_SIZE] ?? null) : null;
  // Recorded (every stored ballot) vs counted (distinct pseudonyms, last-wins). Fall back to
  // recorded until the dedup pass has run, so we never flash a premature "0 counted".
  const recordedBallots = Number(overviewBallotTotal);
  const countedBallots = dedup.counted || recordedBallots;
  const supersededBallots = Math.max(0, recordedBallots - countedBallots);
  const isTriple =
    (showVerifyPanel && tab === "ballots" && !!detailBallot && !!detailView) ||
    (showVerifyGuide && ((tab === "aggregate" && !!aggregate) || (tab === "shares" && !!shares && !!aggregate) || (tab === "result" && !!result && !!aggregate && !!shares)));

  const overviewDisplay = useMemo(
    () => (overview ? computeOverviewDisplay({ overview, result, aggregate, shares, ballotTotal: overviewBallotTotal, ballotCounted: countedBallots, ballotSuperseded: supersededBallots, t }) : null),
    [overview, result, aggregate, shares, overviewBallotTotal, countedBallots, supersededBallots, t],
  );

  const totalPages = Math.ceil(Number(ballotsTotal) / PAGE_SIZE);
  const safeTotalPages = Math.max(totalPages, 1);

  function navigateTo(next: Tab) {
    if (next === "ballots") { setDetailView(null); setShowVerifyPanel(false); }
    setShowTech(false); setShowVerifyGuide(false); setTab(next);
  }
  function applyGotoPage() {
    const n = parseInt(gotoPageInput, 10);
    if (Number.isFinite(n)) setPage(Math.max(0, Math.min(safeTotalPages - 1, n - 1)));
    setGotoPageInput("");
  }
  function buildWaitingOn(stageNum: number): WaitingOnStage[] {
    if (!statusCtx) return [];
    return getWaitingOnStageNums(stageNum, statusCtx).map((num) => ({ num, title: t(STAGE_ITEMS[num - 1]!.title) }) as WaitingOnStage);
  }

  function getStageResult(num: number): { title: string; sub: string } | null {
    if (!overview || stageLifecycle(num) !== "done") return null;
    switch (num) {
      case 1: return { title: t("{{n}} of {{n}} keypers ready", { n: overview.config.thresholdN.toString() }), sub: t("Encryption committee finalized") };
      case 2: return supersededBallots > 0
        ? { title: t("{{c}} of {{r}} ballots counted", { c: countedBallots, r: recordedBallots }), sub: t("{{s}} superseded by re-votes", { s: supersededBallots }) }
        : { title: t("{{n}} ballots accepted", { n: overviewBallotTotal.toString() }), sub: t("Voting closed") };
      case 3: return aggregate ? { title: t("{{n}} ballots summed", { n: countedBallots.toString() }), sub: t("Into {{n}} encrypted candidate totals", { n: aggregate.aggregates.length }) } : null;
      case 4: return shares ? { title: t("{{count}} of {{total}} keyper shares received", { count: shares.length, total: overview.config.thresholdN.toString() }), sub: t("Threshold met · tally decrypted") } : null;
      case 5: { if (!result) return null; const o = computeElectionOutcome(result.tally); return { title: formatOutcomeStageTitle(o, t, Number(overview!.config.budget)), sub: formatTallySummary(o.totalVotes, aggregate, t) }; }
      default: return null;
    }
  }

  async function downloadAggregateFixture() {
    if (!overview || !aggregate) return;
    setDownloadingAggFixture(true);
    try {
      const total = Number(overviewBallotTotal); const PAGE = 50; const all: Ballot[] = [];
      for (let off = 0; off < total; off += PAGE) { const { ballots: pg } = await fetchBallotsPage(electionId, off, PAGE); all.push(...pg); }
      const fixture = { electionId: overview.config.electionId.toString(), numCandidates: overview.config.numCandidates, budget: overview.config.budget, mode: overview.config.mode, variant: overview.config.variant, scale: overview.config.scale, mpkElectionG2: overview.dkg.pkElection, pkWrG1: overview.config.pkWR, aggregate: aggregate.aggregates, admitted: aggregate.admitted, ballots: all, exportedAt: new Date().toISOString() };
      const blob = new Blob([JSON.stringify(fixture, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "aggregate-fixture.json"; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } finally { setDownloadingAggFixture(false); }
  }

  async function exportElectionBallotsFixture() {
    if (!overview) return;
    setExportingFixture(true);
    try {
      const total = Number(ballotsTotal); const PAGE = 50; const all: Ballot[] = [];
      for (let off = 0; off < total; off += PAGE) { const { ballots: pg } = await fetchBallotsPage(electionId, off, PAGE); all.push(...pg); }
      const blob = new Blob([JSON.stringify({ electionId: overview.config.electionId.toString(), ballots: all }, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "ballots.json"; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } finally { setExportingFixture(false); }
  }

  function renderStageHeader(stageNum: number, title: string, subLabel: ReactNode, desc: string) {
    const lc = stageLifecycle(stageNum);
    const statusText = lc === "done" ? t("This stage is completed.") : lc === "stalled" ? t("This stage has stalled.") : lc === "in_progress" ? t("This stage is currently active.") : t("This stage hasn't started yet.");
    return (
      <div className="stageDetailHdr">
        <h2 className="stageDetailTitle">{t(title)}</h2>
        <div className="stageDetailSubTag">{subLabel}</div>
        <div className="stageDetailStatusRow"><StageLifecycleBadge lifecycle={lc} /><span className="dim stageDetailStatusText">{statusText}</span></div>
        <p className="stageDetailDesc">{t(desc)}</p>
        {!isTriple && (
          <div className="techSection">
            <button type="button" className="stageDetailTechLink" onClick={() => setShowTech((v) => !v)}>{t("What this means technically")}</button>
            {showTech && <p className="techSectionText">{STAGE_TECH[tab]}</p>}
          </div>
        )}
      </div>
    );
  }
  function renderStageLocked(stageNum: number) {
    if (!overview) return null;
    return <StageLockedPanel stageNum={stageNum} waitingOn={buildWaitingOn(stageNum)} votingStart={overview.config.votingStart} votingEnd={overview.config.votingEnd} isEasy={false} />;
  }
  // Shown on whichever tally stage the coordinator gave up on (aggregate = stage 3, decryption
  // = stage 4). It reached the max poll attempts and won't retry on its own. Copy is tailored
  // to the reader: voters get reassurance (no action for them), admins get the recovery path.
  // A stall has several causes (too few keypers reached quorum, or keypers disagreed / their
  // submissions failed verification), so the wording stays cause-agnostic.
  function renderStalledNotice(stageNum: number) {
    if (!overview?.tallyStalled || stageLifecycle(stageNum) !== "stalled") return null;
    let body: ReactNode;
    if (audience === "admin") {
      body = (<>
        <strong>{t("Tally stalled")}</strong> — {stageNum === 3
          ? t("the keyper committee did not produce a valid encrypted aggregate — too few keypers reached the quorum, or their submissions disagreed.")
          : t("the keyper committee did not produce enough valid decryption shares — too few keypers reached the quorum, or their shares failed verification.")}{" "}
        {t("Once the committee is healthy again, retry the tally to continue.")}
      </>);
    } else {
      body = (<>
        <strong>{t("Vote counting is paused")}</strong> — {stageNum === 3
          ? t("the keyper committee hasn't finished combining the encrypted ballots yet.")
          : t("the keyper committee hasn't finished decrypting the result yet.")}{" "}
        {t("The election administrators have been notified and will resume the count. Your ballot is safely recorded and stays encrypted.")}
      </>);
    }
    return <div className="stageStalledNotice" role="status">{body}</div>;
  }
  // ── on-demand verification (runs the real crypto in-browser, on click) ──
  const verifyCfg = () => ({
    electionId: overview!.config.electionId, numCandidates: overview!.config.numCandidates,
    budget: overview!.config.budget, mode: overview!.config.mode, variant: overview!.config.variant,
    pkWR: overview!.config.pkWR, scale: overview!.config.scale,
  });
  async function runBallotVerify(b: Ballot, gi: number) {
    setBallotVerify((m) => ({ ...m, [gi]: { status: "verifying" } }));
    try {
      const r = await verifyBallotLocal(b, verifyCfg(), overview!.dkg.pkElection);
      setBallotVerify((m) => ({ ...m, [gi]: r.ok ? { status: "ok" } : { status: "bad", reason: r.reason } }));
    } catch (e: any) { setBallotVerify((m) => ({ ...m, [gi]: { status: "bad", reason: e?.message ?? String(e) } })); }
  }
  // One keyper's share verified across all candidates (result shown as a ballot-style card).
  async function runShareVerify(sh: DecryptionShare) {
    if (!aggregate) return;
    setShareVerify((m) => ({ ...m, [sh.keyperIndex]: { status: "verifying" } }));
    try {
      const res = await verifySharesLocal(overview!.config.electionId, overview!.config.numCandidates, aggregate.aggregates, overview!.dkg.committeePKs, [sh]);
      const bad = res.verdicts.filter((v) => !v.ok).length;
      setShareVerify((m) => ({ ...m, [sh.keyperIndex]: res.ok ? { status: "ok" } : { status: "bad", reason: `${bad} candidate share(s) failed DLEQ` } }));
    } catch (e: any) { setShareVerify((m) => ({ ...m, [sh.keyperIndex]: { status: "bad", reason: e?.message ?? String(e) } })); }
  }

  /** Per-keyper share verification result, styled like the ballot's status card. */
  function renderShareVerifyCard(sv: VState, onRun: () => void) {
    const s = sv.status;
    const iconType = s === "ok" ? "ok" : s === "bad" ? "bad" : s === "verifying" ? "checking" : "idle";
    return (
      <div className={`bdStatusCard bdStatusCard--${iconType}`} style={{ marginTop: 12, marginBottom: 0 }}>
        <div className="bdStatusIcon"><StatusIcon type={iconType} /></div>
        <div className="bdStatusBody">
          {s === "ok" && (<><div className="bdStatusTitle">{t("VALID")}</div><div className="bdStatusDesc">{t("Every candidate's decryption-share DLEQ proof checks out against this keyper's committee key.")}</div></>)}
          {s === "bad" && (<><div className="bdStatusTitle">{t("INVALID")}</div><div className="bdStatusDesc">{(sv as { reason: string }).reason}</div></>)}
          {s === "verifying" && (<><div className="bdStatusTitle">{t("Verifying…")}</div><div className="bdStatusDesc">{t("Running the DLEQ checks in your browser.")}</div></>)}
          {s === "idle" && (<>
            <div className="bdStatusTitle">{t("Not verified yet")}</div>
            <div className="bdStatusDesc">{t("Check this keyper's decryption-share proofs in your browser.")}</div>
            <button type="button" className="verifyYourselfBtn" style={{ marginTop: 10 }} disabled={!aggregate} onClick={onRun}>{t("Verify share")}</button>
          </>)}
        </div>
      </div>
    );
  }

  function renderVerifySection(stageNum: number) {
    if (isTriple) return null;
    const available = statusCtx !== null && isStageVerificationAvailable(stageNum, statusCtx, { hasAggregate: aggregate !== null, hasShares: shares !== null && shares.length > 0, hasResult: result !== null });
    return (
      <div className="verifyYourselfSection">
        <div className="verifyYourselfLabel">{t("VERIFY YOURSELF")}</div>
        <p className="verifyYourselfDesc">{available ? t("Don't trust this panel · re-run the same cryptographic check yourself, against this stage's on-chain data, on your own machine.") : t("Once this stage completes, you'll be able to re-run its cryptographic check on your own machine · same code, same fixtures, no trust in the dashboard required.")}</p>
        <button type="button" className="verifyYourselfBtn" disabled={!available} onClick={() => available && setShowVerifyGuide((v) => !v)}>
          {available ? (showVerifyGuide ? t("Hide manual guide ↑") : t("Open manual verification guide →")) : t("Manual verification not available yet")}
        </button>
      </div>
    );
  }

  if (loadError) return (
    <div className="vd"><div className="pageMain">
      <div className="errorBanner">
        {t("Couldn't load election data.")}{" "}
        <span style={{ opacity: 0.7 }}>({loadError})</span>
      </div>
    </div></div>
  );
  if (!overview) return <div className="vd"><div className="pageMain"><div className="emptyState dim">Loading…</div></div></div>;

  return (
    <div className="vd">
      <div className="pageMain">
        {/* Election header */}
        <div className="elecHeader">
          <div className="elecHeaderTop">
            <div className="elecHeaderMain">
              <div className="elecHeaderLabel">{t("Election #{{n}}", { n: overview.config.electionId.toString() })}</div>
              <div className="elecHeaderTitle">{t("Encrypted Election")}</div>
              <div className="elecHeaderSubtitle">{t("A secret-ballot, end-to-end verifiable vote.")}</div>
              {overview.cancelled && (
                <div className="elecHeaderCancelled" role="status">
                  <span className="elecHeaderCancelled__tag">{t("CANCELLED")}</span>
                  <span>{t("This election was cancelled before voting opened — no key setup, voting, counting, or decryption will take place.")}</span>
                </div>
              )}
            </div>
            <div className="elecHeaderSwitch">
              <div className="switchElecLabel">{t("SWITCH ELECTION")}</div>
              {elections.length > 0 ? (
                <select className="switchElecSelect" value={String(electionId)} onChange={(e) => onSelectElection(Number(e.target.value))}>
                  {elections.map((id) => (<option key={id} value={id}>{t("Election #{{n}}", { n: id })}</option>))}
                </select>
              ) : (
                <span className="dim" style={{ fontSize: 12 }}>{t("No elections")}</span>
              )}
              {headerAction && <div style={{ marginTop: 12, display: "flex", justifyContent: "flex-end" }}>{headerAction}</div>}
            </div>
          </div>
          {/* Drives the column count, so the row stays a single row whether or not the
              scale stat is present. */}
          <div
            className="elecHeaderStats"
            style={
              {
                "--elec-stat-cols": overview.config.scale > 1 ? 6 : 5,
              } as CSSProperties
            }
          >
            <div className="elecHeaderStat"><div className="elecHeaderStatLabel">{t("Voting Opens")}</div><div className="elecHeaderStatValue">{formatUnixUtc(overview.config.votingStart)} <span className="elecHeaderStatDesc">UTC</span></div></div>
            <div className="elecHeaderStat"><div className="elecHeaderStatLabel">{t("Voting Closes")}</div><div className="elecHeaderStatValue">{formatUnixUtc(overview.config.votingEnd)} <span className="elecHeaderStatDesc">UTC</span></div></div>
            <div className="elecHeaderStat"><div className="elecHeaderStatLabel">{t("Candidates on the Ballot")}</div><div className="elecHeaderStatValue">{overview.config.numCandidates} <span className="elecHeaderStatDesc">{t("people running")}</span></div></div>
            <div className="elecHeaderStat"><div className="elecHeaderStatLabel">{t("Vote Points per Voter")}</div><div className="elecHeaderStatValue">{overview.config.budget} <span className="elecHeaderStatDesc">{t("point(s) each")}</span></div><div className="elecHeaderStatDesc">{t("Each voter gets {{budget}} points to distribute across the {{candidates}} candidates.", { budget: overview.config.budget, candidates: overview.config.numCandidates })}</div></div>
            {/* Only above 1. At scale 1 every weight counts as held, so a stat reading
                "counts in units of 1" is noise; above it, every number on this page is
                in those units and the reader needs to know before reading any of them. */}
            {overview.config.scale > 1 && (
              <div className="elecHeaderStat">
                <div className="elecHeaderStatLabel">{t("Counted in Units of")}</div>
                <div className="elecHeaderStatValue">
                  {overview.config.scale.toLocaleString()}{" "}
                  <span className="elecHeaderStatDesc">{t("per vote")}</span>
                </div>
                <div className="elecHeaderStatDesc">
                  {t("Every voter's power is divided by {{scale}} before counting, so ratios are kept but the unit is coarser. A voter holding less than {{floor}} is recorded and counts as nothing.", { scale: overview.config.scale.toLocaleString(), floor: (overview.config.scale / 2).toLocaleString() })}
                </div>
              </div>
            )}
            <div className="elecHeaderStat"><div className="elecHeaderStatLabel">{t("Key Guardians")}</div><div className="elecHeaderStatValue">{t("{{t}} of {{n}}", { t: overview.config.thresholdT.toString(), n: overview.config.thresholdN.toString() })} <span className="elecHeaderStatDesc">{t("must agree")}</span></div><div className="elecHeaderStatDesc">{t("An independent committee. Only when {{t}} of them combine their keys can the result be decrypted · no single guardian can ever see the votes alone.", { t: overview.config.thresholdT.toString() })}</div></div>
          </div>
        </div>

        {/* HOW + CURRENTLY */}
        <div className="persistentOverviewContent">
          <div className="trustSection">
            {/* <div className="trustSectionLabel">{t("HOW THIS ELECTION IS KEPT HONEST")}</div> */}
            <div className={`overviewHonestGrid${overviewDisplay ? "" : " overviewHonestGrid--trustOnly"}`}>
              {/* <div className="overviewHonestCell trustCard">
                <div className="trustCardTitle">{t("Every step is public, signed, and cryptographically proven.")}</div>
                <div className="trustCardDesc">{t("Every action on this election · key setup, ballot submission, counting, decryption · is recorded on-chain with a signature and a")} <Term id="zero-knowledge proof">{t("zero-knowledge proof")}</Term> {t("of correctness. Anyone, including you, can re-run any proof to confirm.")}</div>
              </div>
              <div className="overviewHonestCell trustCard">
                <div className="trustCardTitle">{t("Votes are counted while still encrypted.")}</div>
                <div className="trustCardDesc">{t("Using")} <Term id="homomorphic tallying">{t("homomorphic tallying")}</Term>{t(", encrypted ballots are added together so the totals appear without ever decrypting any individual ballot. You can inspect every ciphertext on-chain and re-verify the tallying authority's proofs that the count is correct.")}</div>
              </div> */}
              {overviewDisplay && (<>
                <div className="overviewHonestCell overviewStatusBlock">
                  <div className="overviewStatusLabel">{overviewDisplay.leftLabel === "CURRENTLY" ? (<>{t("CURRENTLY")} {overviewDisplay.showCurrentlyDot && <span className="overviewCurrentlyDot" />}</>) : (t(overviewDisplay.leftLabel))}</div>
                  {overviewDisplay.leftLabel === "ELECTION FINALIZED" ? (<>
                    <h2 className="overviewStatusWinner">{overviewDisplay.mainTitle}</h2>
                    {overviewDisplay.mainSub && <p className="overviewStatusWinnerSub">{overviewDisplay.mainSub}</p>}
                    {overviewDisplay.footerDesc && (<><hr className="overviewStatusDivider" /><p className="overviewStatusDesc">{overviewDisplay.footerDesc}</p></>)}
                  </>) : (<>
                    <h2 className="overviewStatusTitle">{overviewDisplay.mainTitle}</h2>
                    {overviewDisplay.mainSub && <p className="overviewStatusSub">{overviewDisplay.mainSub}</p>}
                    {overviewDisplay.stageHeading ? (<><hr className="overviewStatusDivider" /><p className="overviewStageHeading">{overviewDisplay.stageHeading}</p>{overviewDisplay.stageDesc && <p className="overviewStatusDesc">{overviewDisplay.stageDesc}</p>}</>) : (overviewDisplay.stageDesc && <p className="overviewStatusDesc">{overviewDisplay.stageDesc}</p>)}
                  </>)}
                </div>
                <div className="overviewHonestCell overviewStatusBlock"><div className="overviewStatusLabel">{t(overviewDisplay.rightLabel)}</div><p className="overviewStatusDesc">{overviewDisplay.rightDesc}</p></div>
              </>)}
            </div>
          </div>
        </div>

        {/* Column headers + content — the whole stage browser is hidden for a cancelled
            election (nothing ran), leaving just the header, banner, stats, and status. */}
        {!overview.cancelled && (
        <div className={`contentFrame${!isStageView ? " contentFrame--overview" : ""}`}>
          <div className={`colHeaders ${!isStageView ? "colHeaders--single" : isTriple ? "colHeaders--triple" : "colHeaders--split"}`}>
            <div className="colHeader colHeaderLeft" role="button" tabIndex={0} onClick={() => navigateTo("overview")} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); navigateTo("overview"); } }}>
              <span><span style={{ color: "#6b7280" }}>01</span> <span style={{ color: "#0b1220" }}>{t("OVERVIEW")}</span></span>
            </div>
            {isStageView && (
              <div className={`colHeader colHeaderRight${isTriple ? " colHeaderRightNav" : ""}`} role={isTriple ? "button" : undefined} tabIndex={isTriple ? 0 : undefined} onClick={isTriple ? () => { setShowVerifyPanel(false); setShowVerifyGuide(false); } : undefined}>
                <span><span style={{ color: "#6b7280" }}>02</span> <span style={{ color: "#0b1220" }}>{t("STAGE")}</span></span>
              </div>
            )}
            {isTriple && (
              <div className="colHeader colHeaderVerify">
                <span><span style={{ color: "#6b7280" }}>03</span> <span style={{ color: "#0b1220" }}>{t("VERIFY")}</span></span>
                <button type="button" className="colHeaderCloseBtn" onClick={() => { setShowVerifyPanel(false); setShowVerifyGuide(false); }}>{t("CLOSE")}</button>
              </div>
            )}
          </div>

          {/* OVERVIEW MODE */}
          {!isStageView && (
            <div className="overviewBody">
              <p className="overviewQuote">{t("\"Every ballot encrypted, counted while still encrypted, opened only by a committee acting together.\"")}</p>
              <div className="stageListFull">
                {STAGE_ITEMS.map((s) => {
                  const lc = stageLifecycle(s.num);
                  const sr = getStageResult(s.num);
                  return (
                    <div key={s.num} className={`stageRowFull${lc === "done" ? " stageRowFull--done" : ""}${lc === "in_progress" ? " stageRowFull--inProgress" : ""}`} role="button" tabIndex={0} onClick={() => navigateTo(s.tab)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); navigateTo(s.tab); } }}>
                      <div className="stageRowFullContent">
                        <div className="stageRowFullNum">0{s.num}</div>
                        <div className="stageRowFullBody">
                          <h3 className="stageRowFullTitle">{t(s.title)}</h3>
                          <div className="stageRowFullSub">{t(s.subLabel)}</div>
                          <p className="stageRowFullDesc">{t(s.desc)}</p>
                          {sr && (<div className="stageRowResult"><div className="stageRowResultLabel">{t("RESULT")}</div><div className="stageRowResultTitle">{sr.title}</div><div className="stageRowResultSub">{sr.sub}</div></div>)}
                          <span className="stageRowFullBadge"><StageLifecycleBadge lifecycle={lc} /></span>
                        </div>
                      </div>
                      <div className="stageRowFullArrow">›</div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* STAGE MODE */}
          {isStageView && (
            <div className={`stageLayout${isTriple ? " stageLayout--triple" : ""}`}>
              <div className="stageLeftCol">
                <div className="stageMiniList">
                  {STAGE_ITEMS.map((s) => {
                    const lc = stageLifecycle(s.num); const isActive = currentStageNum === s.num;
                    return (
                      <div key={s.num} className={`stageRowMini${lc === "done" ? " stageRowMini--done" : ""}${lc === "in_progress" ? " stageRowMini--inProgress" : ""}${isActive ? " stageRowMini--active" : ""}`} role="button" tabIndex={0} onClick={() => navigateTo(s.tab)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); navigateTo(s.tab); } }}>
                        <div className="stageRowMiniNum">0{s.num}</div>
                        <div className="stageRowMiniBody"><div className="stageRowMiniTitle">{t(s.title)}</div><StageLifecycleBadge lifecycle={lc} small /></div>
                        <div className="stageRowMiniArrow">›</div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="stageRightCol">
                {tab === "dkg" && (
                  <div className="stageDetail slideInRight">
                    {renderStageHeader(1, STAGE_ITEMS[0].title, <Term id={STAGE_ITEMS[0].subLabel}>{STAGE_ITEMS[0].subLabel}</Term>, STAGE_ITEMS[0].desc)}
                    <div className="stageDataGrid">
                      <span className="dim"><Term id="Threshold">{t("Threshold")}</Term></span>
                      <span className="mono">{t("{{t}} of {{n}} keypers", { t: overview.config.thresholdT.toString(), n: overview.config.thresholdN.toString() })}</span>
                      <span className="dim">{t("DKG finalized")}</span>
                      <span className="mono">{overview.isDKGFinalized ? t("Yes") : t("No")}</span>
                      <span className="dim"><Term id="Election Public Key">{t("Election Public Key")}</Term></span>
                      <span><Hex value={overview.dkg.pkElection} trim={24} /></span>
                      <span className="dim"><Term id="Whitelist Registrar">{t("Whitelist Registrar Key")}</Term></span>
                      <span><Hex value={overview.config.pkWR} trim={24} /></span>
                    </div>
                    {overview.config.keyperAddresses.length > 0 && (
                      <div className="keyperCommittee">
                        <div className="keyperCommitteeTitle"><Term id="Keyper committee">{t("KEYPER COMMITTEE")}</Term></div>
                        {overview.config.keyperAddresses.map((addr, i) => (<div key={addr} className="keyperRow mono"><span className="keyperRowIdx">#{i}</span><span className="flex1"><Hex value={addr} trim={22} /></span></div>))}
                      </div>
                    )}
                  </div>
                )}

                {tab === "ballots" && (
                  <div className="stageDetail slideInRight">
                    {renderStageHeader(2, STAGE_ITEMS[1].title, <Term id={STAGE_ITEMS[1].subLabel}>{STAGE_ITEMS[1].subLabel}</Term>, STAGE_ITEMS[1].desc)}
                    {stageLifecycle(2) === "pending" ? renderStageLocked(2) : !isTriple && (!detailView || !detailBallot) ? (
                      <>
                        <div className="blControls">
                          <div className="blSummary">
                            {ballotsLoading && <span className="blSummaryMeta">{t("Loading…")}</span>}
                          </div>
                          <div className="blPagination">
                            <button type="button" onClick={() => void exportElectionBallotsFixture()} disabled={ballotsLoading || exportingFixture} style={{ fontSize: 12 }}>{exportingFixture ? t("Exporting…") : t("Export Ballots")}</button>
                            <span className="badge statPill">{t("total {{n}}", { n: ballotsTotal.toString() })}</span>
                            <span className="badge statPill">{t("page size {{n}}", { n: PAGE_SIZE })}</span>
                            <span className="badge statPill">{t("page {{n}}/{{total}}", { n: page + 1, total: safeTotalPages })}</span>
                            <div className="gotoPill"><div className="gotoPillLabel">{t("go to")}</div><input inputMode="numeric" type="number" value={gotoPageInput} onChange={(e) => setGotoPageInput(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { applyGotoPage(); (e.currentTarget as HTMLInputElement).blur(); } }} placeholder={`${page + 1}`} style={{ width: 70, padding: "8px 10px" }} min={1} /></div>
                            <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>{t("Prev")}</button>
                            <button onClick={() => setPage((p) => Math.min(safeTotalPages - 1, p + 1))} disabled={page + 1 >= safeTotalPages}>{t("Next")}</button>
                          </div>
                        </div>
                        <div className="blList">
                          {ballots.map((b, index) => {
                            const globalIndex = page * PAGE_SIZE + index;
                            const isSuperseded = dedup.superseded.has(globalIndex);
                            const isRevoted = dedup.revoted.has(b.pseudonym);
                            return (
                              <div key={`ballot-${globalIndex}`} className={`blRow${isSuperseded ? " blRow--superseded" : ""}`} role="button" tabIndex={0} onClick={() => { setDetailView({ pseudonym: b.pseudonym, globalIndex }); setShowVerifyPanel(false); }} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setDetailView({ pseudonym: b.pseudonym, globalIndex }); setShowVerifyPanel(false); } }}>
                                <div className="blRowIndex"><div className="blRowIndexLabel">index {globalIndex}</div></div>
                                <div className="blRowPseudonym"><span className="blRowPseudonymLabel dim">pseudonym</span><span className="blRowPseudonymGroup"><span className="mono"><Hex value={b.pseudonym} trim={14} copyable={false} /></span><span onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}><CopyTextButton text={b.pseudonym} ariaLabel={t("Copy pseudonym")} /></span></span></div>
                                <div className="blRowStatus">
                                  {b.malformed !== undefined ? (
                                    <span className="tip tip--end" data-tip={t("This record could not be read as a ballot — not counted")}>
                                      <span className="blBadge blBadge--superseded">{t("malformed")}</span>
                                    </span>
                                  ) : isSuperseded ? (
                                    <span className="tip tip--end" data-tip={t("A later ballot from this wallet replaced it — not counted")}>
                                      <span className="blBadge blBadge--superseded">{t("superseded")}</span>
                                    </span>
                                  ) : isRevoted ? (
                                    <span className="tip tip--end" data-tip={t("The wallet's latest re-vote — this is the one counted")}>
                                      <span className="blBadge blBadge--counted">{t("counted")}</span>
                                    </span>
                                  ) : null}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                        <p className="blHelpText">Click any ballot to see its cryptographic details (ciphertexts, ZK proof, voter signature, attestation).</p>
                      </>
                    ) : !isTriple ? (
                      <BallotDetail ballot={detailBallot!} globalIndex={detailView!.globalIndex} verifyState={{ ...(ballotVerify[detailView!.globalIndex] ?? { status: "idle" }), token: 0 } as any} onBack={() => { setDetailView(null); setShowVerifyPanel(false); }} onVerifyLocally={() => void runBallotVerify(detailBallot!, detailView!.globalIndex)} onToggleGuide={() => setShowVerifyPanel((open) => !open)} guideOpen={showVerifyPanel} txHash={null} explorerUrl={undefined} scale={overview!.config.scale} />
                    ) : null}
                  </div>
                )}

                {tab === "aggregate" && (
                  <div className="stageDetail slideInRight">
                    {renderStageHeader(3, STAGE_ITEMS[2].title, <Term id={STAGE_ITEMS[2].subLabel}>{STAGE_ITEMS[2].subLabel}</Term>, STAGE_ITEMS[2].desc)}
                    {renderStalledNotice(3)}
                    {stageLifecycle(3) === "pending" ? (<>{renderStageLocked(3)}{renderVerifySection(3)}</>) : !aggregate ? (<><p className="stageAwaitingData dim">{t("No aggregate published yet. The tally aggregator will homomorphically sum accepted ballots after voting closes.")}</p>{renderVerifySection(3)}</>) : (<>
                      {!isTriple && (<>
                        <div className="stageCountBadge">{t("candidates: {{n}}", { n: aggregate.aggregates.length })}</div>
                        <div className="dataCardList">
                          {aggregate.aggregates.map((ct, j) => (<div key={j} className="dataCard candidateBlock mono"><div className="candidateBlockLabel">{t("candidate {{n}}", { n: j })}</div><div className="candidateBlockData"><div className="candidateCipherRow"><span className="dim">c1</span><Hex value={ct.c1} trim={24} /></div><div className="candidateCipherRow"><span className="dim">c2</span><Hex value={ct.c2} trim={24} /></div></div></div>))}
                        </div>
                        <p className="dim helpFootnote" style={{ marginTop: 20 }}>{t("The aggregate is the encrypted combined vote per candidate: every accepted ballot ciphertext is added together (homomorphic encrypted sum). You still only see ciphertexts here · the actual vote counts stay hidden until keypers submit decryption shares.")}</p>
                      </>)}
                      {renderVerifySection(3)}
                    </>)}
                  </div>
                )}

                {tab === "shares" && (
                  <div className="stageDetail slideInRight">
                    {renderStageHeader(4, STAGE_ITEMS[3].title, <Term id={STAGE_ITEMS[3].subLabel}>{STAGE_ITEMS[3].subLabel}</Term>, STAGE_ITEMS[3].desc)}
                    {renderStalledNotice(4)}
                    {stageLifecycle(4) === "pending" ? (<>{renderStageLocked(4)}{renderVerifySection(4)}</>) : !shares ? (<div className="dim">{t("Loading shares…")}</div>) : shares.length === 0 ? (<><p className="stageAwaitingData dim">{t("No decryption shares submitted yet. Keypers publish one share per candidate once the aggregate is on-chain.")}</p>{renderVerifySection(4)}</>) : (<>
                      {!isTriple && (<>
                        <div className="stageCountBadge">{t("shares submitted: {{n}}", { n: shares.length })}</div>
                        <div className="dataCardList">
                          {shares.map((sh, rowIdx) => { const sv = shareVerify[sh.keyperIndex] ?? { status: "idle" as const };
                            return (
                            <div key={`sh-${rowIdx}-${sh.keyperIndex}`} className="dataCard shareBlock">
                              <div className="shareBlockHeader"><span className="shareBlockKeyper"><span className="shareBlockKeyperIndex">#{sh.keyperIndex}</span><span className="shareBlockKeyperLabel"> {t("KEYPER")}</span></span></div>
                              {renderShareVerifyCard(sv, () => void runShareVerify(sh))}
                              <div className="shareBlockBody">
                                {sh.shares.map((shareHex, j) => (
                                  <div key={j} className="shareCandidate">
                                    <div className="shareCandidateHdr"><span className="shareCandidateTitle">{t("CANDIDATE {{n}}", { n: j })}</span></div>
                                    <div className="shareCandidateData">
                                      <span className="shareFieldLabel">{t("share")}</span>
                                      <div style={{ minWidth: 0 }}><Hex value={shareHex} trim={30} nowrap /></div>
                                      {sh.rawProofs?.[j] && (<>
                                        <span className="shareFieldLabel">{t("proof (DLEQ)")}</span>
                                        <div style={{ minWidth: 0 }}><Hex value={sh.rawProofs[j]} trim={30} nowrap /></div>
                                      </>)}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ); })}
                        </div>
                      </>)}
                      {renderVerifySection(4)}
                    </>)}
                  </div>
                )}

                {tab === "result" && (
                  <div className="stageDetail slideInRight">
                    {renderStageHeader(5, STAGE_ITEMS[4].title, <Term id={STAGE_ITEMS[4].subLabel}>{STAGE_ITEMS[4].subLabel}</Term>, STAGE_ITEMS[4].desc)}
                    {stageLifecycle(5) === "pending" ? (<>{renderStageLocked(5)}{renderVerifySection(5)}</>) : !result ? (<><p className="stageAwaitingData dim">{t("No result published yet. Once enough keyper shares are combined, the decrypted tally will appear here.")}</p>{renderVerifySection(5)}</>) : (<>
                      {!isTriple && (
                        <div className="dataCardList">
                          <div className="dataCard tallySection"><div className="tallySectionHdr"><span className="tallySectionTitle">{t("TALLY")}</span><span className="dim">{t("{{n}} candidates · {{votes}} votes", { n: result.tally.length, votes: formatVotes(result.tally.reduce((s, c) => s + c, 0n), Number(overview.config.budget)) })}</span></div><ResultPie2D tally={result.tally} budget={Number(overview.config.budget)} /></div>
                          {result.keyperIndices.length > 0 && (<div className="dataCard keypersCard"><div className="tallySectionTitle">{t("KEYPERS USED")}</div><div className="keypersIndicesList"><span className="keypersIndicesPill">{t("Indices: {{list}}", { list: result.keyperIndices.join(", ") })}</span></div></div>)}
                        </div>
                      )}
                      {renderVerifySection(5)}
                    </>)}
                  </div>
                )}
              </div>

              {/* Verify column (guide panels — instructional, no live crypto) */}
              {showVerifyPanel && tab === "ballots" && detailBallot && detailView && (<div className="stageVerifyCol slideInRight"><VerifyBallotPanel ballot={detailBallot} globalIndex={detailView.globalIndex} overview={overview} selectedElection={selectedElection} /></div>)}
              {showVerifyGuide && tab === "aggregate" && aggregate && (<div className="stageVerifyCol slideInRight"><VerifyAggregatePanel aggregate={aggregate} onDownloadFixture={downloadAggregateFixture} downloading={downloadingAggFixture} /></div>)}
              {showVerifyGuide && tab === "shares" && shares && aggregate && (<div className="stageVerifyCol slideInRight"><VerifySharesPanel overview={overview} aggregate={aggregate} shares={shares} selectedElection={selectedElection} /></div>)}
              {showVerifyGuide && tab === "result" && result && aggregate && shares && (<div className="stageVerifyCol slideInRight"><VerifyResultPanel overview={overview} aggregate={aggregate} shares={shares} result={result} totalBallots={overviewBallotTotal} selectedElection={selectedElection} /></div>)}
            </div>
          )}
        </div>
        )}
      </div>
    </div>
  );
}
