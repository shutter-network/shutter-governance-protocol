import { forwardRef, useEffect, useState } from "react";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import { parseEther } from "viem";
import { api, cancelElection, eidToBareHex, eidToHex, ELIGIBILITY_URL, fetchEligibilityKey, formatApiError, registerElection } from "@shutter-governance-protocol/shared";
import { type WalletSigner } from "@shutter-governance-protocol/shared/wallet";
import { cancelDigest, encodeElectionId, lowercaseHex, registerDigest } from "./adminSign";
import { requireAddress, requireEligibilityKey, sponsorAddress } from "./fieldValidation";
import { FieldHint } from "./FieldHint";

// A connected signer (its account is non-null wherever a Wallet is passed).
type Wallet = WalletSigner;

// Placeholder only — doRegister replaces it with the id this registration asserts
// (the sequence head + 1), which is what the admin signature binds.
const ZERO_EID = "0x" + "0".repeat(64);

// Ballot/tally feasibility ceilings, mirroring ElectionConfig. Checked here so
// the admin is told before signing; the authoritative check is in the config itself, so
// bypassing this form changes nothing.
const MAX_NUM_CANDIDATES = 0xffff;
const MAX_BUDGET = 0xfffe;          // the proof encodes budget+1 as two bytes
const MAX_PROOF_BRANCHES = 2500;    // ~3 ms each to verify, on every keyper and auditor

/** Reject configs that would register cleanly but leave every ballot unusable. */
function checkBallotBounds(numCandidates: number, budget: number, mode: string): string | null {
  if (numCandidates > MAX_NUM_CANDIDATES) return `At most ${MAX_NUM_CANDIDATES} candidates.`;
  if (budget > MAX_BUDGET) return `Budget must be at most ${MAX_BUDGET}.`;
  // An atMost ballot also proves its sum with another (budget + 1)-branch OR proof.
  const atMost = mode === "atMost";
  const branches = (numCandidates + (atMost ? 1 : 0)) * (budget + 1);
  if (branches > MAX_PROOF_BRANCHES) {
    return `Too expensive to tally: ${numCandidates} candidates${atMost ? " (+1 for the atMost sum proof)" : ""} x (budget ${budget} + 1) = ` +
      `${branches} proof branches per ballot, over the ${MAX_PROOF_BRANCHES} limit. Every keyper ` +
      `and auditor verifies every ballot. Reduce the candidates or the budget.`;
  }
  return null;
}
// Fixed crypto-suite + wire-format label; not a per-election knob (see crypto/params.py).
const PROTOCOL_VERSION = "v1";
type Status = { kind: "ok" | "err" | "info"; msg: string } | null;

// Module-scope so its identity is stable across renders. (Defining it inside a
// component re-creates the type every keystroke → React remounts the input and the
// cursor/focus is lost after one character.)
type Hint = { title: string; body: string };

function F({ label, children, newRow, asDiv, hint }: { label: string; children: React.ReactNode; newRow?: boolean; asDiv?: boolean; hint?: Hint }) {
  // newRow pins the field to column 1 so it always starts a fresh row (stays below the
  // previous field) while keeping the normal half-row width.
  // asDiv renders a <div> instead of a <label> — a <label> forwards any click within it to
  // its first form control (e.g. the calendar icon), which we don't want for multi-control
  // fields like the date/time picker.
  const style = newRow ? { gridColumn: "1" as const } : undefined;
  const labelNode = hint ? <FieldHint title={hint.title} body={hint.body}>{label}</FieldHint> : label;
  const inner = <><span className="label-inline">{labelNode}</span>{children}</>;
  return asDiv
    ? <div className="field" style={style}>{inner}</div>
    : <label className="field" style={style}>{inner}</label>;
}

/** Per-field explanations shown on label hover (what the field + its options mean). */
const HINT: Record<string, Hint> = {
  candidates: { title: "Candidates", body: "Number of candidates for the election — a ballot has one encrypted vote value per candidate." },
  budget: { title: "Budget", body: "Points each voter distributes across the candidates. With a budget of 3 you might give 3 to one, or 1+1+1, or 2+1. A per-candidate ZK range proof enforces it." },
  mode: { title: "Mode", body: "How the per-voter points must add up. exact: the votes must sum to exactly the budget. atMost: they may sum to at most the budget (a voter can spend fewer, or none: a blank ballot still counts toward turnout). An atMost ballot is one candidate's worth larger, as it also proves its sum." },
  variant: { title: "Variant", body: "The per-candidate validity-proof construction. A: a (B+1)-branch OR proof per candidate (the standard). B: bit-decomposition proofs per candidate, smaller for large budgets; planned, not supported yet." },
  weighting: { title: "Weighting", body: "One per voter: every voter counts once. Weighted: the eligibility service assigns each voter a weight, and their whole ballot is multiplied by it in the tally." },
  scale: { title: "Scale", body: "The unit this tally counts in. 1 means whole tokens and is almost always right; a larger value divides every voter equally, and is only needed when a token supply would put the tally beyond what the coordinator can compute." },
  duplicate: { title: "Vote duplicate policy", body: "If one voter (pseudonym) submits more than one ballot, which counts at tally time. last-wins: the most recent. first-wins: the first." },
  votingStart: { title: "Voting start", body: "Ballots are only accepted from this moment. The DKG must finalize before it (see DKG lead time)." },
  votingEnd: { title: "Voting end", body: "When voting closes. After this the committee aggregates and decrypts." },
  dkgLeadTime: { title: "DKG lead time", body: "Seconds of headroom the keyper committee needs to run the distributed key generation before voting opens. Must be ≤ the time from now until voting start." },
  threshold: { title: "Threshold (t of n)", body: "n keypers form the committee; any t of them, acting together, can decrypt — fewer learn nothing. t IS the quorum: enter 2 and 3 for 2-of-3. It must be a MAJORITY (t > n/2), so 2-of-3 and 3-of-5 are allowed but 2-of-5 is not — the committee also uses this count to agree on the key and the tally, and a non-majority lets two different groups each claim the quorum. n must match the number of keyper URLs." },
  keyperUrls: { title: "Keyper URLs", body: "One HTTPS endpoint per committee member (n total), one per line. Each keyper's own address is read from its /status and pinned into the signed config." },
  eligibilityKey: { title: "Eligibility public key", body: "The 48-byte BLS12-381 G1 public key of the eligibility issuer — 0x followed by 96 hex characters. Every ballot carries an ATTESTATION_V1 credential signed by its private counterpart; admission verifies it." },
  resultPublisher: { title: "Result-publisher address", body: "The EOA account authorized to publish the final decrypted tally — 0x followed by 40 hex characters. Others cannot post a result." },
  gatewayKeys: { title: "On-chain ballot sponsor", body: "Blockchain elections only: the single account that submits ballots fee-free (it is granted VOTE_PROXY_ROLE on the contract) — 0x followed by 40 hex characters. Required for a blockchain-backed election; leave blank on the database backend." },
  selfSubmitFee: { title: "Self-submit fee (ETH)", body: "Blockchain elections only: the per-ballot fee a voter pays to submit their OWN ballot on-chain (not through the sponsor). 0 = free for everyone. Enter ETH, e.g. 0.0010." },
};

export function RegisterForm({ wallet, onViewElection }: { wallet: Wallet | null; onViewElection?: (id: number) => void }) {
  const [panel, setPanel] = useState<"register" | "cancel">("register");
  return (
    <div className="stack" style={{ maxWidth: 780, margin: "0 auto", width: "100%" }}>
      {!wallet && <div className="banner">Connect the admin wallet to sign register / cancel requests.</div>}
      <div className="subtabs">
        <button className={`navtab${panel === "register" ? " navtab--on" : ""}`} onClick={() => setPanel("register")}>Register Election</button>
        <button className={`navtab${panel === "cancel" ? " navtab--on" : ""}`} onClick={() => setPanel("cancel")}>Cancel Election</button>
      </div>
      {/* Both kept mounted (toggled via display) so in-progress form input survives a
          sub-tab switch. */}
      <div style={{ display: panel === "register" ? "block" : "none" }}><RegisterPanel wallet={wallet} onViewElection={onViewElection} /></div>
      <div style={{ display: panel === "cancel" ? "block" : "none" }}><CancelPanel wallet={wallet} /></div>
    </div>
  );
}

function RegisterPanel({ wallet, onViewElection }: { wallet: Wallet | null; onViewElection?: (id: number) => void }) {
  return (
    <section className="card reg-a">
      <div className="reg-a__head">
        <h3 className="reg-a__title">Register an election</h3>
      </div>
      <div className="reg-a__body">
        <FormRegister wallet={wallet} onViewElection={onViewElection} />
      </div>
    </section>
  );
}

async function doRegister(wallet: Wallet, config: Record<string, unknown>, dkgLeadTime: number) {
  // The admin is ALWAYS the connected wallet. The signature must recover to
  // config.adminKey, and the service only accepts its own admin EOA — so adminKey is never
  // a free-form field; we force it to the signing account here (also for pasted JSON).
  // dkgLeadTime is a separate (unsigned) gate param; selfSubmitFee is inside `config` (signed).
  if (!wallet.account) throw new Error("Connect a wallet first.");
  // The signed config asserts which election id it expects — the sequence head plus one.
  // The backend still assigns the id and refuses on disagreement, which makes this signed
  // body single-use: once it registers, the head moves on and a replay can never match.
  // (Ids are dense and append-only, so total + 1 is the next one.)
  const { total } = await api.listElections({ limit: 1 });
  const electionId = encodeElectionId(total + 1);
  const full = lowercaseHex({ ...config, electionId, adminKey: wallet.account });
  const signature = await wallet.signDigest(registerDigest(full));
  return registerElection(full, signature, dkgLeadTime);
}

/** `datetime-local` value in the browser's local timezone (`YYYY-MM-DDTHH:mm`). */
function toLocalInputValue(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Parse a `datetime-local` string to unix seconds (local timezone). */
function fromLocalInputValue(s: string): number {
  const ms = new Date(s).getTime();
  if (Number.isNaN(ms)) throw new Error(`Invalid date/time: ${s}`);
  return Math.floor(ms / 1000);
}

/** Validate the voting window + DKG lead time against "now". Returns a human-readable
 * reason, or null if valid (start > now, end > now, end > start, and the DKG has enough
 * lead time: dkgLeadTime <= votingStart - now). */
function scheduleError(startStr: string, endStr: string, dkgLeadTime: number): string | null {
  if (!startStr) return "Pick a voting start date & time.";
  if (!endStr) return "Pick a voting end date & time.";
  const now = Math.floor(Date.now() / 1000);
  const s = fromLocalInputValue(startStr);
  const e = fromLocalInputValue(endStr);
  if (s <= now) return "Voting start must be in the future.";
  if (e <= now) return "Voting end must be in the future.";
  if (e <= s) return "Voting end must be after voting start.";
  if (!Number.isFinite(dkgLeadTime) || dkgLeadTime < 0) return "DKG lead time must be a non-negative number of seconds.";
  if (dkgLeadTime > s - now) return `DKG lead time (${dkgLeadTime}s) exceeds the ${s - now}s until voting starts — pick a later start or a smaller lead time.`;
  return null;
}

function defaultSchedule() {
  const start = new Date(Date.now() + 5 * 60_000);
  const end = new Date(start.getTime() + 60 * 60_000);
  return { votingStart: toLocalInputValue(start), votingEnd: toLocalInputValue(end) };
}

function fmtDuration(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  if (sec < 60) return `${sec}s`;
  const m = Math.round(sec / 60);
  if (m < 120) return `${m}m`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem ? `${h}h ${rem}m` : `${h}h`;
}

/** Read-only date field whose calendar opens ONLY via the calendar icon (clicking the
 * text does nothing), used as react-datepicker's customInput. */
const CalInput = forwardRef<HTMLDivElement, { value?: string; placeholder?: string; onIconClick?: () => void }>(
  ({ value, placeholder, onIconClick }, ref) => (
    <div ref={ref} className="dt-dateinput">
      <span className={`dt-dateinput__text${value ? "" : " dt-dateinput__text--ph"}`}>{value || placeholder}</span>
      <button type="button" className="dt-cal-btn" onClick={onIconClick} aria-label="Open calendar">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="4" width="18" height="18" rx="2" /><line x1="16" y1="2" x2="16" y2="6" /><line x1="8" y1="2" x2="8" y2="6" /><line x1="3" y1="10" x2="21" y2="10" />
        </svg>
      </button>
    </div>
  ),
);
CalInput.displayName = "CalInput";

/** Date (themed calendar) + Hour : Minute + AM/PM controls. Any minute is selectable.
 * value/onChange use the local `YYYY-MM-DDTHH:mm` string (same as the rest of the form). */
function DateTimeField({ value, onChange, minDate }: { value: string; onChange: (v: string) => void; minDate?: Date }) {
  const [open, setOpen] = useState(false);
  const d = value ? new Date(value) : null;
  const h24 = d ? d.getHours() : 9;
  const h12 = h24 % 12 || 12;
  const minute = d ? d.getMinutes() : 0;
  const ampm: "AM" | "PM" = h24 >= 12 ? "PM" : "AM";

  const emit = (base: Date, hh12: number, mm: number, ap: "AM" | "PM") => {
    const hours24 = (hh12 % 12) + (ap === "PM" ? 12 : 0);
    const nd = new Date(base);
    nd.setHours(hours24, mm, 0, 0);
    onChange(toLocalInputValue(nd));
  };
  const base = d ?? new Date(); // touching the time before a date defaults to today

  return (
    <div style={{ display: "grid", gap: 6 }}>
      <DatePicker
        selected={d}
        open={open}
        onInputClick={() => {}}
        onClickOutside={() => setOpen(false)}
        onChange={(nd) => { if (nd) emit(nd, h12, minute, ampm); setOpen(false); }}
        dateFormat="MMM d, yyyy"
        minDate={minDate}
        popperPlacement="bottom-start"
        portalId="rdp-portal"
        customInput={<CalInput onIconClick={() => setOpen((o) => !o)} placeholder="Pick a date" />}
      />
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <select className="dt-part" value={h12} onChange={(e) => emit(base, Number(e.target.value), minute, ampm)}>
          {Array.from({ length: 12 }, (_, i) => i + 1).map((h) => (
            <option key={h} value={h}>{String(h).padStart(2, "0")}</option>
          ))}
        </select>
        <span className="dim">:</span>
        <select className="dt-part" value={minute} onChange={(e) => emit(base, h12, Number(e.target.value), ampm)}>
          {Array.from({ length: 60 }, (_, i) => i).map((m) => (
            <option key={m} value={m}>{String(m).padStart(2, "0")}</option>
          ))}
        </select>
        <div className="seg" style={{ width: "auto" }}>
          <button type="button" className={`seg__btn${ampm === "AM" ? " seg__btn--on" : ""}`} onClick={() => emit(base, h12, minute, "AM")}>AM</button>
          <button type="button" className={`seg__btn${ampm === "PM" ? " seg__btn--on" : ""}`} onClick={() => emit(base, h12, minute, "PM")}>PM</button>
        </div>
      </div>
    </div>
  );
}

export interface ResolvedKeyper {
  signingKey: string;
  url: string;
}

/** Browser-reachable probe URL for a keyper. On a single-host Docker *dev* run the config
 * URL is `host.docker.internal:810N` — what the coordinator container uses — but the
 * browser runs on the host, where that name doesn't resolve; the same keyper is published
 * at `localhost:810N`. We probe /status via localhost while storing the *original* URL in
 * the (signed) config so the coordinator still reaches it.
 *
 * Gated to dev builds: in production (`vite build`) this is compiled out entirely, so the
 * probe always hits the exact URL the admin entered. Real keyper URLs are public and
 * resolve identically from the browser and the coordinator — no rewrite needed. */
function browserProbeUrl(url: string): string {
  if (import.meta.env.DEV) return url.replace("host.docker.internal", "localhost");
  return url;
}

/** Turn a list of keyper URLs into signed-config committee entries by reading each
 * keyper's own address from its open `/status`. Rejects (before any signature) on:
 *  - duplicate URLs (operator typo), and
 *  - two distinct URLs that resolve to the *same* keyper address (one keyper listed
 *    twice) — which would corrupt the t-of-n quorum.
 * The admin service re-checks both authoritatively, but failing here gives the admin
 * an immediate, specific error. */
export async function resolveKeypers(rawUrls: string[]): Promise<ResolvedKeyper[]> {
  const urls = rawUrls.map((u) => u.trim().replace(/\/+$/, "")).filter(Boolean);
  if (urls.length === 0) throw new Error("Enter at least one keyper URL.");

  const seenUrl = new Set<string>();
  for (const u of urls) {
    if (seenUrl.has(u)) throw new Error(`Duplicate keyper URL: ${u}`);
    seenUrl.add(u);
  }

  const resolved = await Promise.all(
    urls.map(async (url): Promise<ResolvedKeyper> => {
      const probe = browserProbeUrl(url);
      let res: Response;
      try {
        res = await fetch(`${probe}/status`);
      } catch {
        throw new Error(`Cannot reach keyper at ${probe} (/status). Is it running and CORS-enabled?`);
      }
      if (!res.ok) throw new Error(`Keyper ${probe} /status returned HTTP ${res.status}.`);
      const body = (await res.json()) as { address?: string };
      const id = String(body.address ?? "").toLowerCase().replace(/^0x/, "");
      if (!/^[0-9a-f]{40}$/.test(id)) throw new Error(`Keyper ${url} /status did not return a valid address.`);
      return { signingKey: `0x${id}`, url };
    }),
  );

  const byAddr = new Map<string, string>();
  for (const k of resolved) {
    const prev = byAddr.get(k.signingKey);
    if (prev) throw new Error(`${prev} and ${k.url} are the same keyper (address ${k.signingKey}). Each committee member must be distinct.`);
    byAddr.set(k.signingKey, k.url);
  }
  return resolved;
}

/** Confirm the eligibility public key being registered matches the running issuer at
 * `ELIGIBILITY_URL` (its `/health` publishes its key). A mismatch means every ballot would
 * fail attestation verification at ingestion, so we block the registration with a clear
 * reason. If the issuer is unreachable we also block — the key can't be confirmed, and
 * registering blind is exactly what this guard exists to prevent. */
async function verifyEligibilityKey(enteredKey: string): Promise<void> {
  const entered = enteredKey.trim().toLowerCase();
  if (!entered) throw new Error("Enter the eligibility public key.");
  let issuerKey: string;
  try {
    issuerKey = (await fetchEligibilityKey()).eligibilityKey.toLowerCase();
  } catch {
    throw new Error(
      `Could not reach the eligibility service at ${ELIGIBILITY_URL} to verify the public key. ` +
      `Is it running and CORS-enabled?`,
    );
  }
  if (entered !== issuerKey) {
    throw new Error(
      "Eligibility public key does not match the issuer you have configured. " +
      "Ballots would fail verification, fix the key.",
    );
  }
}

const FORM_STEPS = [
  { id: "ballot", label: "Ballot" },
  { id: "schedule", label: "Schedule" },
  { id: "committee", label: "Committee" },
  { id: "roles", label: "Roles" },
] as const;

function Seg({
  value, options, onChange,
}: { value: string; options: { value: string; label: string; disabled?: boolean; title?: string }[]; onChange: (v: string) => void }) {
  return (
    <div className="seg" role="group">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          className={`seg__btn${value === o.value ? " seg__btn--on" : ""}`}
          onClick={() => onChange(o.value)}
          disabled={o.disabled}
          title={o.title}
          style={o.disabled ? { opacity: 0.45, cursor: "not-allowed" } : undefined}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

function initialForm() {
  return {
    numCandidates: 3, budget: 1, mode: "exact", variant: "A", weighted: false, scale: 1,
    duplicatePolicy: "last-wins", ...defaultSchedule(), dkgLeadTime: 180,
    t: 2, n: 3,  // 2-of-3: t IS the quorum
    keyperUrls: "", eligibilityKey: "", resultPublisherKey: "", gatewayKeys: "", selfSubmitFee: "0",
  };
}

function FormRegister({ wallet, onViewElection }: { wallet: Wallet | null; onViewElection?: (id: number) => void }) {
  const [f, setF] = useState(initialForm);
  const set = (k: string, v: unknown) => setF((s) => ({ ...s, [k]: v }));
  const setWeighted = (on: boolean) =>
    setF((s) => ({ ...s, weighted: on }));
  const [status, setStatus] = useState<Status>(null);
  const [step, setStep] = useState(0);
  // Decimal id of a just-registered election → drives the success dialog.
  const [registeredId, setRegisteredId] = useState<number | null>(null);

  // Which data store the api runs on, so we only show the chain-only options (vote-proxy,
  // self-submit fee). null = not yet known / unreachable → show them (they're required on
  // chain and harmless — ignored — on db).
  const [dataStore, setDataStore] = useState<"database" | "blockchain" | null>(null);
  useEffect(() => {
    let alive = true;
    api.getCapability().then((c) => { if (alive) setDataStore(c.dataStore); }).catch(() => { if (alive) setDataStore(null); });
    return () => { alive = false; };
  }, []);
  const showChainOnly = dataStore !== "database"; // true for blockchain or unknown

  let voteSecs = 0;
  try {
    voteSecs = fromLocalInputValue(f.votingEnd) - fromLocalInputValue(f.votingStart);
  } catch { /* incomplete while typing */ }
  const schedErr = scheduleError(f.votingStart, f.votingEnd, Number(f.dkgLeadTime));

  const submit = async () => {
    if (!wallet) return;
    if (schedErr) { setStatus({ kind: "err", msg: schedErr }); return; }
    setStatus({ kind: "info", msg: "Resolving keyper addresses from /status…" });
    try {
      const keypers = await resolveKeypers(f.keyperUrls.split("\n"));
      if (keypers.length !== Number(f.n)) {
        throw new Error(`Threshold n = ${f.n} but ${keypers.length} keyper URL(s) provided — they must match.`);
      }
      // t IS the quorum, so the legal range is 1 <= t <= n.
      const tq = Number(f.t);
      const nq = Number(f.n);
      if (!Number.isInteger(tq) || tq < 1 || tq > nq) {
        throw new Error(
          `Threshold t = ${f.t} is invalid: t is the quorum (how many keypers must combine ` +
          `to decrypt), so it must be a whole number with 1 <= t <= n (n = ${f.n}).`
        );
      }
      // The quorum must be a strict majority. 2-of-3 and 3-of-5 are majorities; 2-of-5 is
      // not, and two disjoint groups of 2 could each claim it. Mirrors both
      // `Threshold.__post_init__` and the KeyperSet constructor, so the admin is told
      // before signing instead of getting a 400 (db) or a revert (chain).
      if (tq * 2 <= nq) {
        throw new Error(
          `Threshold ${tq}-of-${nq} is not a majority. The quorum must satisfy t > n/2 — ` +
          `use t >= ${Math.floor(nq / 2) + 1}. (${tq}-of-${nq} would let two different ` +
          `groups of ${tq} each claim the quorum.)`
        );
      }
      // Shape-check the 0x-hex identities first. Doing this before the issuer round-trip
      // means a truncated or non-hex key reports exactly that, instead of surfacing as a
      // confusing "does not match the issuer" — and nothing is signed until all three are
      // well formed. Values are returned lowercased, which is the form the digest binds.
      const eligibilityKey = requireEligibilityKey(f.eligibilityKey);
      const resultPublisherKey = requireAddress(f.resultPublisherKey, "Result-publisher address");
      // Required on chain, optional on db — decided by the same `dataStore` capability that
      // decides whether the field is rendered at all (see `showChainOnly`).
      const sponsor = sponsorAddress(f.gatewayKeys, dataStore);

      setStatus({ kind: "info", msg: "Verifying eligibility public key with the issuer…" });
      await verifyEligibilityKey(eligibilityKey);
      const votingStart = fromLocalInputValue(f.votingStart);
      const votingEnd = fromLocalInputValue(f.votingEnd);
      setStatus({ kind: "info", msg: "Awaiting wallet signature…" });
      // One sponsor only (see the field hint): a single vote-proxy address, sent as a
      // 1-element list because config.gatewayKeys is a list. On-chain requires it; the db
      // backend ignores it. Blank → empty list (fine on db; the chain adapter returns a
      // clear error).
      const gatewayKeys = sponsor ? [sponsor] : [];
      // Self-submit fee → wei string, inside the SIGNED config. parseEther gives an exact wei
      // bigint from the ETH decimal (no float precision loss). Only meaningful on chain; on
      // db it rides along as "0" and is ignored. Sent as a decimal string (matches the
      // Python codec, which keeps it a string so the register digest byte-matches).
      let selfSubmitFee = "0";
      if (showChainOnly) {
        try {
          selfSubmitFee = parseEther((f.selfSubmitFee || "0").trim()).toString();
        } catch {
          throw new Error(`Invalid self-submit fee "${f.selfSubmitFee}" — enter ETH, e.g. 0.0010 (or 0).`);
        }
      }
      const boundsError = checkBallotBounds(Number(f.numCandidates), Number(f.budget), f.mode);
      if (boundsError) throw new Error(boundsError);
      const config = {
        electionId: ZERO_EID,
        numCandidates: Number(f.numCandidates), budget: Number(f.budget), mode: f.mode, variant: f.variant,
        weighted: f.weighted, scale: Number(f.scale), duplicatePolicy: f.duplicatePolicy,
        votingStart, votingEnd,
        threshold: { t: Number(f.t), n: Number(f.n) },
        keypers,
        eligibilityKey,
        resultPublisherKey,
        gatewayKeys,
        // adminKey is injected by doRegister (always the connected wallet).
        protocolVersion: PROTOCOL_VERSION,
        selfSubmitFee,
      };
      const { electionId } = await doRegister(wallet, config, Number(f.dkgLeadTime));
      setStatus(null);
      setRegisteredId(Number(BigInt(electionId))); // 0x-hex eid → decimal id (dashboard key)
    } catch (e: unknown) {
      setStatus({ kind: "err", msg: formatApiError(e) });
    }
  };

  // OK on the success dialog: start a fresh registration at step 1.
  const startAnother = () => {
    setRegisteredId(null);
    setStatus(null);
    setF(initialForm());
    setStep(0);
  };

  const ballot = (
    <div className="reg-sec" data-sec="ballot">
      <p className="reg-sec__title">Ballot rules</p>
      <div className="reg-sec__grid">
        <F label="Candidates" hint={HINT.candidates}><input type="number" value={f.numCandidates} onChange={(e) => set("numCandidates", e.target.value)} /></F>
        <F label="Budget" hint={HINT.budget}><input type="number" value={f.budget} onChange={(e) => set("budget", e.target.value)} /></F>
        <F label="Mode" hint={HINT.mode}><Seg value={f.mode} onChange={(v) => set("mode", v)} options={[{ value: "exact", label: "exact" }, { value: "atMost", label: "atMost" }]} /></F>
        <F label="Variant" hint={HINT.variant}><Seg value={f.variant} onChange={(v) => set("variant", v)} options={[{ value: "A", label: "A" }, { value: "B", label: "B (planned)", disabled: true, title: "Variant B is not supported yet" }]} /></F>
        <F label="Weighting" hint={HINT.weighting}><Seg value={f.weighted ? "yes" : "no"} onChange={(v) => setWeighted(v === "yes")} options={[{ value: "no", label: "One per voter" }, { value: "yes", label: "Weighted" }]} /></F>
        <F label="Scale" hint={HINT.scale}><input type="number" min={1} value={f.scale} onChange={(e) => set("scale", e.target.value)} /></F>
        <F label="Vote Duplicate Policy" hint={HINT.duplicate} newRow><Seg value={f.duplicatePolicy} onChange={(v) => set("duplicatePolicy", v)} options={[{ value: "last-wins", label: "last-wins" }, { value: "first-wins", label: "first-wins" }]} /></F>
      </div>
    </div>
  );

  const schedule = (
    <div className="reg-sec" data-sec="schedule">
      <p className="reg-sec__title">Schedule</p>
      <div className="reg-sec__grid">
        <F label="Voting start" hint={HINT.votingStart} asDiv>
          <DateTimeField value={f.votingStart} onChange={(v) => set("votingStart", v)} minDate={new Date()} />
        </F>
        <F label="Voting end" hint={HINT.votingEnd} asDiv>
          <DateTimeField value={f.votingEnd} onChange={(v) => set("votingEnd", v)}
            minDate={f.votingStart ? new Date(f.votingStart) : new Date()} />
        </F>
        <F label="DKG lead time (seconds)" hint={HINT.dkgLeadTime}>
          <input type="number" min={0} value={f.dkgLeadTime} onChange={(e) => set("dkgLeadTime", e.target.value)} />
        </F>
      </div>
      <p className="dim" style={{ margin: "6px 0 0" }}>Minimum time the keyper DKG needs before voting opens (must be ≤ time until voting starts).</p>
      {schedErr ? (
        <div className="notice notice--err" style={{ marginTop: 8 }}>{schedErr}</div>
      ) : voteSecs > 0 ? (
        <p className="dim" style={{ margin: "8px 0 0" }}>Voting window: {fmtDuration(voteSecs)}</p>
      ) : null}
    </div>
  );

  const committee = (
    <div className="reg-sec" data-sec="committee">
      <p className="reg-sec__title">Committee</p>
      <div className="reg-sec__grid">
        <F label="Threshold t of n" hint={HINT.threshold}>
          <span style={{ display: "flex", gap: 6 }}>
            <input type="number" value={f.t} onChange={(e) => set("t", e.target.value)} style={{ width: 70 }} />
            <input type="number" value={f.n} onChange={(e) => set("n", e.target.value)} style={{ width: 70 }} />
          </span>
        </F>
        <F label="Keyper URLs (one per line)" hint={HINT.keyperUrls}><textarea className="input-mono" value={f.keyperUrls} onChange={(e) => set("keyperUrls", e.target.value)} rows={3} placeholder={"https://keyper1.example.org\nhttps://keyper2.example.org\nhttps://keyper3.example.org"} /></F>
      </div>
    </div>
  );

  const roles = (
    <div className="reg-sec" data-sec="roles">
      <p className="reg-sec__title">Roles</p>
      <p className="dim" style={{ margin: "0 0 8px" }}>Public addresses / public keys (0x)</p>
      <div className="reg-sec__grid">
        <F label="Eligibility public key (BLS G1)" hint={HINT.eligibilityKey}><input className="input-mono" value={f.eligibilityKey} onChange={(e) => set("eligibilityKey", e.target.value)} placeholder="0x… 48-byte BLS12-381 G1 public key" /></F>
        <F label="Result-publisher address" hint={HINT.resultPublisher}><input className="input-mono" value={f.resultPublisherKey} onChange={(e) => set("resultPublisherKey", e.target.value)} placeholder="0x… public address" /></F>
      </div>

      {/* Submission / economics — blockchain-only settings. Shown only on the blockchain
          data store; entirely absent (no reference) on the database backend. */}
      {showChainOnly && (
        <div className="reg-subsec">
          <p className="reg-subsec__title">Submission / Economics</p>
          <div className="reg-sec__grid">
            <F label="On-chain ballot sponsor (vote-proxy)" hint={HINT.gatewayKeys}><input className="input-mono" value={f.gatewayKeys} onChange={(e) => set("gatewayKeys", e.target.value)} placeholder="0x… signer — required" /></F>
            <F label="Self-submit fee (ETH)" hint={HINT.selfSubmitFee}><input type="number" min={0} step="0.0001" value={f.selfSubmitFee} onChange={(e) => set("selfSubmitFee", e.target.value)} placeholder="0" /></F>
          </div>
        </div>
      )}
    </div>
  );

  const sections = [ballot, schedule, committee, roles];

  return (
    <div className="reg-steps">
      <div className="reg-steps__nav" role="tablist">
        {FORM_STEPS.map((s, i) => (
          <button
            key={s.id}
            type="button"
            role="tab"
            aria-selected={step === i}
            className={`reg-steps__tab${step === i ? " reg-steps__tab--on" : ""}${i < step ? " reg-steps__tab--done" : ""}`}
            onClick={() => setStep(i)}
          >
            <span className="reg-steps__idx">{i + 1}</span>
            {s.label}
          </button>
        ))}
      </div>
      <div className="reg-steps__panel">{sections[step]}</div>
      <div className="reg-steps__footer">
        <button type="button" className="btn btn--sm" disabled={step === 0} onClick={() => setStep((s) => s - 1)}>Back</button>
        {step < FORM_STEPS.length - 1 ? (
          <button type="button" className="btn btn--primary btn--sm"
            disabled={FORM_STEPS[step].id === "schedule" && !!schedErr}
            onClick={() => setStep((s) => s + 1)}>Continue</button>
        ) : (
          <span className="tip tip--end" data-tip={!wallet ? "Connect the admin wallet to register." : undefined}>
            <button className="btn btn--primary" onClick={submit} disabled={!wallet || !!schedErr}>Sign &amp; register</button>
          </span>
        )}
      </div>
      {/* On the last step the schedule notice isn't visible, so surface the reason here. */}
      {step === FORM_STEPS.length - 1 && schedErr && (
        <div className="notice notice--err" style={{ marginTop: 8 }}>{schedErr}</div>
      )}
      <StatusView status={status} />
      {registeredId != null && (
        <SuccessModal
          electionId={registeredId}
          onOk={startAnother}
          onView={() => onViewElection?.(registeredId)}
        />
      )}
    </div>
  );
}

/** Post-register confirmation: DKG is about to start; the admin either registers another
 * (back to step 1) or jumps to this election's dashboard. */
function SuccessModal({ electionId, onOk, onView }: { electionId: number; onOk: () => void; onView: () => void }) {
  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Election registered">
      <div className="modal-content" style={{ maxWidth: 440 }}>
        <div className="card">
          <h3 className="card-title" style={{ marginTop: 0 }}>Election registered</h3>
          <p style={{ margin: "0 0 4px" }}>Election #{electionId} was registered successfully.</p>
          <p className="dim" style={{ margin: "0 0 18px" }}>DKG will start soon.</p>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", flexWrap: "wrap" }}>
            <button type="button" className="btn btn--sm" onClick={onOk}>OK</button>
            <button type="button" className="btn btn--primary btn--sm" onClick={onView}>Go to election dashboard</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function CancelPanel({ wallet }: { wallet: Wallet | null }) {
  const [id, setId] = useState("");
  const [status, setStatus] = useState<Status>(null);
  const submit = async () => {
    if (!wallet) return;
    setStatus({ kind: "info", msg: "Awaiting wallet signature…" });
    try {
      const eidHex = eidToHex(Number(id));
      const signature = await wallet.signDigest(cancelDigest(eidHex));
      await cancelElection(eidToBareHex(Number(id)), signature);
      setStatus({ kind: "ok", msg: `Cancelled election #${id}` });
    } catch (e: unknown) {
      setStatus({ kind: "err", msg: formatApiError(e) });
    }
  };
  return (
    <section className="card">
      <div className="card-head"><h3 className="card-title">Cancel an election</h3></div>
      <p className="dim" style={{ margin: "0 0 10px" }}>Only valid before voting_start.</p>
      <label className="field"><span className="label-inline">Election id (decimal)</span>
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder="1" /></label>
      <span className="tip" data-tip={!wallet ? "Connect the admin wallet to cancel." : undefined} style={{ marginTop: 10 }}>
        <button className="btn btn--danger" onClick={submit} disabled={!wallet || !id.trim()}>Sign &amp; cancel</button>
      </span>
      <StatusView status={status} />
    </section>
  );
}

function StatusView({ status }: { status: Status }) {
  if (!status) return null;
  return <div className={`notice notice--${status.kind === "ok" ? "ok" : status.kind === "err" ? "err" : "info"}`} style={{ marginTop: 8 }}>{status.msg}</div>;
}
