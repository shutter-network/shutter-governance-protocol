/** Derived election lifecycle — a faithful TS mirror of `shutter_governance_protocol.core.state.derive_state`.
 *
 * The public API exposes no derived state, so the dashboard computes it from the
 * config timings + the facts it can read (cancelled, finalized key, result). The
 * voting window is half-open `[votingStart, votingEnd)`. */

export type ElectionState =
  | "Cancelled"
  | "Complete"
  | "DKGFailed"
  | "Registered"
  | "KeyReady"
  | "Voting"
  | "Tallying"
  | "TallyStalled";

export interface StateTimings {
  votingStart: number;
  votingEnd: number;
}

export interface StateFacts {
  cancelled: boolean;
  keyFinalized: boolean;
  resultPublished: boolean;
  /** Advisory, recoverable: the coordinator abandoned the tally. Overlays `Tallying`;
   * a published result still wins (→ `Complete`). Defaults to false when absent. */
  tallyStalled?: boolean;
}

/** Same normative ordering as `derive_state`: terminal outcomes before live states. */
export function deriveState(c: StateTimings, f: StateFacts, now: number): ElectionState {
  if (f.cancelled) return "Cancelled";
  if (f.resultPublished) return "Complete";
  if (now >= c.votingStart && !f.keyFinalized) return "DKGFailed";
  if (!f.keyFinalized) return "Registered"; // now < votingStart guaranteed here
  if (now < c.votingStart) return "KeyReady";
  if (now < c.votingEnd) return "Voting";
  if (f.tallyStalled) return "TallyStalled"; // advisory overlay on Tallying (result would be Complete above)
  return "Tallying";
}

export function isVotingOpen(c: StateTimings, now: number): boolean {
  return c.votingStart <= now && now < c.votingEnd;
}
