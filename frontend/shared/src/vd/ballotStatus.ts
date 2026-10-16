import type { Ballot, EncryptedTally } from "./eth/types";

/** Which ballots count, for the ballot list and the counts above it.
 *
 * `final` once the aggregate is published: the statuses are then the tally's own
 * (`admitted`, and `exclusions` with their reasons), not an estimate.
 *
 * Before that they are `provisional`: the dashboard ranks each wallet's ballots by the
 * election's duplicate policy, as admission does, but it cannot check proofs and
 * signatures for every ballot. A copy of a voter's ballot with a broken proof and a
 * higher nonce therefore still looks like a re-vote until the count excludes it. */
export interface BallotStatuses {
  final: boolean;
  /** Absolute indexes of ballots replaced by another ballot from the same wallet. */
  superseded: Set<number>;
  /** Absolute index → reason, for ballots the tally excluded for anything but a re-vote.
   *  Empty while provisional. */
  excluded: Map<number, string>;
  /** Pseudonyms that cast more than one readable ballot. */
  revoted: Set<string>;
  /** Ballots that count (or will, if valid). */
  counted: number;
}

export const EMPTY_STATUSES: BallotStatuses = {
  final: false, superseded: new Set(), excluded: new Map(), revoted: new Set(), counted: 0,
};

/** `all` is the full ballot list in stored order (index = sequence number). */
export function ballotStatuses(
  all: Ballot[],
  policy: "first-wins" | "last-wins",
  aggregate: EncryptedTally | null,
): BallotStatuses {
  const seen = new Map<string, number>();
  all.forEach((b) => {
    if (b.malformed === undefined) seen.set(b.pseudonym, (seen.get(b.pseudonym) ?? 0) + 1);
  });
  const revoted = new Set<string>();
  seen.forEach((n, p) => { if (n > 1) revoted.add(p); });

  if (aggregate) {
    const superseded = new Set<number>();
    const excluded = new Map<number, string>();
    for (const e of aggregate.exclusions) {
      if (e.reason === "DUPLICATE_PSEUDONYM") superseded.add(e.sequenceNumber);
      else excluded.set(e.sequenceNumber, e.reason);
    }
    return { final: true, superseded, excluded, revoted, counted: aggregate.admittedCount };
  }

  // Same ranking as admission's `_duplicate_losers`: (nonce, index), highest wins under
  // last-wins and lowest under first-wins. Nonces are compared exactly, as BigInt.
  const nonceOf = (b: Ballot) => BigInt(b.attestation?.nonce ?? b.nonce);
  const beats = (a: [bigint, number], b: [bigint, number]) => {
    const later = a[0] !== b[0] ? a[0] > b[0] : a[1] > b[1];
    return policy === "last-wins" ? later : !later;
  };
  const winner = new Map<string, number>();
  all.forEach((b, i) => {
    if (b.malformed !== undefined) return; // never counted, and has no real pseudonym
    const cur = winner.get(b.pseudonym);
    if (cur === undefined || beats([nonceOf(b), i], [nonceOf(all[cur]), cur])) winner.set(b.pseudonym, i);
  });
  const superseded = new Set<number>();
  all.forEach((b, i) => {
    if (b.malformed === undefined && winner.get(b.pseudonym) !== i) superseded.add(i);
  });
  return { final: false, superseded, excluded: new Map(), revoted, counted: winner.size };
}
