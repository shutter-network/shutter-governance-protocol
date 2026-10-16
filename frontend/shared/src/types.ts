/** TypeScript shapes mirroring the shutter_governance_protocol wire envelopes (`shutter_governance_protocol.envelopes.codecs`).
 *
 * The **public read API** decimalizes every `electionId` (so those are `number`);
 * cryptographic byte-strings stay `0x`-hex. Ballots/attestations *sent* to the
 * gateway/eligibility use `0x`-hex `electionId` (the internal wire form). */

import type { Hex } from "./hex";

export type Mode = "exact" | "atMost";
export type Variant = "A" | "B";
export type DuplicatePolicy = "first-wins" | "last-wins";

export interface Threshold {
  t: number;
  n: number;
}
export interface Keyper {
  signingKey: Hex; // 20-byte address (chain) / opaque identity
  url: string;
}

export interface ElectionConfig {
  electionId: number;
  numCandidates: number;
  budget: number;
  mode: Mode;
  variant: Variant;
  weighted: boolean;
  scale: number;
  duplicatePolicy: DuplicatePolicy;
  votingStart: number;
  votingEnd: number;
  threshold: Threshold;
  keypers: Keyper[];
  eligibilityKey: Hex;
  resultPublisherKey: Hex;
  gatewayKeys: Hex[];
  adminKey: Hex;
  protocolVersion: string;
}

export interface FinalizedKey {
  pkElection: Hex;
  committeePKs: Hex[];
}

export interface ElectionRecord {
  electionId: number;
  config: ElectionConfig;
  cancelled: boolean;
  /** Advisory, recoverable: the coordinator abandoned the tally (overlays `Tallying`). */
  tallyStalled?: boolean;
  finalizedKey: FinalizedKey | null;
}

export interface DkgSubmission {
  electionId: number;
  pkElection: Hex;
  committeePKs: Hex[];
  keyperSignature: Hex;
}

export interface CiphertextJson {
  c1: Hex;
  c2: Hex;
}

export interface AttestationJson {
  scheme: string;
  electionId: Hex;
  pseudonym: Hex;
  vk: Hex;
  /** Decimal string: weights are often token balances in wei, far above 2^53, which a
   *  JSON number cannot carry exactly. Parse with `BigInt`. (Older servers sent a
   *  number; `BigInt` accepts both, but only the string is exact.) */
  weight: string | number;
  /** Monotonic per (election, pseudonym): the re-vote arbiter. The issuer always
   * emits it; it was missing from this type while nothing here read it, and the
   * binding message does. Decimal string, like `weight`. */
  nonce?: string | number;
  signature: Hex;
}

/** The ballot envelope POSTed to the gateway (electionId is 0x-hex here). */
export interface BallotJson {
  electionId: Hex;
  pseudonym: Hex;
  vk: Hex;
  ciphertexts: CiphertextJson[];
  zkProof: Hex;
  voterSignature: Hex;
  attestation: AttestationJson;
  /** Schnorr under the same voter key as `voterSignature`, over the ballot digest
   * *and* the credential together — see `binding.ts`. Required: an optional
   * binding is no binding, since an assembler would simply omit it. */
}

export interface ExclusionJson {
  sequenceNumber: number;
  reason: string;
}
export interface AggregateJson {
  electionId: number;
  aggregates: CiphertextJson[];
  admitted: number[];
  exclusions: ExclusionJson[];
  /** Sum of the admitted ballots' weights as held. Decimal string (see `AttestationJson.weight`). */
  totalAdmittedWeight: string | number;
  /**
   * The same sum after each weight was divided by the election's scale — what the
   * tally actually counted, and what the published totals reconcile against
   * (`totals` sum to `budget x totalScaledWeight` in exact mode).
   *
   * Optional because an aggregate written before scaling existed does not carry it;
   * such an election was necessarily unscaled, so callers should fall back to
   * `totalAdmittedWeight` rather than to 0.
   */
  totalScaledWeight?: string | number;
}

export interface DecryptionShareJson {
  electionId: number;
  keyperIndex: number;
  entries: { sigma: Hex; proof: Hex }[];
}

export interface ResultJson {
  electionId: number;
  /** Decimal strings: totals are votes × weights, so they grow with the weights. */
  totals: (string | number)[];
  keyperIndices: number[];
  bsgsBound: string | number;
}
