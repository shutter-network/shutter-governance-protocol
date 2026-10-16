/** Data client for the ported voting-dashboard — sources from shutter_governance_protocol's public read API
 * (`@shutter-governance-protocol/shared` `api`) instead of an Ethereum contract, and shapes the responses into the
 * voting-dashboard `types.ts` views. Keyed by shutter_governance_protocol's decimal electionId (number). */
import { api } from "../../api";
import type {
  Ballot,
  DecryptionShare,
  DkgResultView,
  ElectionConfigView,
  ElectionResult,
  EncryptedTally,
  Hex,
} from "./types";

const ZERO32 = ("0x" + "0".repeat(64)) as Hex;

export async function fetchElectionOverview(electionId: number): Promise<{
  config: ElectionConfigView;
  dkg: DkgResultView;
  phase: number;
  cancelled: boolean;
  isDKGFinalized: boolean;
  isResultFinalized: boolean;
  tallyStalled: boolean;
}> {
  const [rec, resultResp] = await Promise.all([api.getElection(electionId), api.getResult(electionId)]);
  const cfg = rec.config;
  const now = Math.floor(Date.now() / 1000);
  // shutter_governance_protocol has no on-chain phase enum; derive the three the dashboard cares about:
  // <3 pre-voting, 3 voting-open, >=4 post-voting.
  const phase = now >= cfg.votingEnd ? 4 : now >= cfg.votingStart ? 3 : 2;
  const config: ElectionConfigView = {
    electionId: BigInt(cfg.electionId),
    votingStart: BigInt(cfg.votingStart),
    votingEnd: BigInt(cfg.votingEnd),
    selfSubmitFee: 0n,
    numCandidates: cfg.numCandidates,
    budget: cfg.budget,
    mode: cfg.mode,
    variant: cfg.variant,
    scale: cfg.scale ?? 1,
    duplicatePolicy: cfg.duplicatePolicy ?? "last-wins",
    thresholdN: BigInt(cfg.threshold.n),
    thresholdT: BigInt(cfg.threshold.t),
    keyperAddresses: cfg.keypers.map((k) => k.signingKey),
    pkWR: cfg.eligibilityKey as Hex,
  };
  const dkg: DkgResultView = rec.finalizedKey
    ? { pkElection: rec.finalizedKey.pkElection as Hex, committeePKs: rec.finalizedKey.committeePKs as Hex[] }
    : { pkElection: ZERO32, committeePKs: [] };
  return {
    config,
    dkg,
    phase,
    cancelled: rec.cancelled,
    isDKGFinalized: rec.finalizedKey != null,
    isResultFinalized: resultResp.result != null,
    tallyStalled: rec.tallyStalled ?? false,
  };
}

/** A credential integer as a decimal string. The API sends these as JSON numbers, which
 *  the browser parses as floats: above 2^53 the value is already rounded, and `String`
 *  would render it in exponent form that `BigInt` rejects. `BigInt(n)` keeps the
 *  (rounded) integer, so such a credential fails its signature check instead of crashing
 *  the verifier. Exact values need the API to send these as decimal strings. */
const decimal = (v: unknown): string =>
  typeof v === "number" && Number.isFinite(v) ? BigInt(Math.trunc(v)).toString() : String(v);

export async function fetchBallotsPage(
  electionId: number,
  startIndex: number,
  count: number,
): Promise<{ total: bigint; ballots: Ballot[] }> {
  // The server may return fewer rows than asked for (pages are capped by size as well
  // as count, so large ballots come back a few at a time). Keep asking until the page is
  // full or the list ends, so a page never silently skips the indices it was short by.
  const raw: any[] = [];
  let total = 0n;
  do {
    const resp = await api.listBallots(electionId, Math.max(0, startIndex) + raw.length, count - raw.length);
    total = BigInt(resp.total);
    if (resp.ballots.length === 0) break;
    raw.push(...resp.ballots);
  } while (raw.length < count && BigInt(Math.max(0, startIndex) + raw.length) < total);
  const ballots: Ballot[] = raw.map((b) => b.malformed !== undefined ? ({
    // Kept in place so page positions line up with the API's ballot indices.
    pseudonym: "0x" as Hex, vk: "0x" as Hex, ciphertexts: [], zkProof: "0x" as Hex,
    voterSignature: "0x" as Hex, attestation: null, nonce: 0, weight: 0,
    malformed: String(b.malformed ?? "undecodable record"),
  }) : ({
    pseudonym: b.pseudonym as Hex,
    vk: b.vk as Hex,
    ciphertexts: (b.ciphertexts ?? []).map((ct: any) => ({ c1: ct.c1 as Hex, c2: ct.c2 as Hex })),
    zkProof: b.zkProof as Hex,
    voterSignature: b.voterSignature as Hex,
    attestation: b.attestation ? {
      electionId: String(b.attestation.electionId),
      pseudonym: b.attestation.pseudonym as Hex,
      vk: b.attestation.vk as Hex,
      weight: decimal(b.attestation.weight),
      nonce: decimal(b.attestation.nonce ?? 1),
      signature: b.attestation.signature as Hex,
    } : null,
    nonce: Number(b.attestation?.nonce ?? 1),
    weight: Number(b.attestation?.weight ?? 1),
  }));
  return { total, ballots };
}

export async function fetchAggregate(electionId: number): Promise<EncryptedTally | null> {
  const { aggregate } = await api.getAggregate(electionId);
  if (!aggregate) return null;
  return {
    aggregates: aggregate.aggregates.map((ct: any) => ({ c1: ct.c1 as Hex, c2: ct.c2 as Hex })),
    totalAdmittedWeight: BigInt(aggregate.totalAdmittedWeight ?? 0),
    // Mirrors shutter_governance_protocol's decoder, which defaults the scaled total to the raw one when the
    // field is absent: they are equal by construction at scale 1, so an artifact
    // written before scaling existed decodes correctly. Defaulting to 0 would make
    // an unscaled election look like it counted nothing.
    totalScaledWeight: BigInt(
      aggregate.totalScaledWeight ?? aggregate.totalAdmittedWeight ?? 0,
    ),
    admittedCount: (aggregate.admitted ?? []).length,
    admitted: (aggregate.admitted ?? []).map(Number),
    exclusions: (aggregate.exclusions ?? []).map((e: any) => ({
      sequenceNumber: Number(e.sequenceNumber), reason: String(e.reason),
    })),
  };
}

export async function fetchDecryptionShares(electionId: number): Promise<DecryptionShare[]> {
  const { shares } = await api.getShares(electionId);
  return shares.map((s) => ({
    keyperIndex: s.keyperIndex,
    submittedAt: 0n,
    shares: s.entries.map((e) => e.sigma as Hex),
    // shutter_governance_protocol packs each DLEQ proof as a 64-byte big-endian blob `e(32) ‖ z(32)`
    // (crypto/params.py DLEQ_BYTES, proofs.encode_dleq); decode it back to {e, z}
    // so the shares/result verification fixtures carry the real challenge + response.
    proofs: s.entries.map((e) => decodeDleq(e.proof as Hex)),
    rawProofs: s.entries.map((e) => e.proof as Hex),
  }));
}

/** Split shutter_governance_protocol's 64-byte DLEQ blob (0x-hex, big-endian `e(32)‖z(32)`) into scalars. */
function decodeDleq(proof: Hex): { e: bigint; z: bigint } {
  const hex = proof.replace(/^0x/, "").padStart(128, "0");
  return { e: BigInt("0x" + hex.slice(0, 64)), z: BigInt("0x" + hex.slice(64, 128)) };
}

export async function fetchResult(electionId: number): Promise<ElectionResult | null> {
  const { result } = await api.getResult(electionId);
  if (!result) return null;
  return { tally: result.totals.map((n) => BigInt(n)), keyperIndices: result.keyperIndices, bsgsBound: BigInt(result.bsgsBound) };
}
