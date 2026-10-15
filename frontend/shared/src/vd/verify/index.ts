/* On-demand, in-browser cryptographic verification of the four public artifacts —
 * ballot, aggregate, decryption shares, result — using the same SDK the voter's ballot
 * builder uses (`@shutter-network/urban-verified-crypto`). The SDK (+ blst.wasm) is
 * loaded lazily on first use so it stays out of the main bundle.
 *
 * shutter-governance-protocol specifics:
 *   - The ballot carries its eligibility credential (ATTESTATION_V1) as a structured
 *     object; the SDK verifies it against the issuer's public key and checks that it
 *     belongs to this ballot (election, pseudonym, vk). The voter's signature covers it.
 *   - The aggregate is the weighted sum `Σ scaled(weightᵢ)·ctᵢ` over the ballots the
 *     aggregate itself lists as admitted.
 *   - Result BSGS bound is the published `bsgsBound` (= budget · Σ admitted weights). */
import { Buffer } from "buffer";

export type VerifyResult = { ok: true } | { ok: false; reason: string };

// ── lazy SDK + curve init ────────────────────────────────────────────────
let _sdk: any = null;
async function sdk(): Promise<any> {
  if (!_sdk) {
    _sdk = await import("@shutter-network/urban-verified-crypto");
    await _sdk.initCurves();
  }
  return _sdk;
}

// ── byte helpers ─────────────────────────────────────────────────────────
const fromHex = (h: string) => Uint8Array.from(Buffer.from(String(h).replace(/^0x/, ""), "hex"));
const electionId32 = (id: bigint | number | string) => fromHex(BigInt(id).toString(16).padStart(64, "0"));

// ── shared input shapes (subset of the dashboard's view types) ───────────
type Ct = { c1: string; c2: string };
export type VAttestation = { electionId: string; pseudonym: string; vk: string; weight: string; nonce: string; signature: string };
export type VBallot = {
  pseudonym: string; vk: string; ciphertexts: Ct[]; zkProof: string; voterSignature: string;
  attestation: VAttestation | null;
  malformed?: string;
};
type VConfig = { electionId: bigint; numCandidates: number; budget: number; mode: "exact" | "atMost"; variant: "A" | "B"; pkWR: string; scale?: number };
type VShare = { keyperIndex: number; shares: string[]; proofs: { e: bigint; z: bigint }[] };

/** The SDK's `verifyBallot` inputs. The credential's fields are passed as the credential
 *  holds them, never copied from the ballot, so the SDK's "does it belong to this
 *  ballot" checks are real. */
function ballotInputs(b: VBallot, cfg: VConfig) {
  const a = b.attestation!;
  return {
    electionId: electionId32(cfg.electionId), pseudonym: fromHex(b.pseudonym), vk: fromHex(b.vk),
    ciphertexts: b.ciphertexts.map((c) => [fromHex(c.c1), fromHex(c.c2)]),
    zkProof: fromHex(b.zkProof), voterSignature: fromHex(b.voterSignature),
    attestation: {
      electionId: electionId32(a.electionId), pseudonym: fromHex(a.pseudonym), vk: fromHex(a.vk),
      weight: BigInt(a.weight), nonce: BigInt(a.nonce), signature: fromHex(a.signature),
    },
  };
}

function checkBallot(S: any, b: VBallot, cfg: VConfig, mpk: any): VerifyResult {
  if (b.malformed !== undefined || !b.attestation) {
    return { ok: false, reason: `malformed record: ${b.malformed ?? "no credential"}` };
  }
  try {
    const res = S.verifyBallot(
      ballotInputs(b, cfg),
      { numCandidates: cfg.numCandidates, budget: cfg.budget, mode: cfg.mode, variant: cfg.variant },
      mpk,
      fromHex(cfg.pkWR),
    );
    return res.ok ? { ok: true } : { ok: false, reason: res.reason ?? "invalid" };
  } catch (e: any) {
    return { ok: false, reason: e?.message ?? String(e) };
  }
}

// ── 1. ballot ─────────────────────────────────────────────────────────────
export async function verifyBallotLocal(ballot: VBallot, cfg: VConfig, mpkHex: string): Promise<VerifyResult> {
  const S = await sdk();
  return checkBallot(S, ballot, cfg, S.G2Point.fromBytes(fromHex(mpkHex)));
}

/** One attested weight in the units the tally counts: integer half-up `(w + s/2) / s`,
 *  exactly as the Python aggregator rounds. */
const scaledWeight = (w: bigint, scale: bigint) => (w + scale / 2n) / scale;

// ── 2. aggregate (weighted homomorphic sum over the admitted ballots) ───────
/** `ballots` is the full stored list in order, so `ballots[seq]` is sequence `seq`; `admitted`
 *  is the aggregate's own list of counted sequence numbers. Every admitted ballot must
 *  verify, and their weighted sum must equal the published aggregate. */
export async function verifyAggregateLocal(cfg: VConfig, mpkHex: string, aggregate: Ct[], ballots: VBallot[], admitted: number[]): Promise<VerifyResult> {
  const S = await sdk();
  const g2 = (h: string) => S.G2Point.fromBytes(fromHex(h));
  const mpk = g2(mpkHex);
  const scale = BigInt(cfg.scale ?? 1);
  const counted: VBallot[] = [];
  for (const seq of admitted) {
    const b = ballots[seq];
    if (!b) return { ok: false, reason: `admitted ballot ${seq} is missing from the ballot list` };
    const v = checkBallot(S, b, cfg, mpk);
    if (!v.ok) return { ok: false, reason: `admitted ballot ${seq} is invalid: ${v.reason}` };
    counted.push(b);
  }
  for (let j = 0; j < cfg.numCandidates; j++) {
    const terms = counted
      .map((b) => ({ w: scaledWeight(BigInt(b.attestation!.weight), scale), b }))
      .filter((x) => x.w > 0n)
      .map((x) => S.scalarMulCt(x.w, { c1: g2(x.b.ciphertexts[j].c1), c2: g2(x.b.ciphertexts[j].c2) }));
    const sum = S.sumCts(terms);
    const pub = { c1: g2(aggregate[j].c1), c2: g2(aggregate[j].c2) };
    if (!(sum.c1.equals(pub.c1) && sum.c2.equals(pub.c2))) return { ok: false, reason: `candidate ${j}: sum ≠ published aggregate` };
  }
  return { ok: true };
}

// ── 3. decryption shares (DLEQ) ─────────────────────────────────────────────
function decryptTranscript(S: any, eid: Uint8Array, j: number) {
  const t = new S.Transcript("SHUTTER-VOTE-DECRYPT-v1");
  t.append("electionId", eid);
  t.append("candidate", new Uint8Array([(j >> 8) & 255, j & 255]));
  return t;
}
export type ShareVerdict = { keyperIndex: number; candidate: number; ok: boolean };
export async function verifySharesLocal(electionId: bigint, numCandidates: number, aggregate: Ct[], committeePks: string[], shares: VShare[]): Promise<{ ok: boolean; verdicts: ShareVerdict[] }> {
  const S = await sdk();
  const eid = electionId32(electionId);
  const g2 = (h: string) => S.G2Point.fromBytes(fromHex(h));
  const verdicts: ShareVerdict[] = [];
  let ok = true;
  for (const s of shares) {
    const member = s.keyperIndex - 1; // shutter_governance_protocol keyperIndex is 1-based; committee is 0-based
    const pk = g2(committeePks[member]);
    for (let j = 0; j < numCandidates; j++) {
      const ct = { c1: g2(aggregate[j].c1), c2: g2(aggregate[j].c2) };
      const share = { keyperIndex: s.keyperIndex, sigma: g2(s.shares[j]), proof: { e: BigInt(s.proofs[j].e), z: BigInt(s.proofs[j].z) } };
      const valid = S.verifyDecryptionShare(ct, share, pk, decryptTranscript(S, eid, j));
      if (!valid) ok = false;
      verdicts.push({ keyperIndex: s.keyperIndex, candidate: j, ok: valid });
    }
  }
  return { ok, verdicts };
}
