import { beforeAll, describe, expect, it } from "vitest";
import * as S from "@shutter-network/urban-verified-crypto";
import { verifyAggregateLocal, verifyBallotLocal, type VBallot } from "./index";

const hex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");
const eid32 = (id: bigint) => Uint8Array.from(Buffer.from(id.toString(16).padStart(64, "0"), "hex"));
const ELECTION = 7n;
const params = { numCandidates: 3, budget: 3, mode: "exact" as const, variant: "A" as const };

let mpkHex: string;
let eligSk: bigint;
let eligVk: any;
let cfg: { electionId: bigint; numCandidates: number; budget: number; mode: "exact"; variant: "A"; pkWR: string; scale?: number };

beforeAll(async () => {
  await S.initCurves();
  mpkHex = hex(S.G2Point.generator().mul(123456789n).toBytes());
  ({ sk: eligSk, vk: eligVk } = S.schnorrKeygen());
  cfg = { electionId: ELECTION, ...params, pkWR: hex(eligVk.toBytes()) };
});

function makeBallot(votes: bigint[], weight: bigint, nonce = 1n): VBallot {
  const pseudonym = crypto.getRandomValues(new Uint8Array(32));
  const { sk, vk } = S.schnorrKeygen();
  const unsigned = { electionId: eid32(ELECTION), pseudonym, vk: vk.toBytes(), weight, nonce };
  const attestation = { ...unsigned, signature: S.signAttestation(eligSk, eligVk, unsigned) };
  const b = S.buildBallot({
    mpk: S.G2Point.fromBytes(Buffer.from(mpkHex.slice(2), "hex")),
    electionId: eid32(ELECTION), pseudonym, sk, vk, votes, params, attestation,
  });
  return {
    pseudonym: hex(b.pseudonym), vk: hex(b.vk),
    ciphertexts: b.ciphertexts.map(([c1, c2]) => ({ c1: hex(c1), c2: hex(c2) })),
    zkProof: hex(b.zkProof), voterSignature: hex(b.voterSignature),
    attestation: {
      electionId: ELECTION.toString(), pseudonym: hex(pseudonym), vk: hex(vk.toBytes()),
      weight: weight.toString(), nonce: nonce.toString(), signature: hex(attestation.signature),
    },
  };
}

describe("ballot verification (SDK 0.3)", () => {
  it("accepts an honest ballot", async () => {
    expect(await verifyBallotLocal(makeBallot([1n, 0n, 2n], 5n), cfg, mpkHex)).toEqual({ ok: true });
  });

  it("accepts an honest ballot with a wei-scale weight (above 2^53)", async () => {
    expect(await verifyBallotLocal(makeBallot([1n, 0n, 2n], 1234567890123456789n), cfg, mpkHex)).toEqual({ ok: true });
  });

  it("rejects a ballot whose credential weight was edited", async () => {
    const b = makeBallot([3n, 0n, 0n], 1n);
    const res = await verifyBallotLocal({ ...b, attestation: { ...b.attestation!, weight: "9" } }, cfg, mpkHex);
    expect(res.ok).toBe(false);
  });

  it("rejects a credential issued for another ballot", async () => {
    const b = makeBallot([3n, 0n, 0n], 1n);
    const other = makeBallot([0n, 3n, 0n], 1n);
    const res = await verifyBallotLocal({ ...b, attestation: other.attestation }, cfg, mpkHex);
    expect(res.ok).toBe(false);
  });

  it("reports a malformed record without calling the SDK", async () => {
    const malformed: VBallot = { pseudonym: "0x", vk: "0x", ciphertexts: [], zkProof: "0x", voterSignature: "0x",
                                  attestation: null, malformed: "JSONDecodeError: bad" };
    expect(await verifyBallotLocal(malformed, cfg, mpkHex)).toEqual({ ok: false, reason: "malformed record: JSONDecodeError: bad" });
  });
});

describe("aggregate verification", () => {
  /** What the Python aggregator publishes: Σ scaled(weight)·ct over the admitted ballots. */
  function aggregateOf(ballots: VBallot[], admitted: number[], scale: bigint) {
    const g2 = (h: string) => S.G2Point.fromBytes(Buffer.from(h.slice(2), "hex"));
    return [0, 1, 2].map((j) => {
      const terms = admitted
        .map((i) => ({ w: (BigInt(ballots[i].attestation!.weight) + scale / 2n) / scale, b: ballots[i] }))
        .filter((x) => x.w > 0n)
        .map((x) => S.scalarMulCt(x.w, { c1: g2(x.b.ciphertexts[j].c1), c2: g2(x.b.ciphertexts[j].c2) }));
      const s = S.sumCts(terms);
      return { c1: hex(s.c1.toBytes()), c2: hex(s.c2.toBytes()) };
    });
  }

  it("matches the published aggregate over the admitted ballots only, with scaling", async () => {
    // Ballot 1 is a superseded re-vote: valid, but not admitted. Summing every valid
    // ballot, as the old check did, would report a mismatch here.
    const ballots = [makeBallot([3n, 0n, 0n], 3n), makeBallot([0n, 3n, 0n], 4n), makeBallot([0n, 0n, 3n], 5n)];
    const admitted = [0, 2];
    const scaled = { ...cfg, scale: 2 };
    const agg = aggregateOf(ballots, admitted, 2n);
    expect(await verifyAggregateLocal(scaled, mpkHex, agg, ballots, admitted)).toEqual({ ok: true });
    expect((await verifyAggregateLocal(scaled, mpkHex, agg, ballots, [0, 1, 2])).ok).toBe(false);
  });
});
