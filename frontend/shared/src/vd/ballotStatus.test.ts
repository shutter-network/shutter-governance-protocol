import { describe, expect, it, vi } from "vitest";
import { ballotStatuses } from "./ballotStatus";
import type { Ballot, EncryptedTally } from "./eth/types";

const P = (n: number) => (`0x${n.toString(16).padStart(64, "0")}`) as `0x${string}`;
function ballot(pseudonym: number, nonce: number): Ballot {
  return {
    pseudonym: P(pseudonym), vk: "0x", ciphertexts: [], zkProof: "0x", voterSignature: "0x",
    attestation: { electionId: "1", pseudonym: P(pseudonym), vk: "0x", weight: "1", nonce: String(nonce), signature: "0x" },
    nonce, weight: 1,
  };
}
const malformed: Ballot = { ...ballot(0, 0), attestation: null, malformed: "bad bytes" };

describe("ballotStatuses (provisional, before the count)", () => {
  // Wallet 1 votes at nonce 1, then re-votes at nonce 2; wallet 2 votes once.
  const all = [ballot(1, 1), ballot(2, 1), ballot(1, 2), malformed];

  it("keeps the highest nonce under last-wins", () => {
    const s = ballotStatuses(all, "last-wins", null);
    expect([...s.superseded]).toEqual([0]);
    expect(s.counted).toBe(2);
    expect(s.final).toBe(false);
    expect(s.revoted.has(P(1))).toBe(true);
  });

  it("keeps the lowest nonce under first-wins (it used to assume last-wins)", () => {
    expect([...ballotStatuses(all, "first-wins", null).superseded]).toEqual([2]);
  });

  it("ranks by nonce, not position: a replayed older ballot stays superseded", () => {
    const replayed = [ballot(1, 2), ballot(1, 1)];
    expect([...ballotStatuses(replayed, "last-wins", null).superseded]).toEqual([1]);
  });

  it("compares nonces exactly above 2^53", () => {
    const big = (n: string): Ballot => ({ ...ballot(1, 0), attestation: { ...ballot(1, 0).attestation!, nonce: n } });
    const s = ballotStatuses([big("9007199254740993"), big("9007199254740992")], "last-wins", null);
    expect([...s.superseded]).toEqual([1]);
  });
});

describe("ballotStatuses (final, from the published aggregate)", () => {
  it("follows the tally, so a forged higher-nonce copy cannot supersede the real ballot", () => {
    // Index 0 is the voter's real ballot; index 1 a copy with their pseudonym, a higher
    // nonce and a broken proof. Provisionally the copy wins; the tally excludes it.
    const all = [ballot(1, 1), ballot(1, 5)];
    expect([...ballotStatuses(all, "last-wins", null).superseded]).toEqual([0]);

    const agg = {
      aggregates: [], totalAdmittedWeight: 1n, totalScaledWeight: 1n, admittedCount: 1, admitted: [0],
      exclusions: [{ sequenceNumber: 1, reason: "INVALID_PROOF" }],
    } as EncryptedTally;
    const s = ballotStatuses(all, "last-wins", agg);
    expect(s.final).toBe(true);
    expect(s.superseded.size).toBe(0);
    expect(s.excluded.get(1)).toBe("INVALID_PROOF");
    expect(s.counted).toBe(1);
  });

  it("reports re-votes the tally superseded", () => {
    const agg = {
      aggregates: [], totalAdmittedWeight: 1n, totalScaledWeight: 1n, admittedCount: 1, admitted: [1],
      exclusions: [{ sequenceNumber: 0, reason: "DUPLICATE_PSEUDONYM" }],
    } as EncryptedTally;
    const s = ballotStatuses([ballot(1, 1), ballot(1, 2)], "last-wins", agg);
    expect([...s.superseded]).toEqual([0]);
    expect(s.excluded.size).toBe(0);
  });
});

describe("fetchBallotsPage", () => {
  it("keeps asking until the page is full when the server returns short pages", async () => {
    vi.resetModules();
    const rows = Array.from({ length: 25 }, (_, i) => ({ ...ballot(i + 1, 1), attestation: { ...ballot(i + 1, 1).attestation } }));
    const listBallots = vi.fn(async (_id: number, offset: number, limit: number) => ({
      ballots: rows.slice(offset, offset + Math.min(limit, 3)), // a size-capped server: 3 at a time
      total: rows.length, limit, offset,
    }));
    vi.doMock("../api", () => ({ api: { listBallots } }));
    const { fetchBallotsPage } = await import("./eth/client");
    const page = await fetchBallotsPage(1, 10, 10);
    expect(page.ballots.map((b) => b.pseudonym)).toEqual(rows.slice(10, 20).map((r) => r.pseudonym));
    const tail = await fetchBallotsPage(1, 20, 10);   // only 5 left: stops at the end
    expect(tail.ballots).toHaveLength(5);
    vi.doUnmock("../api");
  });
});
