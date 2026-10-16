import { describe, expect, it } from "vitest";
import { countedWeight } from "./BallotDetail";

describe("countedWeight", () => {
  it("is the held weight divided by the scale, rounded half-up as the tally does", () => {
    // A wei-scale credential: the page showed 2.5e21 as the counted weight.
    expect(countedWeight(2_500_000_000_000_000_000_000n, 10n ** 15n)).toBe(2_500_000n);
    expect(countedWeight(79n, 1n)).toBe(79n);
    expect(countedWeight(15n, 10n)).toBe(2n); // half-up, not half-to-even
    expect(countedWeight(25n, 10n)).toBe(3n);
    expect(countedWeight(4n, 10n)).toBe(0n);
  });
});
