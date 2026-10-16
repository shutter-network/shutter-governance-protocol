import { beforeAll, describe, expect, it } from "vitest";
import * as S from "@shutter-network/urban-verified-crypto";
import { toSdkAttestation } from "./ballot";

/** A real `/attest` response from the Python issuer (generated with its codecs) for a
 *  wei-scale weight. JSON numbers above 2^53 are rounded by `JSON.parse`, so the voter
 *  used to sign a different weight from the issuer's and every such ballot was rejected. */
const VOTER_SK = 0x1357n;
const ELIGIBILITY_KEY = "b1d451c0c9520fcb974b612631c96824e42965d5189809225bbe9d207aed2ced9d82890c4983314fa98ee9ec7f5959fc";
const ATTEST_RESPONSE = '{"attestation": {"scheme": "ATTESTATION_V1", "electionId": "0x0000000000000000000000000000000000000000000000000000000000000007", "pseudonym": "0x3131313131313131313131313131313131313131313131313131313131313131", "vk": "0x854d7a0d05fdb62a21b7d776d365a8e6f0a055de021696e322a1adfb05705a7d136f47131ff8ea63e7efede862a284fd", "weight": "1234567890123456789", "nonce": "2", "signature": "0xb4d1beca80e4ac7e073d43141655fa7164466805fe1f8a12ff4500efea7a123d0b00a309abf1d9d90bcebbc16773d1a001d6d9e78d2eea8be1aa23816ac1f049dff587582456fcf9a60b287492da1474"}, "pseudonym": "0x3131313131313131313131313131313131313131313131313131313131313131"}';

const params = { numCandidates: 3, budget: 3, mode: "exact" as const, variant: "A" as const };
const bytes = (h: string) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

beforeAll(() => S.initCurves());

function buildAndVerify(responseText: string) {
  const { attestation, pseudonym } = JSON.parse(responseText);
  const { sk, vk } = S.schnorrKeygen(VOTER_SK);
  const mpk = S.G2Point.generator().mul(987654321n);
  const inputs = S.buildBallot({
    mpk, electionId: bytes(attestation.electionId), pseudonym: bytes(pseudonym), sk, vk,
    votes: [3n, 0n, 0n], params, attestation: toSdkAttestation(attestation),
  });
  return { weight: inputs.attestation.weight, res: S.verifyBallot(inputs, params, mpk, bytes(ELIGIBILITY_KEY)) };
}

describe("voter credential parsing", () => {
  it("keeps a wei-scale weight exact when the issuer sends a decimal string", () => {
    const { weight, res } = buildAndVerify(ATTEST_RESPONSE);
    expect(weight).toBe(1234567890123456789n);
    expect(res).toEqual({ ok: true });
  });

  it("the old JSON-number form loses the weight, so the issuer's signature no longer matches", () => {
    const asNumber = ATTEST_RESPONSE.replace('"weight": "1234567890123456789"', '"weight": 1234567890123456789');
    const { weight, res } = buildAndVerify(asNumber);
    expect(weight).not.toBe(1234567890123456789n);
    expect(res.ok).toBe(false);
  });
});
