import { describe, expect, it } from "vitest";
import { cancelDigest, canonicalize, lowercaseHex, registerDigest, requestNoncePayload, retryTallyDigest } from "./adminSign";

// Fixtures generated from Python (shutter_governance_protocol.core.authz). If the wire config shape or the
// digest scheme changes, regenerate these from register_digest / request_digest.
const CONFIG = {
  electionId: "0x1111111111111111111111111111111111111111111111111111111111111111",
  numCandidates: 3,
  budget: 3,
  mode: "exact",
  variant: "A",
  weighted: true,
  scale: 1,
  duplicatePolicy: "last-wins",
  votingStart: 1000,
  votingEnd: 2000,
  threshold: { t: 2, n: 3 },
  keypers: [
    { signingKey: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url: "http://k1:8101" },
    { signingKey: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", url: "http://k2:8102" },
    { signingKey: "0xcccccccccccccccccccccccccccccccccccccccc", url: "http://k3:8103" },
  ],
  eligibilityKey:
    "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
  resultPublisherKey: "0xdddddddddddddddddddddddddddddddddddddddd",
  gatewayKeys: ["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],
  adminKey: "0xabababababababababababababababababababab",
  protocolVersion: "v1",
  selfSubmitFee: "0", // decimal wei string; part of the signed config
};

const EXPECTED_CANON =
  '{"adminKey":"0xabababababababababababababababababababab","budget":3,"duplicatePolicy":"last-wins","electionId":"0x1111111111111111111111111111111111111111111111111111111111111111","eligibilityKey":"0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","gatewayKeys":["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],"keypers":[{"signingKey":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"http://k1:8101"},{"signingKey":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","url":"http://k2:8102"},{"signingKey":"0xcccccccccccccccccccccccccccccccccccccccc","url":"http://k3:8103"}],"mode":"exact","numCandidates":3,"protocolVersion":"v1","resultPublisherKey":"0xdddddddddddddddddddddddddddddddddddddddd","scale":1,"selfSubmitFee":"0","threshold":{"n":3,"t":2},"variant":"A","votingEnd":2000,"votingStart":1000,"weighted":true}';
const EXPECTED_REGISTER = "0x8536550a834b1758270a909fdf80fa18a10d08ea391abfb00132d62f586e52e7";
const EXPECTED_CANCEL = "0xb6fcd4128e28fa3ad25b85b21ae2ffd9d586e9b0d67a419a3cdb7e4c85cd985f";
// request_digest("tally_resume", eid 7, request_nonce_payload(1700000000)).
const EXPECTED_RETRY = "0x23a3ce05b02fe845a2baf18b3eab4b4384ab530a6c1cedfc1e970d8dee191842";
const EID_7 = ("0x" + (7).toString(16).padStart(64, "0")) as `0x${string}`;

describe("admin digests match shutter_governance_protocol.core.authz (byte-exact)", () => {
  it("canonicalize == Python canonical JSON (electionId included)", () => {
    expect(canonicalize(CONFIG)).toBe(EXPECTED_CANON);
  });
  it("registerDigest == register_digest (binds electionId)", () => {
    expect(registerDigest(CONFIG)).toBe(EXPECTED_REGISTER);
  });
  it("a different asserted electionId yields a different digest (the replay guard)", () => {
    // Signing is per-id: the body that registered election N cannot be replayed to
    // register N+1, because the backend's next id would no longer match what was signed.
    expect(registerDigest({ ...CONFIG, electionId: "0x" + "2".repeat(64) })).not.toBe(EXPECTED_REGISTER);
  });
  it("cancelDigest == request_digest('cancel', eid)", () => {
    expect(cancelDigest(EID_7)).toBe(EXPECTED_CANCEL);
  });
  // The retry digest had no cross-check, so when the service started requiring a signed
  // timestamp the browser kept signing the old empty payload and every Retry failed.
  it("retryTallyDigest == request_digest('tally_resume', eid, request_nonce_payload(issuedAt))", () => {
    expect(retryTallyDigest(EID_7, 1700000000)).toBe(EXPECTED_RETRY);
    expect(retryTallyDigest(EID_7, 1700000001)).not.toBe(EXPECTED_RETRY);
  });
  it("requestNoncePayload is 8 bytes, big-endian seconds", () => {
    expect(Array.from(requestNoncePayload(1700000000))).toEqual([0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00]);
  });
});

describe("lowercaseHex normalizes wallet-checksummed addresses (regression)", () => {
  // wagmi returns EIP-55 checksummed (mixed-case) addresses; the backend re-encodes bytes
  // lowercase before recomputing the digest, so signing the mixed-case form fails
  // verification ("bad admin signature over the config").
  it("a checksummed adminKey yields the SAME digest as lowercase after normalization", () => {
    const checksummed = { ...CONFIG, adminKey: "0xABABABABABABABABABABABABABABABABABABABAB" };
    expect(registerDigest(checksummed)).not.toBe(EXPECTED_REGISTER); // mixed-case would fail
    expect(registerDigest(lowercaseHex(checksummed))).toBe(EXPECTED_REGISTER); // fix restores it
  });

  it("normalizes nested hex (keypers[].signingKey, gatewayKeys) but leaves non-0x strings", () => {
    const out = lowercaseHex({
      variant: "A",
      mode: "exact",
      keypers: [{ signingKey: "0xAAaaBBbb", url: "http://K1:8101" }],
      gatewayKeys: ["0xEEee"],
      adminKey: "0xAbCd",
    });
    expect(out).toEqual({
      variant: "A",            // enum value untouched
      mode: "exact",
      keypers: [{ signingKey: "0xaaaabbbb", url: "http://K1:8101" }], // url case preserved
      gatewayKeys: ["0xeeee"],
      adminKey: "0xabcd",
    });
  });
});
