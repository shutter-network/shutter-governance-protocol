/** Admin authorization: sign register/cancel requests with the admin wallet (MetaMask).
 *
 * The digests below are byte-exact mirrors of `shutter_governance_protocol.core.authz`:
 *   register → keccak256(canonical JSON of the config, electionId INCLUDED)     == register_digest
 *   cancel   → keccak256(DST | len|op | len|eid | len|payload)                   == request_digest("cancel", eid)
 * The wallet then EIP-191 personal-signs the raw digest (== Python encode_defunct(primitive=digest)),
 * so the service/data-layer `ecrecover` matches config.admin_key. Locked by adminSign.test.ts. */

import { concat, hexToBytes, keccak256, stringToBytes, type Hex } from "viem";

/** Canonical JSON matching Python `json.dumps(obj, sort_keys=True, separators=(",",":"))`:
 * object keys sorted recursively, array order preserved, no whitespace. (Values here are
 * ASCII hex / ints / short strings, so JSON escaping is identical across Python and JS.) */
export function canonicalize(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(o[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

/** Lowercase every 0x-hex value in a config. The backend decodes each address/key to bytes
 * and re-encodes it **lowercase** before recomputing the digest, so we must sign the
 * lowercase form. Critically, wagmi returns the admin's address EIP-55 **checksummed**
 * (mixed case); signing that verbatim changes the digest and fails verification. Non-hex
 * strings (variant "A", mode, urls, protocolVersion) don't start with 0x, so are untouched. */
export function lowercaseHex<T>(v: T): T {
  if (typeof v === "string") return (v.startsWith("0x") ? v.toLowerCase() : v) as T;
  if (Array.isArray(v)) return v.map(lowercaseHex) as unknown as T;
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, lowercaseHex(val)])) as T;
  }
  return v;
}

/** register_digest: the digest covers the whole config **including electionId**, which
 * must carry the id this registration expects to be assigned (the current sequence head
 * plus one — see `nextElectionId`). The backend still assigns the id itself and refuses
 * when its own next id disagrees, which is what makes a signed registration single-use:
 * once it lands the sequence moves on, so replaying the same body is permanently dead. */
export function registerDigest(config: Record<string, unknown>): Hex {
  return keccak256(stringToBytes(canonicalize(config)));
}

/** Render an election id as the canonical 0x-hex 32-byte value the config carries. */
export function encodeElectionId(n: number): Hex {
  return ("0x" + n.toString(16).padStart(64, "0")) as Hex;
}

/** Domain tag + 4-byte big-endian length framing, byte-exact with `authz.REQUEST_DST`
 * and `authz.request_digest`. The previous `"op" | "|" | eid | "|"` join was ambiguous —
 * two different (op, eid, payload) triples could hash equal if any field contained the
 * separator. Framing makes each boundary explicit, so content can never
 * impersonate one. Both sides must change together or admin signatures stop verifying;
 * adminSign.test.ts and tests/test_admin_digest_fixture.py lock the pair. */
const REQUEST_DST = "SHUTTER-GOVERNANCE-PROTOCOL-REQUEST-v1";

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false); // false = big-endian
  return b;
}

function framed(bytes: Uint8Array): Uint8Array[] {
  return [u32be(bytes.length), bytes];
}

/** request_digest(op, eid, payload). `eid` is the canonical 0x-hex 32-byte election
 * id (accepts a plain string; @shutter-governance-protocol/shared's Hex is `string`). */
function requestDigest(op: string, eid: string, payload: Uint8Array = new Uint8Array(0)): Hex {
  return keccak256(concat([
    stringToBytes(REQUEST_DST),
    ...framed(stringToBytes(op)),
    ...framed(hexToBytes(eid as `0x${string}`)),
    ...framed(payload),
  ]));
}

/** authz.request_nonce_payload: the signing time as 8 bytes, big-endian unsigned seconds. */
export function requestNoncePayload(issuedAt: number): Uint8Array {
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) throw new Error(`bad issuedAt: ${issuedAt}`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(issuedAt), false); // false = big-endian
  return b;
}

/** request_digest("cancel", eid). */
export function cancelDigest(eid: string): Hex {
  return requestDigest("cancel", eid);
}

/** request_digest("tally_resume", eid, request_nonce_payload(issuedAt)) — the admin's
 * "retry" signature that clears a stalled tally so the coordinator resumes. It binds the
 * signing time, so the service accepts it only while fresh (±300 s) and only once: a
 * captured retry cannot be replayed to un-stall the tally again later. Send the same
 * `issuedAt` alongside the signature. */
export function retryTallyDigest(eid: string, issuedAt: number): Hex {
  return requestDigest("tally_resume", eid, requestNoncePayload(issuedAt));
}

