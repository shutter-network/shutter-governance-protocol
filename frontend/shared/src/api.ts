/** Typed client for the shutter_governance_protocol service surfaces the browser apps talk to.
 *
 * - Public API (`:8500`) — backend-blind reads (dashboard) + ballot ingest (voter app;
 *   the former standalone gateway, now merged into this service).
 * - Admin (`:8300`) — register/cancel (admin app, wallet EIP-191 signature).
 * - Eligibility (`:8600`) — dummy attestation issuer (voter app; called from the browser).
 *
 * Base URLs come from Vite env (`VITE_*`) with localhost defaults. */

import type {
  AggregateJson,
  AttestationJson,
  BallotJson,
  DecryptionShareJson,
  DkgSubmission,
  ElectionRecord,
  FinalizedKey,
  ResultJson,
} from "./types";
import type { Hex } from "./hex";

const env: Record<string, string | undefined> = (import.meta as any).env ?? {};
export const API_URL = env.VITE_API_URL ?? "http://127.0.0.1:8500";
export const ADMIN_URL = env.VITE_ADMIN_URL ?? "http://127.0.0.1:8300";
export const ELIGIBILITY_URL = env.VITE_ELIGIBILITY_URL ?? "http://127.0.0.1:8600";

/** An HTTP error that carries the service's structured error body (reason/message). */
export class ApiError extends Error {
  constructor(public status: number, public body: any, msg: string) {
    super(msg);
  }
}

/** Prefer the service's human `message` field; fall back to `Error.message` / String. */
export function formatApiError(e: unknown): string {
  if (e instanceof ApiError) {
    const m = e.body?.message ?? e.body?.reason;
    if (typeof m === "string" && m.trim()) return m;
  }
  if (e instanceof Error && e.message) return e.message;
  return String(e);
}

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, init);
  const text = await resp.text();
  const body = text ? safeJson(text) : null;
  if (!resp.ok) {
    const reason = body?.reason ?? body?.message ?? body?.error ?? resp.statusText;
    throw new ApiError(resp.status, body, `${resp.status} ${reason}`);
  }
  return body as T;
}
function safeJson(t: string): any {
  try {
    return JSON.parse(t);
  } catch {
    return { message: t };
  }
}
const jsonPost = (body: unknown, headers: Record<string, string> = {}): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json", ...headers },
  body: JSON.stringify(body),
});

// -- public read API -------------------------------------------------------- //

export interface ElectionList {
  electionIds: number[];
  total: number;
  limit: number;
  offset: number;
}

export const api = {
  listElections: (opts: { admin?: string; limit?: number; offset?: number } = {}) => {
    const q = new URLSearchParams();
    if (opts.admin) q.set("admin", opts.admin);
    if (opts.limit != null) q.set("limit", String(opts.limit));
    if (opts.offset != null) q.set("offset", String(opts.offset));
    const qs = q.toString();
    return req<ElectionList>(`${API_URL}/elections${qs ? `?${qs}` : ""}`);
  },
  getElection: (id: number) => req<ElectionRecord>(`${API_URL}/elections/${id}`),
  getDkg: (id: number) => req<{ submissions: DkgSubmission[] }>(`${API_URL}/elections/${id}/dkg`),
  getFinalized: (id: number) => req<{ finalizedKey: FinalizedKey | null }>(`${API_URL}/elections/${id}/dkg/finalized`),
  countBallots: (id: number) => req<{ count: number }>(`${API_URL}/elections/${id}/ballots/count`),
  listBallots: (id: number, offset = 0, limit = 50) =>
    req<{ ballots: any[]; total: number; limit: number; offset: number }>(
      `${API_URL}/elections/${id}/ballots?offset=${offset}&limit=${limit}`,
    ),
  getAggregate: (id: number) => req<{ aggregate: AggregateJson | null }>(`${API_URL}/elections/${id}/aggregate`),
  getShares: (id: number) => req<{ shares: DecryptionShareJson[] }>(`${API_URL}/elections/${id}/shares`),
  getResult: (id: number) => req<{ result: ResultJson | null }>(`${API_URL}/elections/${id}/result`),
  getCapability: () => req<{ verifiabilityTier: string; dataStore: "database" | "blockchain" }>(`${API_URL}/capability`),
};

// -- ballot ingest (voter) -------------------------------------------------- //

/** POST a fully-assembled ballot envelope to the public API's ingest route (formerly the
 * standalone gateway). `eidBareHex` is the 64-char hex (no 0x). */
export const submitBallot = (eidBareHex: string, ballot: BallotJson) =>
  req<{ sequenceNumber: number }>(`${API_URL}/elections/${eidBareHex}/ballots`, jsonPost({ ballot }));

// -- admin ------------------------------------------------------------------ //

// The admin authorizes with a wallet signature (no bearer token). `signature`
// is the admin EOA's EIP-191 sig over the register/cancel digest; the service relays it.
// selfSubmitFee is part of `config` (signed), so it is not a separate param here.
export const registerElection = (config: unknown, signature: Hex, dkgLeadTime?: number) =>
  req<{ electionId: Hex }>(
    `${ADMIN_URL}/elections`,
    jsonPost({ config, signature, ...(dkgLeadTime != null ? { dkgLeadTime } : {}) }),
  );

export const cancelElection = (idBareHex: string, signature: Hex) =>
  req<unknown>(`${ADMIN_URL}/elections/${idBareHex}/cancel`, jsonPost({ signature }));

/** Admin "retry" for a stalled tally: clears the persisted flag so the coordinator resumes.
 *  `issuedAt` is the unix time the signature covers (see adminSign.retryTallyDigest). */
export const retryTally = (idBareHex: string, signature: Hex, issuedAt: number) =>
  req<unknown>(`${ADMIN_URL}/elections/${idBareHex}/tally/retry`, jsonPost({ signature, issuedAt }));

// -- eligibility (voter) ---------------------------------------------------- //

/** Wallet-authenticated attestation: the voter proves address control by EIP-191
 * personal-signing the challenge over `(electionId, vk)` (chain-agnostic); the service
 * derives the pseudonym + weight and returns them (the pseudonym is server-owned,
 * enforcing one wallet, one vote). */
export const attest = (r: { electionId: Hex; vk: Hex; signature: Hex }) =>
  req<{ attestation: AttestationJson; pseudonym: Hex }>(`${ELIGIBILITY_URL}/attest`, jsonPost(r));

/** The eligibility issuer's public key, from its `/health`. Used by the admin register form
 * to confirm the `eligibilityKey` being registered matches the running issuer (otherwise
 * every ballot for the election would fail attestation verification at ingestion). */
export const fetchEligibilityKey = (url: string = ELIGIBILITY_URL) =>
  req<{ ok: boolean; eligibilityKey: Hex }>(`${url.replace(/\/+$/, "")}/health`);
