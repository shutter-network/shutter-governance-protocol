/** Client-side ballot construction + submission.
 *
 * Uses `@shutter-network/urban-verified-crypto` (the TS origin the Python crypto
 * byte-matches) to build the encrypted ballot entirely in the browser — plaintext
 * votes and randomness never leave this device. The eligibility attestation comes from
 * the (pluggable, dummy) eligibility service and is attached as the shutter_governance_protocol wire's
 * *structured* `attestation` field.
 *
 * Attestation note: since the v2 ballot message the credential lives *inside* the signed
 * ballot, so there is exactly one voter signature and it covers `weight`, `nonce` and the
 * issuer's signature bytes along with the ciphertexts and proof.
 *
 * It used to be two. The SDK's `wrAttestation` slot was opaque bytes not covered by
 * `canonicalBallotMessage`, so this module passed an empty placeholder, attached the real
 * credential beside it, and signed a *second* time over a separate binding transcript to
 * tie them together — because otherwise the voter committed to no particular `weight` or
 * `nonce`, and `nonce` is what orders their re-votes. That transcript existed in four
 * implementations across two languages; folding the credential into the ballot deleted all
 * of them.
 *
 * One consequence worth knowing when reading rejections: a tampered ciphertext and a
 * swapped credential now both fail as an invalid signature. The old two-step check could
 * tell them apart, and `INVALID_ATTESTATION` meant something narrow — ballot and
 * credential each sound, the *pairing* wrong. There is only one signature to fail now. */

import {
  G2Point,
  buildBallot,
  initCurves,
  schnorrKeygen,
  type Attestation,
  type BallotInputs,
} from "@shutter-network/urban-verified-crypto";
import {
  type AttestationJson,
  attest,
  bytesToHex,
  eidToBareHex,
  eidToHex,
  hexToBytes,
  submitBallot,
  type BallotJson,
  type ElectionConfig,
} from "@shutter-governance-protocol/shared";
import type { Hex } from "viem";

/** The chain-free EIP-191 challenge the wallet signs — byte-identical to the eligibility
 * service's `challenge_message` (see eligibility.py), so the service can `ecrecover` it. */
function challengeMessage(eidHex: string, vkHex: string): string {
  return `Shutter Governance Protocol eligibility attestation\nelectionId: ${eidHex}\nvk: ${vkHex}`;
}

let curvesReady: Promise<void> | null = null;
/** Load blst.wasm + init the curve library once (idempotent). */
export function ensureCurves(): Promise<void> {
  if (!curvesReady) curvesReady = initCurves();
  return curvesReady;
}

/** The wire credential (hex, optional nonce) as the SDK's byte-and-bigint shape. Weight
 *  and nonce arrive as decimal strings so `BigInt` gets them exactly; exported for tests. */
export function toSdkAttestation(a: AttestationJson): Attestation {
  return {
    electionId: hexToBytes(a.electionId),
    pseudonym: hexToBytes(a.pseudonym),
    vk: hexToBytes(a.vk),
    weight: BigInt(a.weight),
    // The issuer always emits it; defaulting keeps an older stub usable rather than
    // silently signing over a different nonce than the one that will be stored.
    nonce: BigInt(a.nonce ?? 1),
    signature: hexToBytes(a.signature),
  };
}

export interface CastVoteArgs {
  config: ElectionConfig;
  pkElectionHex: string; // finalizedKey.pkElection (0x-hex, 96-byte compressed G2)
  votes: number[]; // length == numCandidates
  /** EIP-191 personal-sign from the connected wallet (chain-agnostic). */
  signMessage: (message: string) => Promise<Hex>;
  onStage?: (msg: string) => void;
}

export async function castVote(args: CastVoteArgs): Promise<{ sequenceNumber: number }> {
  await ensureCurves();
  const { config, pkElectionHex, votes, signMessage, onStage } = args;

  const eidHex = eidToHex(config.electionId);
  const eidBytes = hexToBytes(eidHex);
  const mpk = G2Point.fromBytes(hexToBytes(pkElectionHex));

  // Ephemeral voter Schnorr key. The wallet personal-signs the challenge over
  // (electionId, vk); the eligibility service recovers the wallet, derives a stable
  // per-wallet pseudonym, and returns it + the attestation. The pseudonym is
  // server-owned (one wallet, one vote); we build the ballot with exactly it.
  const { sk, vk } = schnorrKeygen();
  const vkHex = bytesToHex(vk.toBytes());
  const signature = await signMessage(challengeMessage(eidHex, vkHex));
  onStage?.("Requesting eligibility attestation…");
  const { attestation, pseudonym } = await attest({ electionId: eidHex, vk: vkHex, signature });
  const pseudonymBytes = hexToBytes(pseudonym);

  onStage?.("Building ballot");

  // The credential goes *into* the ballot, so it must exist before the ballot is
  // signed. Under v1 it was fetched here too, but the ballot's own signature did not
  // cover it and a second signature over a separate binding transcript was what tied
  // them together.
  const inputs: BallotInputs = buildBallot({
    mpk,
    electionId: eidBytes,
    pseudonym: pseudonymBytes,
    sk,
    vk,
    votes: votes.map((v) => BigInt(v)),
    params: {
      numCandidates: config.numCandidates,
      budget: config.budget,
      mode: config.mode,
      variant: config.variant,
    },
    attestation: toSdkAttestation(attestation),
  });

  const ballot: BallotJson = {
    electionId: eidHex,
    pseudonym: bytesToHex(inputs.pseudonym),
    vk: bytesToHex(inputs.vk),
    ciphertexts: inputs.ciphertexts.map(([c1, c2]) => ({ c1: bytesToHex(c1), c2: bytesToHex(c2) })),
    zkProof: bytesToHex(inputs.zkProof),
    voterSignature: bytesToHex(inputs.voterSignature),
    attestation,
  };

  return submitBallot(eidToBareHex(config.electionId), ballot);
}
