"""Ballot construction, validity-proof codec, and crypto verification.

Variant A / exact mode (conformance level 1). Byte-faithful to
the SDK (``verify.ts``, ``highlevel.ts``, ``codec.ts``): the canonical ballot
message the voter signs, the transcript seeding shared by prover and verifier,
and the versioned ``BallotValidityProof`` encoding.

Ballot *crypto* verification here covers only the range/budget proofs and the
Schnorr signature — attestation verification is a separate concern
(:mod:`shutter_governance_protocol.ports.eligibility` / the admission module) so the admitter can assign
a precise exclusion reason. ``verify_ballot_crypto`` returns a reason string that
matches the :class:`shutter_governance_protocol.envelopes.types.ExclusionReason` vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from eth_utils import keccak

from shutter_governance_protocol.crypto import proofs, schnorr
from shutter_governance_protocol.crypto.params import (
    BALLOT_MESSAGE_LABEL,
    BALLOT_PROOF_TRANSCRIPT_LABEL,
    BUDGET_EXACT_TAG,
    BVP_VERSION,
    CURVE_ORDER,
    VARIANT_A_BYTE,
    scalar_from_bytes,
)
from shutter_governance_protocol.crypto.points import (
    G2,
    Z1,
    Z2,
    add,
    g1_from_compressed,
    g1_to_compressed,
    g2_from_compressed,
    g2_to_compressed,
    mul,
    random_scalar,
)
from shutter_governance_protocol.crypto.proofs import ORBranch
from shutter_governance_protocol.crypto.transcript import Transcript


# --------------------------------------------------------------------------- #
#  BallotValidityProof binary codec (Variant A / exact)
# --------------------------------------------------------------------------- #

def encode_ballot_validity_proof(range_proofs: Sequence[Sequence[ORBranch]], e_b: int, z_b: int) -> bytes:
    """Encode Variant-A / exact validity proof."""
    n_outer = len(range_proofs)
    if n_outer == 0:
        raise ValueError("encode_ballot_validity_proof: no range proofs")
    branch_count = len(range_proofs[0])
    if any(len(p) != branch_count for p in range_proofs):
        raise ValueError("encode_ballot_validity_proof: branch counts diverge")

    out = bytearray()
    out.append(BVP_VERSION)
    out.append(VARIANT_A_BYTE)
    out += n_outer.to_bytes(2, "big")
    for _ in range(n_outer):
        out += branch_count.to_bytes(2, "big")
    for proof in range_proofs:
        for br in proof:
            out += g2_to_compressed(br.a1)
            out += g2_to_compressed(br.a2)
            out += (br.e % CURVE_ORDER).to_bytes(32, "big")
            out += (br.z % CURVE_ORDER).to_bytes(32, "big")
    out.append(BUDGET_EXACT_TAG)
    out += (e_b % CURVE_ORDER).to_bytes(32, "big")
    out += (z_b % CURVE_ORDER).to_bytes(32, "big")
    return bytes(out)


def decode_ballot_validity_proof(buf: bytes, num_candidates: int, budget: int):
    """Decode Variant-A / exact bytes. Returns ``(range_proofs, e_b, z_b)``."""
    if len(buf) < 4:
        raise ValueError("decode_ballot_validity_proof: buffer too short")
    o = 0
    if buf[o] != BVP_VERSION:
        raise ValueError(f"unsupported version 0x{buf[o]:02x}")
    o += 1
    if buf[o] != VARIANT_A_BYTE:
        raise ValueError(f"only variant A supported (got 0x{buf[o]:02x})")
    o += 1
    n_outer = int.from_bytes(buf[o:o + 2], "big"); o += 2
    if n_outer != num_candidates:
        raise ValueError(f"n_outer wire {n_outer} != numCandidates {num_candidates}")
    branch_count_expected = budget + 1
    branch_counts = []
    for _ in range(n_outer):
        bc = int.from_bytes(buf[o:o + 2], "big"); o += 2
        if bc != branch_count_expected:
            raise ValueError(f"branch_count {bc} != expected {branch_count_expected}")
        branch_counts.append(bc)

    range_proofs = []
    for bc in branch_counts:
        branches = []
        for _ in range(bc):
            a1 = g2_from_compressed(buf[o:o + 96]); o += 96
            a2 = g2_from_compressed(buf[o:o + 96]); o += 96
            e = scalar_from_bytes(buf[o:o + 32], "branch e"); o += 32
            z = scalar_from_bytes(buf[o:o + 32], "branch z"); o += 32
            branches.append(ORBranch(a1, a2, e, z))
        range_proofs.append(branches)

    if o >= len(buf):
        raise ValueError("decode_ballot_validity_proof: truncated before budget tag")
    tag = buf[o]; o += 1
    if tag != BUDGET_EXACT_TAG:
        raise ValueError(f"only exact-budget supported (got 0x{tag:02x})")
    e_b = scalar_from_bytes(buf[o:o + 32], "budget e"); o += 32
    z_b = scalar_from_bytes(buf[o:o + 32], "budget z"); o += 32
    if o != len(buf):
        raise ValueError(f"{len(buf) - o} trailing bytes after parse")
    return range_proofs, e_b, z_b


# --------------------------------------------------------------------------- #
#  Canonical ballot message + transcript seeding
# --------------------------------------------------------------------------- #

def canonical_ballot_message(election_id: bytes, pseudonym: bytes,
                             ciphertexts: Sequence[tuple[bytes, bytes]], zk_proof: bytes,
                             attestation) -> bytes:
    """The exact preimage the voter Schnorr-signs (mirrors ``verify.ts``).

    ``attestation`` is the eligibility credential, and **all of it is covered,
    signature bytes included**. Covering only the fields would leave the signature
    bytes unauthenticated, and Schnorr signing is randomised — one set of credential
    fields has many valid signatures — so a relay could swap one for another and keep
    the voter's signature valid. Semantically identical, but it makes the envelope
    malleable, and the published ballot feed is re-aggregated byte-for-byte by
    auditors while ballot digests serve as stable identifiers for duplicate detection
    and re-vote ordering. Both need the bytes pinned.

    The credential's own ``election_id`` is not repeated: the message already opens
    with it, and admission rejects an attestation naming a different election.
    """
    if len(election_id) != 32:
        raise ValueError(f"electionId must be 32 bytes (got {len(election_id)})")
    if len(pseudonym) != 32:
        raise ValueError(f"pseudonym must be 32 bytes (got {len(pseudonym)})")
    for c1, c2 in ciphertexts:
        if len(c1) != 96 or len(c2) != 96:
            raise ValueError("each ciphertext component must be 96 bytes")
    if len(attestation.pseudonym) != 32:
        raise ValueError("attestation.pseudonym must be 32 bytes")
    if len(attestation.vk) != 48:
        raise ValueError("attestation.vk must be 48 bytes")
    if attestation.weight < 0 or attestation.nonce < 0:
        raise ValueError("attestation weight/nonce must be non-negative")
    out = bytearray()
    out += BALLOT_MESSAGE_LABEL.encode("utf-8")
    out += election_id
    out += pseudonym
    out += len(ciphertexts).to_bytes(2, "big")
    for c1, c2 in ciphertexts:
        out += c1
        out += c2
    out += len(zk_proof).to_bytes(4, "big")
    out += zk_proof
    # Fixed 32-byte big-endian rather than a minimal encoding: a variable-length
    # integer would need its own length prefix to keep the concatenation injective,
    # and weight is unbounded now that voting power is uncapped.
    out += attestation.pseudonym
    out += attestation.vk
    out += int(attestation.weight).to_bytes(32, "big")
    out += int(attestation.nonce).to_bytes(32, "big")
    sig = attestation.signature
    if len(sig) > 0xFFFF:
        raise ValueError(f"attestation.signature too long ({len(sig)})")
    out += len(sig).to_bytes(2, "big")
    out += sig
    return bytes(out)


def _pre_v1_ballot_message(election_id: bytes, pseudonym: bytes,
                           ciphertexts: Sequence[tuple[bytes, bytes]],
                           zk_proof: bytes) -> bytes:
    """The v1 preimage -- diagnostic only, never accepted.

    Its single caller is the failure path in ``verify_ballot_crypto``, so a ballot
    from a pre-v2 client is reported as a format mismatch rather than as a bad
    signature. Deliberately a separate function rather than a flag on
    ``canonical_ballot_message``: a parameter that switches a signed format between
    versions is one mistaken argument away from accepting the old one.
    """
    out = bytearray()
    out += b"SHUTTER-VOTE-BALLOT-v1"
    out += election_id
    out += pseudonym
    out += len(ciphertexts).to_bytes(2, "big")
    for c1, c2 in ciphertexts:
        out += c1
        out += c2
    out += len(zk_proof).to_bytes(4, "big")
    out += zk_proof
    return bytes(out)


def seed_ballot_transcript(election_id: bytes, mpk, vk, ciphertexts_pts, *,
                           num_candidates: int, budget: int) -> Transcript:
    """Seed the shared prover/verifier transcript (Variant A / exact)."""
    t = Transcript(BALLOT_PROOF_TRANSCRIPT_LABEL)
    t.append("electionId", election_id)
    t.append_point("mpk", mpk)
    t.append("vk", g1_to_compressed(vk))  # vk is G1
    t.append("variant", b"\x41")
    t.append("mode", b"\x00")
    t.append("numCandidates", num_candidates.to_bytes(2, "big"))
    t.append("budget", budget.to_bytes(2, "big"))
    t.append("|cts|", len(ciphertexts_pts).to_bytes(2, "big"))
    for i, (c1, c2) in enumerate(ciphertexts_pts):
        t.append_point(f"ct.c1[{i}]", c1)
        t.append_point(f"ct.c2[{i}]", c2)
    return t


# --------------------------------------------------------------------------- #
#  build_ballot (Variant A / exact)
# --------------------------------------------------------------------------- #

@dataclass
class BuiltBallot:
    election_id: bytes
    pseudonym: bytes
    vk: bytes  # 48-byte compressed G1
    ciphertexts: list[tuple[bytes, bytes]]  # each (96, 96)
    zk_proof: bytes
    voter_signature: bytes  # 80 bytes
    canonical_preimage: bytes


def build_ballot(*, mpk, election_id: bytes, pseudonym: bytes, sk: int, vk, attestation,
                 votes: Sequence[int], num_candidates: int, budget: int,
                 rs=None, range_proof_w=None, range_proof_sims=None,
                 budget_proof_w=None, schnorr_k=None) -> BuiltBallot:
    """Build a Variant-A / exact ballot (mirrors ``highlevel.ts:buildBallot``).

    Randomness stays inside this function; optional pinned
    randomness reproduces fixtures. Does NOT create the eligibility attestation —
    that is issued separately by the eligibility service and attached to the
    envelope by the caller.
    """
    if len(votes) != num_candidates:
        raise ValueError(f"votes length {len(votes)} != numCandidates {num_candidates}")
    for j, v in enumerate(votes):
        if v < 0 or v > budget:
            raise ValueError(f"vote[{j}] = {v} not in [0, {budget}]")
    if sum(int(v) for v in votes) != budget:
        raise ValueError(f"exact mode requires Σvotes == {budget}, got {sum(votes)}")
    if schnorr.keygen(sk)[1] != vk:
        raise ValueError("build_ballot: vk does not match sk·P1 (mismatched keypair)")

    # 1. Encrypt each vote.
    cts_pts, rs_used = [], []
    for j, v in enumerate(votes):
        r = (rs[j] if rs is not None else random_scalar()) % CURVE_ORDER
        c1 = mul(G2, r)
        c2 = add(mul(mpk, r), mul(G2, v))
        cts_pts.append((c1, c2))
        rs_used.append(r)

    # 2. Seed transcript.
    t = seed_ballot_transcript(election_id, mpk, vk, cts_pts,
                               num_candidates=num_candidates, budget=budget)

    # 3. Per-candidate range OR proof.
    candidates = list(range(budget + 1))
    range_proofs = []
    for j in range(num_candidates):
        t.append("ballot:range", j.to_bytes(2, "big"))
        c1, c2 = cts_pts[j]
        proof = proofs.prove_or(
            c1, c2, mpk, candidates, rs_used[j], int(votes[j]), t,
            w=(range_proof_w[j] if range_proof_w is not None else None),
            simulated=(range_proof_sims[j] if range_proof_sims is not None else None),
        )
        range_proofs.append(proof)

    # 4. Homomorphic sum + exact-budget proof.
    c1_sum, c2_sum = Z2, Z2
    for c1, c2 in cts_pts:
        c1_sum = add(c1_sum, c1)
        c2_sum = add(c2_sum, c2)
    r_sum = sum(rs_used) % CURVE_ORDER
    t.append("ballot:budget", b"\x00")
    e_b, z_b = proofs.prove_budget_exact(c1_sum, c2_sum, mpk, budget, r_sum, t, w=budget_proof_w)

    # 5. Encode proof, canonicalize, Schnorr-sign.
    zk_proof = encode_ballot_validity_proof(range_proofs, e_b, z_b)
    ct_bytes = [(g2_to_compressed(c1), g2_to_compressed(c2)) for (c1, c2) in cts_pts]
    preimage = canonical_ballot_message(election_id, pseudonym, ct_bytes, zk_proof, attestation)
    R, s = schnorr.sign(sk, vk, keccak(preimage), k=schnorr_k)
    return BuiltBallot(
        election_id=election_id,
        pseudonym=pseudonym,
        vk=g1_to_compressed(vk),
        ciphertexts=ct_bytes,
        zk_proof=zk_proof,
        voter_signature=schnorr.encode(R, s),
        canonical_preimage=preimage,
    )


# --------------------------------------------------------------------------- #
#  verify_ballot_crypto (proofs + signature; attestation checked elsewhere)
# --------------------------------------------------------------------------- #

def verify_ballot_crypto(*, mpk, election_id: bytes, pseudonym: bytes, vk_bytes: bytes,
                         ciphertext_bytes: Sequence[tuple[bytes, bytes]], zk_proof: bytes,
                         voter_signature: bytes, attestation, num_candidates: int,
                         budget: int) -> tuple[bool, str | None]:
    """Verify range/budget proofs and the Schnorr signature.

    Returns ``(ok, reason)`` where ``reason`` is ``None`` on success or one of
    ``"MALFORMED"`` / ``"INVALID_PROOF"`` / ``"INVALID_SIGNATURE"`` — matching the
    exclusion-reason vocabulary. Attestation validity is verified separately.
    """
    if not (1 <= num_candidates <= 0xFFFF):
        return False, "MALFORMED"
    # 0xFFFE, not 0xFFFF: the proof encodes ``branch_count = budget + 1`` as two bytes
    # big-endian, so budget = 0xFFFF makes branch_count 0x10000 and
    # ``encode_ballot_validity_proof`` raises OverflowError. Accepting it here would turn a
    # clean MALFORMED rejection into an uncaught crash on the verify path.
    if not (1 <= budget <= 0xFFFE):
        return False, "MALFORMED"
    if len(election_id) != 32 or len(pseudonym) != 32:
        return False, "MALFORMED"
    if mpk == Z2:
        return False, "MALFORMED"

    try:
        vk = g1_from_compressed(vk_bytes)
    except Exception:  # noqa: BLE001
        return False, "MALFORMED"
    if vk == Z1:
        return False, "MALFORMED"
    if len(ciphertext_bytes) != num_candidates:
        return False, "MALFORMED"

    cts_pts = []
    for (c1b, c2b) in ciphertext_bytes:
        try:
            cts_pts.append((g2_from_compressed(c1b), g2_from_compressed(c2b)))
        except Exception:  # noqa: BLE001
            return False, "MALFORMED"

    try:
        range_proofs, e_b, z_b = decode_ballot_validity_proof(zk_proof, num_candidates, budget)
    except Exception:  # noqa: BLE001
        return False, "MALFORMED"

    t = seed_ballot_transcript(election_id, mpk, vk, cts_pts,
                               num_candidates=num_candidates, budget=budget)
    candidates = list(range(budget + 1))
    for j in range(num_candidates):
        t.append("ballot:range", j.to_bytes(2, "big"))
        c1, c2 = cts_pts[j]
        if not proofs.verify_or(c1, c2, mpk, candidates, range_proofs[j], t):
            return False, "INVALID_PROOF"

    c1_sum, c2_sum = Z2, Z2
    for c1, c2 in cts_pts:
        c1_sum = add(c1_sum, c1)
        c2_sum = add(c2_sum, c2)
    t.append("ballot:budget", b"\x00")
    if not proofs.verify_budget_exact(c1_sum, c2_sum, mpk, budget, e_b, z_b, t):
        return False, "INVALID_PROOF"

    try:
        R, s = schnorr.decode(voter_signature)
    except Exception:  # noqa: BLE001
        return False, "MALFORMED"
    # Stored ballots are untrusted, so a credential that cannot be encoded (a weight or
    # nonce too large for its 32-byte field) must be excluded, not crash the tally.
    try:
        preimage = canonical_ballot_message(election_id, pseudonym, ciphertext_bytes, zk_proof,
                                           attestation)
    except (ValueError, OverflowError):
        return False, "MALFORMED"
    if not schnorr.verify(vk, keccak(preimage), R, s):
        # Name a format mismatch as one. A v1 signature does not fail informatively
        # against v2 -- ``schnorr.verify`` just returns False, which reads as "wrong
        # voter" and sends the reader after the key. One extra keccak, on a path that
        # has already failed.
        if schnorr.verify(vk, keccak(_pre_v1_ballot_message(
                election_id, pseudonym, ciphertext_bytes, zk_proof)), R, s):
            return False, "INVALID_SIGNATURE_PRE_V2"
        return False, "INVALID_SIGNATURE"
    return True, None
