"""Election configuration and lifecycle enums.

The election-configuration table. The config is
registered once by the admin service and is **immutable after ``voting_start``**
(the data-layer adapter enforces this: free on the contract adapter, mandatory
server-side on the database adapter).

Every field here is a pure datum; nothing in this module performs I/O or crypto.
Identities (``eligibility_key``, ``result_publisher_key``, ``gateway_keys``,
``admin_key``, and each keyper's signing identity) are opaque ``bytes`` — the
data-layer adapter decides how to interpret them (a 20-byte Ethereum address on
the chain adapter, a 48-byte compressed-G1 key on a signature-checking database
adapter, etc.). The core protocol only compares them for equality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Mode(str, Enum):
    """Budget constraint over the per-ballot vote vector."""

    EXACT = "exact"  # sum(votes) == budget
    AT_MOST = "atMost"  # sum(votes) <= budget   (conformance level 2)


class Variant(str, Enum):
    """Per-candidate validity-proof construction."""

    A = "A"  # (B+1)-branch OR proof per candidate      (conformance level 1)
    B = "B"  # bit-decomposition proofs per candidate   (conformance level 2)


class DuplicatePolicy(str, Enum):
    """How repeated ballots for one pseudonym are resolved at tally time.

    Evaluated over the data layer's stable total order, so the
    outcome is reproducible by any auditor.
    """

    FIRST_WINS = "first-wins"
    LAST_WINS = "last-wins"


@dataclass(frozen=True)
class Threshold:
    """(t, n): any ``t`` of ``n`` keypers can decrypt — ``t`` **is** the quorum.

    ``t`` is the number of keypers that must act together, not the corruption
    threshold: (2, 3) means 2-of-3. This is deliberate. The on-chain
    ``KeyperSet.getThreshold()`` has always stored the quorum count, and
    ``ElectionConfigView.thresholdT`` exposes it under the ``t`` name, so the previous
    "``t`` is the corruption threshold, quorum is ``t+1``" reading made one field mean
    two different things across backends and left the whole cross-backend agreement
    resting on a single compensating ``-1`` in the chain codec. One meaning everywhere
    now: **the number in the config is the number of keypers you need.**

    The Feldman-VSS polynomial that ``t`` implies is degree ``t - 1`` (``t``
    coefficients, so ``t`` shares interpolate it) — see :attr:`polynomial_degree`.
    """

    t: int
    n: int

    def __post_init__(self) -> None:
        if self.n < 1:
            raise ValueError("The committee size (n) must be at least 1.")
        if not (1 <= self.t <= self.n):
            raise ValueError(
                f"The threshold must satisfy 1 <= t <= n (t is the quorum: t of n keypers "
                f"decrypt); got t={self.t}, n={self.n}."
            )
        # The quorum must be a strict MAJORITY. 2-of-3 and 3-of-5 are majorities; 2-of-5 is
        # not — it is just a subset, and two *disjoint* ones fit in the committee at once.
        # That matters because this number is used for agreement, not only for decryption:
        # an artifact becomes canonical when the quorum submits it byte-identically, and
        # without majority intersection two different artifacts could each be "canonical",
        # leaving the winner to iteration order. Threshold decryption alone
        # would tolerate t <= n/2 (it favours liveness), but agreement will not.
        if self.t * 2 <= self.n:
            raise ValueError(
                f"The threshold must be a majority: t > n/2. Got t={self.t}, n={self.n} "
                f"— use t >= {self.n // 2 + 1}. Two disjoint groups of {self.t} fit in a "
                f"committee of {self.n}, so they could each claim the same quorum."
            )

    @property
    def quorum(self) -> int:
        """Keypers required to act together. An alias for ``t``, for call sites where
        naming the concept is clearer than the bare letter."""
        return self.t

    @property
    def polynomial_degree(self) -> int:
        """Degree of each dealer's Feldman polynomial: ``t`` coefficients ⇒ degree ``t-1``."""
        return self.t - 1


@dataclass(frozen=True)
class KeyperIdentity:
    """One committee member: a signing identity plus a P2P URL.

    ``signing_key`` is the opaque identity the data layer checks DKG-result,
    aggregate, and decryption-share writes against; ``url`` is where the
    coordinator reaches this keyper over HTTP.
    """

    signing_key: bytes
    url: str


@dataclass(frozen=True)
class ElectionConfig:
    """Full immutable election configuration.

    Superset of the on-chain ``ElectionConfigView``: this generalised config
    adds ``mode``, ``variant``, ``weighted``, ``scale``, ``duplicate_policy``,
    per-keyper URLs, and the explicit authorization
    identities (``eligibility_key``, ``result_publisher_key``, ``gateway_keys``,
    ``admin_key``) plus ``protocol_version``.
    """

    election_id: bytes  # globally unique (bytes32)
    num_candidates: int  # length of the vote vector
    budget: int  # B, the per-ballot vote budget
    mode: Mode
    variant: Variant
    weighted: bool  # whether attested weights other than 1 are permitted
    duplicate_policy: DuplicatePolicy
    voting_start: int  # absolute unix timestamp (seconds)
    voting_end: int  # absolute unix timestamp (seconds)
    threshold: Threshold
    keypers: tuple[KeyperIdentity, ...]  # n keyper identities + URLs
    eligibility_key: bytes  # public key attestations must verify against
    result_publisher_key: bytes  # identity authorized to publish aggregate + result
    gateway_keys: tuple[bytes, ...]  # authorized ballot writers (empty = open writes)
    admin_key: bytes  # identity authorized to register/cancel
    protocol_version: str  # crypto suite + wire format version
    # Divisor applied to every attested weight at aggregation: the tally counts in
    # units of `scale` rather than in single tokens.
    #
    # Exists because the recovery bound is `budget × Σ(admitted weights)` and BSGS
    # cost grows as its square root, so a token with a very large supply could
    # otherwise put a tally out of reach. Dividing everyone preserves every ratio in
    # the cap table; the alternative — capping the largest holders — silently
    # flattens the top of it and changes outcomes.
    #
    # `1` means no scaling and is the expected value for essentially every election:
    # a deployment only needs `scale > 1` when `budget × total supply` exceeds what
    # its coordinator can solve (see docs/COORDINATOR_SIZING.md). The value is chosen
    # by the deployment, frozen before voting opens, and disclosed to voters — it
    # changes what a ballot is worth, so it is not something to discover at tally.
    scale: int = 1
    # Per-ballot fee (wei) a non-proxy self-submitter pays on the blockchain backend; part
    # of the signed config (it is on-chain contract state, unlike the ephemeral DKG lead
    # time). 0 = free. The database backend has no fees and ignores it. Defaulted so
    # existing constructors/fixtures need no change.
    self_submit_fee_wei: int = 0

    def __post_init__(self) -> None:
        if self.num_candidates < 1:
            raise ValueError("There must be at least one candidate.")
        if self.self_submit_fee_wei < 0:
            raise ValueError("Self-submit fee cannot be negative.")
        if self.budget < 1:
            raise ValueError("The budget must be at least 1.")
        if self.scale < 1:
            raise ValueError("Scale must be at least 1 (1 means no scaling).")
        if self.scale >= 2**256:
            raise ValueError("Scale must fit in 256 bits.")
        self._check_ballot_bounds()
        if self.voting_end <= self.voting_start:
            raise ValueError("Voting end must be after voting start.")
        if len(self.keypers) != self.threshold.n:
            raise ValueError(
                f"The committee needs exactly {self.threshold.n} keypers, but got {len(self.keypers)}."
            )
        # The committee must be n *distinct* members. Two entries with the same
        # signing key are the same keyper (e.g. two URLs that resolve to one keyper's
        # /status identity) and would corrupt the t-of-n threshold — reject
        # authoritatively here, independent of any frontend check. (URLs are not
        # deduped: in-process deployments leave them empty; duplicate-URL rejection is
        # a frontend UX guard.)
        keys = [k.signing_key for k in self.keypers]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate keyper: each committee member must be a distinct wallet.")

    # -- ballot / tally feasibility bounds ----------------------- #
    #
    # Enforced here, in the frozen config, rather than at any single entry point: every
    # path builds an ElectionConfig (admin service, data-layer service via dec_config, the
    # CLI, tests), so a caller who bypasses the frontend — or the admin service entirely —
    # is still caught. Registering a config that no voter can vote under, and only finding
    # out at tally, is the failure these ceilings prevent.

    # A ballot's validity proof is one OR-proof branch per (candidate, budget level):
    # num_candidates * (budget + 1) branches, each 256 bytes, plus another budget + 1 for
    # the atMost proof over the sum. Two independent ceilings.

    #: Absolute encoding limits. ``n_outer`` is written as 2 bytes big-endian and
    #: ``branch_count = budget + 1`` likewise — so budget tops out one BELOW 0xFFFF, or the
    #: encoder raises OverflowError. Mirrors ``crypto.ballot.verify_ballot_crypto``.
    MAX_NUM_CANDIDATES = 0xFFFF
    MAX_BUDGET = 0xFFFE

    #: Verification ceiling, and in practice the binding one. Each branch costs ~2.8 ms to
    #: verify, and **every keyper and every auditor verifies every ballot** at tally. Sized
    #: for the real target shape — 20 candidates at budget 100 = 2020 branches (~5.7 s per
    #: ballot, ~1 MiB of ballot) — with headroom to 25 candidates at that budget. The
    #: encoding limits above would allow 4.3 billion branches, i.e. an election that
    #: registers cleanly and can never be tallied.
    #:
    #: Note this bounds per-*ballot* cost only. Total tally cost is branches x ballots,
    #: which registration cannot know; that is bounded at run time by the coordinator's
    #: tally-phase deadline instead.
    MAX_PROOF_BRANCHES = 2500


    def _check_ballot_bounds(self) -> None:
        if self.num_candidates > self.MAX_NUM_CANDIDATES:
            raise ValueError(
                f"Too many candidates: {self.num_candidates} exceeds the {self.MAX_NUM_CANDIDATES} "
                f"the ballot proof format can encode."
            )
        if self.budget > self.MAX_BUDGET:
            raise ValueError(
                f"Budget too large: {self.budget} exceeds {self.MAX_BUDGET} (the proof encodes "
                f"budget+1 as two bytes)."
            )
        proofs = self.num_candidates + (1 if self.mode == Mode.AT_MOST else 0)
        branches = proofs * (self.budget + 1)
        if branches > self.MAX_PROOF_BRANCHES:
            sum_proof = " (+1 for the atMost sum proof)" if self.mode == Mode.AT_MOST else ""
            raise ValueError(
                f"This election is too expensive to tally: {self.num_candidates} candidates{sum_proof} x "
                f"(budget {self.budget} + 1) = {branches} proof branches per ballot, over the "
                f"{self.MAX_PROOF_BRANCHES} limit. Every keyper and auditor verifies every "
                f"ballot, at roughly 3 ms per branch. Reduce the candidates or the budget."
            )

