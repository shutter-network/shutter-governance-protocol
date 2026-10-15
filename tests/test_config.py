"""Validation tests for ElectionConfig and its enums."""

from __future__ import annotations

import pytest

from shutter_governance_protocol.core.config import (
    DuplicatePolicy,
    ElectionConfig,
    KeyperIdentity,
    Mode,
    Threshold,
    Variant,
)


def _keypers(n: int) -> tuple[KeyperIdentity, ...]:
    return tuple(
        KeyperIdentity(signing_key=bytes([i]) * 20, url=f"https://keyper{i}.example")
        for i in range(n)
    )


def make_config(**overrides) -> ElectionConfig:
    base = dict(
        election_id=b"\x11" * 32,
        num_candidates=3,
        budget=1,
        mode=Mode.EXACT,
        variant=Variant.A,
        weighted=False,
        duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000,
        voting_end=2_000,
        threshold=Threshold(t=2, n=3),
        keypers=_keypers(3),
        eligibility_key=b"\xe1" * 48,
        result_publisher_key=b"\xa1" * 20,
        gateway_keys=(b"\x91" * 20,),
        admin_key=b"\xad" * 20,
        protocol_version="SHUTTER-VOTE-v1",
    )
    base.update(overrides)
    return ElectionConfig(**base)


def test_valid_config_constructs():
    cfg = make_config()
    assert cfg.threshold.t == 2 and cfg.threshold.n == 3
    assert len(cfg.keypers) == 3


def test_conformance_level_1_defaults():
    """Level 1 = variant A / exact / weighted-capable."""
    cfg = make_config(weighted=True)
    assert (cfg.variant, cfg.mode, cfg.weighted) == (Variant.A, Mode.EXACT, True)


@pytest.mark.parametrize(
    "overrides,match",
    [
        (dict(num_candidates=0), "at least one candidate"),
        (dict(budget=0), "budget"),
        (dict(voting_start=2_000, voting_end=2_000), "Voting end must be after"),
        (dict(threshold=Threshold(t=2, n=3), keypers=_keypers(2)), "exactly 3 keypers"),
    ],
)
def test_invalid_config_rejected(overrides, match):
    with pytest.raises(ValueError, match=match):
        make_config(**overrides)


@pytest.mark.parametrize(
    "t,n",
    # t IS the quorum, so the range is 1 <= t <= n: a quorum of 0 is meaningless and a
    # quorum above n can never be met.
    [(0, 3), (4, 3), (-1, 3), (1, 0)],
)
def test_invalid_threshold_rejected(t, n):
    with pytest.raises(ValueError):
        Threshold(t=t, n=n)


@pytest.mark.parametrize("t,n", [(1, 2), (1, 3), (2, 4), (2, 5), (3, 7), (1, 100)])
def test_non_majority_threshold_rejected(t, n):
    """The quorum must be a strict majority (t > n/2).

    2-of-5 is a *subset*, not a quorum: two disjoint groups of 2 fit in 5, so each could
    claim it. Since this same count decides agreement — which DKG result and which
    aggregate are canonical — a non-majority leaves the winner to iteration order.
    """
    with pytest.raises(ValueError, match="majority"):
        Threshold(t=t, n=n)


@pytest.mark.parametrize("t,n", [(1, 1), (2, 3), (3, 3), (3, 4), (3, 5), (5, 5), (4, 7)])
def test_majority_threshold_accepted(t, n):
    """Every strict majority, including unanimity (t == n) and the minimum majority."""
    assert Threshold(t=t, n=n).quorum == t
    assert t * 2 > n


@pytest.mark.parametrize("n,minimum", [(1, 1), (2, 2), (3, 2), (4, 3), (5, 3), (6, 4), (7, 4)])
def test_minimum_majority_is_floor_n_over_2_plus_1(n, minimum):
    """The boundary, pinned per committee size: `minimum` is legal, one less is not."""
    assert Threshold(t=minimum, n=n).t == minimum
    if minimum - 1 >= 1:
        with pytest.raises(ValueError, match="majority"):
            Threshold(t=minimum - 1, n=n)


def test_duplicate_keyper_signing_key_rejected():
    """Two committee entries with the same address are the same keyper (e.g. two URLs
    resolving to one keyper's /status identity) and must be rejected."""
    dup = (
        KeyperIdentity(signing_key=b"\x07" * 20, url="https://a.example"),
        KeyperIdentity(signing_key=b"\x07" * 20, url="https://b.example"),
        KeyperIdentity(signing_key=b"\x08" * 20, url="https://c.example"),
    )
    with pytest.raises(ValueError, match="Duplicate keyper"):
        make_config(keypers=dup)


def test_duplicate_keyper_url_allowed():
    """URLs are not deduped at the config level: in-process deployments leave them
    empty (duplicate-URL rejection is a frontend UX guard, not a protocol invariant)."""
    same_url = tuple(
        KeyperIdentity(signing_key=bytes([i + 1]) * 20, url="") for i in range(3)
    )
    cfg = make_config(keypers=same_url)
    assert len(cfg.keypers) == 3


def test_threshold_t_is_the_quorum():
    """(t, n): any ``t`` of ``n`` can decrypt — ``t`` IS the quorum.

    Pins the semantics this codebase now shares with the chain: the number in the config
    is the number of keypers you need, with no ±1 anywhere. The implied Feldman
    polynomial is degree ``t-1`` (``t`` coefficients, so ``t`` shares interpolate it).
    """
    th = Threshold(t=2, n=3)
    assert th.t == 2 and th.quorum == 2 and th.n == 3
    assert th.polynomial_degree == 1


# --------------------------------------------------------------------------- #
#  Ballot / tally feasibility bounds
# --------------------------------------------------------------------------- #
#
# A config that registers cleanly but makes every ballot unusable is the failure these ceilings prevent.
# Three independent ceilings, each catching configs the others let through.

def test_encoding_limit_rejects_candidates_above_two_bytes():
    with pytest.raises(ValueError, match="Too many candidates"):
        make_config(num_candidates=0x1_0000, budget=1)


def test_encoding_limit_on_budget_is_0xFFFE_not_0xFFFF():
    """Off-by-one in the finding *and* in the crypto layer: the proof encodes
    `branch_count = budget + 1` as two bytes, so 0xFFFF overflows the encoder. Accepting it
    would swap a clean MALFORMED for an uncaught OverflowError."""
    with pytest.raises(ValueError, match="Budget too large"):
        make_config(num_candidates=1, budget=0xFFFF)
    # And the encoder confirms why.
    with pytest.raises(OverflowError):
        (0xFFFF + 1).to_bytes(2, "big")
    (0xFFFE + 1).to_bytes(2, "big")  # the real ceiling encodes fine


def test_verification_cost_limit_catches_what_the_encoding_limit_misses():
    at_limit = ElectionConfig.MAX_PROOF_BRANCHES
    cfg_ok = make_config(num_candidates=1, budget=at_limit - 1)         # exactly at the line
    assert cfg_ok.num_candidates * (cfg_ok.budget + 1) == at_limit
    with pytest.raises(ValueError, match="too expensive to tally"):
        make_config(num_candidates=3, budget=60_000)
    with pytest.raises(ValueError, match="too expensive to tally"):
        make_config(num_candidates=1, budget=at_limit)                  # one branch over

    # The real target shape must fit: 20 candidates at budget 100.
    make_config(num_candidates=20, budget=100, weighted=True)


def test_at_most_counts_the_budget_proof_branches_too():
    """An atMost ballot proves its sum with another (budget + 1)-branch OR proof, so it
    costs (candidates + 1) x (budget + 1) branches to verify, not candidates x (budget + 1)."""
    from shutter_governance_protocol.core.config import Mode

    make_config(num_candidates=24, budget=103)                          # 2496 branches exact
    with pytest.raises(ValueError, match="too expensive to tally"):
        make_config(num_candidates=24, budget=103, mode=Mode.AT_MOST)   # 2600 with the sum proof
    make_config(num_candidates=24, budget=99, mode=Mode.AT_MOST)        # 2500: at the line


def test_ordinary_election_shapes_still_construct():
    for nc, budget in ((3, 3), (10, 10), (100, 9), (2, 400)):
        make_config(num_candidates=nc, budget=budget)
