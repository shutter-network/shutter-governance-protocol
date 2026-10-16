"""Feldman VSS distributed key generation over G2.

Each keyper draws a random degree-``quorum - 1`` polynomial, publishes Feldman
commitments ``γ_j = c_j·P2``, and hands share ``φ(i)`` to keyper ``i``. In round 2
every keyper checks each received share against the dealer's commitments
(``s_i·P2 == Σ_j i^j·γ_j``) and, if all pass, forms its combined secret share
``msk_j = Σ_k s_j^(k)``. The joint key is ``mpk = Σ_k γ_0^(k) = msk·P2``.

Throughout this module ``quorum`` is the number of keypers required to decrypt — the
config's ``threshold.t``, which *is* the quorum. A quorum of ``q`` implies a
degree-``q-1`` polynomial with ``q`` coefficients, hence exactly ``q`` Feldman
commitments, so that any ``q`` shares Lagrange-interpolate the secret.

A fresh DKG runs per election; there is no long-lived master key.
"""

from __future__ import annotations

from shutter_governance_protocol.crypto.params import CURVE_ORDER
from shutter_governance_protocol.crypto.points import G2, Z2, add, eq, mul, random_scalar


class KeyperDKGState:
    """One keyper's DKG state machine (round1 → round2 → partial_decrypt)."""

    def __init__(self) -> None:
        self.keyper_id: int | None = None
        self.n: int | None = None
        self.quorum: int | None = None
        self.coefficients: list[int] | None = None
        self.commitments: list | None = None  # [γ_0..γ_{quorum-1}] as G2 points
        self.shares_for_others: dict[int, int] = {}
        self.combined_share: int | None = None  # msk_j
        self.public_key_share = None  # msk_j·P2

    def round1(self, keyper_id: int, n: int, quorum: int):
        """Generate polynomial, Feldman commitments, and shares for i = 1..n.

        ``quorum`` keypers must be able to decrypt, so the polynomial has ``quorum``
        coefficients (degree ``quorum - 1``). Returns ``(commitments, shares_dict)``.
        """
        self.keyper_id, self.n, self.quorum = keyper_id, n, quorum
        self.coefficients = [random_scalar() for _ in range(quorum)]
        self.commitments = [mul(G2, c) for c in self.coefficients]
        self.shares_for_others = {}
        for i in range(1, n + 1):
            val, x_power = 0, 1
            for j in range(quorum):
                val = (val + self.coefficients[j] * x_power) % CURVE_ORDER
                x_power = (x_power * i) % CURVE_ORDER
            self.shares_for_others[i] = val
        return self.commitments, self.shares_for_others

    def round2(self, all_commitments: dict, received_shares: dict, dealers=None):
        """Verify received shares (Feldman VSS) and combine into ``msk_j``.

        ``dealers`` is the set of qualified dealers whose contributions make up the key
        (default: every committee member). A dealer excluded for misbehaving is left out
        of both the check and the sum, so its shares are ignored; the caller must build
        the key from the same set (see :func:`qualified`).

        Raises ``ValueError`` with a ``bad_dealers`` attribute listing any dealer that
        published a commitment vector of the wrong length, delivered no usable
        commitments at all, **delivered no share**, or whose share failed
        ``s_i·P2 == Σ_j my_id^j·γ_j`` — the trigger for the signed complaint flow.
        """
        my_id = self.keyper_id
        expected_len = self.quorum
        qualified_dealers = set(range(1, self.n + 1) if dealers is None else dealers)
        received_shares = {d: s for d, s in received_shares.items() if d in qualified_dealers}
        bad_dealers = []
        # Every committee member deals, and the joint key is built from every dealer's
        # commitments. A dealer that publishes commitments but withholds this keyper's
        # share would otherwise be skipped here: this keyper's secret would then lack a
        # contribution that the published key includes, and its decryption shares would
        # never verify. Treat a missing share like a bad one, so it is complained about
        # and repaired before any key is published.
        for dealer_id in sorted(qualified_dealers):
            if dealer_id not in received_shares:
                bad_dealers.append(dealer_id)
        for dealer_id, share in received_shares.items():
            comms = all_commitments.get(dealer_id)
            # A dealer must publish exactly `quorum` commitments (a degree-(quorum-1)
            # polynomial).
            #
            # Too many is an attack: with quorum+1 commitments a dealer can deal a
            # degree-`quorum` polynomial whose shares all still satisfy the Feldman equation
            # below — no complaint is raised, the DKG finalizes, and every decryption-share
            # DLEQ verifies, yet the joint polynomial needs quorum+1 points so NO quorum-sized
            # subset Lagrange-interpolates to the right secret. The election finalizes
            # healthily and is then permanently untalliable. One dealer of n, undetected
            # until tally.
            #
            # Too few is malformed for the mirror reason (a lower-degree contribution).
            # Both are refused here, and unlike a bad share this fault is *publicly*
            # checkable: commitments are broadcast and dealer-signed, so every honest
            # keyper independently reaches the same verdict with no reveal or adjudication.
            # ``None`` means this keyper refused the vector at ingest (or never got one)
            # while the dealer still sent a share — equally disqualifying.
            if comms is None or len(comms) != expected_len:
                bad_dealers.append(dealer_id)
                continue
            if not verify_share(comms, my_id, share):
                bad_dealers.append(dealer_id)
        if bad_dealers:
            bad_dealers = sorted(set(bad_dealers))
            err = ValueError(f"Keyper {my_id}: Feldman VSS failed for dealers {bad_dealers}")
            err.bad_dealers = bad_dealers
            raise err

        self.combined_share = sum(received_shares.values()) % CURVE_ORDER
        self.public_key_share = mul(G2, self.combined_share)
        return self.combined_share, self.public_key_share

    def zeroize_dealing(self) -> None:
        """Drop this dealer's polynomial and outbound shares.

        Called once the ceremony no longer needs them — i.e. at publish, after any
        complaint has had its chance to be repaired. Idempotent. ``combined_share`` (this
        keyper's own long-lived secret) is deliberately untouched: it is what decryption
        needs, and it is persisted encrypted at rest.
        """
        self.coefficients = None
        self.shares_for_others = {}

    def partial_decrypt(self, C1):
        """Partial decryption share ``σ_j = msk_j·C1`` (G2 point)."""
        if self.combined_share is None:
            raise RuntimeError("DKG not completed; cannot decrypt")
        return mul(C1, self.combined_share)


def verify_share(commitments: list, recipient_index: int, share: int) -> bool:
    """Feldman check for one dealt share: ``share·P2 == Σ_j recipient^j·γ_j``.

    Shared by round 2 and by the replacement-share path, so a repaired share is held to
    exactly the same standard as the original — a dealer cannot use the repair channel to
    slip in a share that would not have passed first time.
    """
    expected, x_power = Z2, 1
    for c in commitments:
        expected = add(expected, mul(c, x_power))
        x_power = (x_power * recipient_index) % CURVE_ORDER
    return eq(expected, mul(G2, share))


def qualified(all_commitments: dict, excluded) -> dict:
    """The commitments of the dealers that were not excluded.

    The joint key and every committee key are sums over dealers, so building both from
    this subset drops an excluded dealer's contribution entirely. The dealer stays a
    committee *member*: it still holds a valid combined share from the other dealers'
    shares, and its committee key is still derived (see :func:`committee_keys`).
    """
    return {d: c for d, c in all_commitments.items() if d not in set(excluded)}


def committee_keys(n: int, all_commitments: dict, quorum: int) -> list:
    """``committee_pks`` for members ``1..n``, from the given dealers' commitments.

    Indexed by member, not by dealer: with a dealer excluded there are fewer dealers
    than members, and every member still needs its entry at ``index - 1``.
    """
    return [derive_mpk_share(i, all_commitments, quorum) for i in range(1, n + 1)]


def check_commitment_lengths(all_commitments: dict, quorum: int) -> None:
    """Reject any dealer not publishing exactly ``quorum`` Feldman commitments.

    ``quorum`` is required rather than inferred: inferring the expected length from the
    vectors themselves would accept a committee where *every* dealer agreed on a
    degree other than ``quorum - 1``. Raises ``ValueError`` with a ``bad_dealers``
    attribute, matching :meth:`KeyperDKGState.round2`.

    This is the last gate before a joint key is derived and published. Round 2 already
    refuses such a dealer, so reaching here means a caller assembled commitments by some
    other route — the derived key would silently encode a higher-degree polynomial that
    no quorum-sized subset can ever decrypt.
    """
    bad_dealers = sorted(d for d, c in all_commitments.items() if len(c) != quorum)
    if bad_dealers:
        err = ValueError(
            f"dealers {bad_dealers} published a commitment vector of the wrong length "
            f"(expected {quorum} for a degree-{quorum - 1} polynomial)"
        )
        err.bad_dealers = bad_dealers
        raise err


def derive_joint_mpk(all_commitments: dict, quorum: int):
    """Joint master public key ``mpk = Σ_dealer γ_0^(dealer)``.

    ``quorum`` is the number of keypers required to decrypt; every dealer must have
    published exactly ``quorum`` commitments (see :func:`check_commitment_lengths`).
    """
    check_commitment_lengths(all_commitments, quorum)
    mpk = Z2
    for dealer_id in sorted(all_commitments):
        mpk = add(mpk, all_commitments[dealer_id][0])
    return mpk


def derive_mpk_share(target_keyper_id: int, all_commitments: dict, quorum: int):
    """Per-keyper public share ``mpk_target = Σ_dealer Σ_j target^j·γ_j^(dealer)``.

    This is what is published on the data layer as
    ``committee_pks[target_keyper_id - 1]``.
    """
    check_commitment_lengths(all_commitments, quorum)
    mpk_share = Z2
    for dealer_id in sorted(all_commitments):
        comms = all_commitments[dealer_id]
        x_power = 1
        for j in range(len(comms)):
            mpk_share = add(mpk_share, mul(comms[j], x_power))
            x_power = (x_power * target_keyper_id) % CURVE_ORDER
    return mpk_share
