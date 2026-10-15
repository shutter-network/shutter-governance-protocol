"""Reusable ``ElectionDataLayer`` conformance suite.

``DataLayerConformance`` is a base class of behavioural tests for the port
contract — ordering, immutability, the finalization quorum rule, the authz
matrix, idempotent shares, and public reads. Every adapter subclasses it and
supplies a ``backend`` fixture; it is correct iff it passes these unmodified.

The suite is abstracted over **two seams** so the *same assertions* run against
backends with different authorization and time models:

* **Authorization** — a write is issued through ``backend.dl(role)`` (the adapter
  authorized to act as ``role``) with ``backend.sig(role, op)`` (the credential to
  pass). Signature-checking backends (in-memory, database) return one adapter and
  real Schnorr request signatures; the chain backend returns a per-actor adapter
  bound to that role's Ethereum key and an empty sig.
* **Time** — ``backend.set_time(t)`` advances the backend's clock (a ``ManualClock``
  for memory/DB; an Anvil warp for chain).

Artifacts are well-formed but not crypto-valid — the data layer performs no proof
verification (availability only), so structural artifacts exercise the contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import pytest

from shutter_governance_protocol.core import authz

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.envelopes.types import (
    AggregateArtifact,
    Attestation,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
    ResultArtifact,
)
from shutter_governance_protocol.ports.data_layer import ImmutabilityError, VotingWindowError, WriteAuthorizationError

# Election ids are registry-assigned sequential values; a fresh backend per test
# means the first (and usually only) registration is id 1.
ELECTION_ID = (1).to_bytes(32, "big")
N, T = 3, 2  # 2-of-3: T is the quorum
NUM_CANDIDATES, BUDGET = 3, 3


def _b(size: int, fill: int) -> bytes:
    return bytes([fill % 256]) * size


class ManualClock:
    def __init__(self, t: int = 0):
        self.t = t

    def __call__(self) -> int:
        return self.t

    def set(self, t: int) -> None:
        self.t = t


# --------------------------------------------------------------------------- #
#  Backend seam
# --------------------------------------------------------------------------- #

class ConformanceBackend(ABC):
    """The two-seam abstraction the conformance tests drive.

    ``config`` carries backend-appropriate identities. ``dl(role)`` returns the
    adapter authorized to write as ``role`` (``"admin"``, ``"result_publisher"``,
    ``"gateway"``, ``"keyper1".."keyperN"``, ``"outsider"``); ``reader()`` is a
    public read handle. ``sig(role, op)`` is the credential to pass for that write.
    """

    config: ElectionConfig

    @abstractmethod
    def dl(self, role: str): ...

    @abstractmethod
    def reader(self): ...

    @abstractmethod
    def sig(self, role: str, op: str, payload: bytes = b"") -> bytes: ...

    @abstractmethod
    def set_time(self, t: int) -> None: ...

    # -- well-formed dummy artifacts (shared) ------------------------------- #

    def pk_and_committee(self, fill: int = 0xA0):
        return _b(96, fill), [_b(96, fill + 1 + i) for i in range(N)]

    def ballot(self, pseudonym: bytes = b"\x22" * 32) -> BallotEnvelope:
        att = Attestation(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk=_b(48, 0x33),
            weight=1, signature=_b(80, 0x44),
        )
        return BallotEnvelope(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk=_b(48, 0x33),
            ciphertexts=tuple(Ciphertext(c1=_b(96, 1), c2=_b(96, 2)) for _ in range(NUM_CANDIDATES)),
            zk_proof=b"\x01\x02\x03", voter_signature=_b(80, 0x55), attestation=att,
        )

    def aggregate(self, fill: int = 7) -> AggregateArtifact:
        return AggregateArtifact(
            election_id=ELECTION_ID,
            aggregates=tuple(Ciphertext(c1=_b(96, fill), c2=_b(96, fill + 1)) for _ in range(NUM_CANDIDATES)),
            admitted=(0, 1), exclusions=(), total_admitted_weight=2,
        )

    def share(self, keyper_index: int) -> DecryptionShareEnvelope:
        return DecryptionShareEnvelope(
            election_id=ELECTION_ID, keyper_index=keyper_index,
            entries=tuple(DecryptionShareEntry(sigma=_b(96, 9), proof=_b(64, 0x0A)) for _ in range(NUM_CANDIDATES)),
        )

    def result(self) -> ResultArtifact:
        return ResultArtifact(election_id=ELECTION_ID, totals=(1, 1, 1), keyper_indices=(1, 2), bsgs_bound=6)

    def result_sig(self, role: str, result: ResultArtifact | None = None) -> bytes:
        """Result-publisher credential, bound to the totals it publishes.
        Chain ignores it — there `publishResult` is gated on RESULT_PUBLISHER_ROLE."""
        return self.sig(role, "result", write_auth.result_digest(ELECTION_ID, result or self.result()))

    def register_sig(self, role: str) -> bytes:
        """Credential for a register call. The signed config asserts the id it expects
        (the replay guard); signature backends override. Chain ignores it."""
        return self.sig(role, "register")

    def ballot_sig(self, role: str, ballot) -> bytes:
        """Gateway write authorization for a ballot. Chain ignores it —
        there the writer is the transaction sender holding VOTE_PROXY_ROLE."""
        return b""

    def write_ballot(self, role: str, ballot):
        """Submit ``ballot`` as ``role``, carrying that role's write authorization."""
        return self.dl(role).submit_ballot(ELECTION_ID, ballot, self.ballot_sig(role, ballot))

    def register_sig_for(self, role: str, config) -> bytes:
        """Credential for registering ``config`` — which may assert a different id than
        ``self.config`` (used when registering a second election)."""
        return self.register_sig(role)

    def register(self) -> None:
        self.dl("admin").register_election(self.config, self.register_sig("admin"))


# --------------------------------------------------------------------------- #
#  Signature backend (in-memory + database): one adapter, Schnorr request sigs
# --------------------------------------------------------------------------- #

class SignatureBackend(ConformanceBackend):
    """Backend for signature-checking adapters. ``adapter`` uses ``clock``."""

    def __init__(self, adapter, clock: ManualClock):
        from shutter_governance_protocol.core.authz import Signer

        self._adapter = adapter
        self._clock = clock
        self._signers = {
            "admin": Signer.generate(),
            "result_publisher": Signer.generate(),
            "gateway": Signer.generate(),
            "outsider": Signer.generate(),
        }
        for i in range(1, N + 1):
            self._signers[f"keyper{i}"] = Signer.generate()

        self.config = ElectionConfig(
            election_id=ELECTION_ID,
            num_candidates=NUM_CANDIDATES,
            budget=BUDGET,
            mode=Mode.EXACT,
            variant=Variant.A,
            weighted=True,
            
            duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=1_000,
            voting_end=2_000,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(
                KeyperIdentity(signing_key=self._signers[f"keyper{i}"].identity, url=f"http://k{i}")
                for i in range(1, N + 1)
            ),
            eligibility_key=_b(48, 0xE1),
            result_publisher_key=self._signers["result_publisher"].identity,
            gateway_keys=(self._signers["gateway"].identity,),
            admin_key=self._signers["admin"].identity,
            protocol_version="SHUTTER-VOTE-v1",
        )

    def dl(self, role: str):
        return self._adapter

    def reader(self):
        return self._adapter

    def sig(self, role: str, op: str, payload: bytes = b"") -> bytes:
        return self._signers[role].sign(op, ELECTION_ID, payload)

    def register_sig(self, role: str) -> bytes:
        return self._signers[role].sign_register(self.config)

    def register_sig_for(self, role: str, config) -> bytes:
        return self._signers[role].sign_register(config)

    def ballot_sig(self, role: str, ballot) -> bytes:
        return write_auth.sign_ballot(self._signers[role].private_key, ELECTION_ID, ballot)

    def dkg_sig(self, role: str, pk: bytes, committee: list[bytes]) -> bytes:
        return write_auth.sign_dkg_result(self._signers[role].private_key, ELECTION_ID, pk, committee)

    def share_sig(self, role: str, share) -> bytes:
        sigmas = [e.sigma for e in share.entries]
        proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
        return write_auth.sign_decryption_share(self._signers[role].private_key, ELECTION_ID, sigmas, proofs)

    def aggregate_sig(self, role: str, aggregate) -> bytes:
        return write_auth.sign_aggregate(self._signers[role].private_key, ELECTION_ID, aggregate)

    def set_time(self, t: int) -> None:
        self._clock.set(t)


# --------------------------------------------------------------------------- #
#  Conformance behaviours
# --------------------------------------------------------------------------- #

class DataLayerConformance:
    """Behavioural conformance tests. Subclasses provide the ``backend`` fixture."""

    # -- lifecycle + authz -------------------------------------------------- #

    def test_register_and_get_round_trip(self, backend):
        backend.register()
        rec = backend.reader().get_election(ELECTION_ID)
        assert rec.config.election_id == ELECTION_ID
        assert rec.cancelled is False
        assert rec.finalized_key is None

    def test_register_rejects_unauthorized_writer(self, backend):
        with pytest.raises(WriteAuthorizationError):
            backend.dl("result_publisher").register_election(backend.config, backend.register_sig("result_publisher"))

    def test_register_assigns_sequential_ids(self, backend):
        # Ids are backend-assigned (registry-style), so each call yields a new id — but the
        # signed config asserts the id it expects, so a second election must be signed for
        # the NEXT id rather than reusing the first body.
        from dataclasses import replace

        eid1 = backend.dl("admin").register_election(backend.config, backend.register_sig("admin"))
        cfg2 = replace(backend.config, election_id=(2).to_bytes(32, "big"))
        eid2 = backend.dl("admin").register_election(cfg2, backend.register_sig_for("admin", cfg2))
        assert eid1 == (1).to_bytes(32, "big")
        assert eid2 == (2).to_bytes(32, "big")

    def test_register_body_cannot_be_replayed(self, backend):
        """A captured registration is single-use. Once it lands the sequence moves on,
        so re-sending the identical (validly signed) body can never register again — no
        duplicate-election spam, and on chain no gas spent replaying it."""
        backend.register()
        with pytest.raises(ImmutabilityError):
            backend.dl("admin").register_election(backend.config, backend.register_sig("admin"))
        assert backend.reader().list_elections() == [ELECTION_ID]

    def test_list_elections_and_filter(self, backend):
        from shutter_governance_protocol.ports.data_layer import ElectionFilter

        backend.register()
        assert ELECTION_ID in backend.reader().list_elections()
        assert backend.reader().list_elections(ElectionFilter(admin_key=backend.config.admin_key)) == [ELECTION_ID]
        assert backend.reader().list_elections(ElectionFilter(admin_key=b"\x00" * len(backend.config.admin_key))) == []

    def test_cancel_before_start_ok(self, backend):
        backend.register()
        backend.set_time(500)
        backend.dl("admin").cancel_election(ELECTION_ID, backend.sig("admin", "cancel"))
        assert backend.reader().get_election(ELECTION_ID).cancelled is True

    def test_cancel_after_start_rejected(self, backend):
        backend.register()
        backend.set_time(1_000)
        with pytest.raises(ImmutabilityError):
            backend.dl("admin").cancel_election(ELECTION_ID, backend.sig("admin", "cancel"))

    def test_cancel_unauthorized_rejected(self, backend):
        backend.register()
        backend.set_time(500)
        with pytest.raises(WriteAuthorizationError):
            backend.dl("result_publisher").cancel_election(ELECTION_ID, backend.sig("result_publisher", "cancel"))

    # -- ballots: ordering, sequence, pagination --------------------------- #

    def _open_voting(self, backend, now: int = 1_500):
        """Reach derived state ``Voting`` — the precondition for a ballot write.

        Every backend now gates ``submit_ballot`` on the chain contract's
        ``submitVote`` gate set (not cancelled + DKG finalized + inside the half-open
        window), so a ballot write needs a finalized key and a clock in
        ``[voting_start, voting_end)``.
        """
        pk, committee = backend.pk_and_committee()
        for role in ("keyper1", "keyper2"):
            backend.dl(role).submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig(role, pk, committee))
        assert backend.reader().get_finalized_key(ELECTION_ID) is not None
        backend.set_time(now)

    def test_ballot_ordering_and_monotonic_sequence(self, backend):
        backend.register()
        self._open_voting(backend)
        seqs = [backend.write_ballot("gateway", backend.ballot(bytes([i]) * 32)) for i in range(5)]
        assert seqs == [0, 1, 2, 3, 4]
        assert backend.reader().count_ballots(ELECTION_ID) == 5
        listed = backend.reader().list_ballots(ELECTION_ID, 0, 5)
        assert [sb.envelope.pseudonym for sb in listed] == [bytes([i]) * 32 for i in range(5)]
        assert [sb.sequence_number for sb in listed] == [0, 1, 2, 3, 4]

    def test_ballot_pagination(self, backend):
        backend.register()
        self._open_voting(backend)
        for i in range(5):
            backend.write_ballot("gateway", backend.ballot(bytes([i]) * 32))
        page = backend.reader().list_ballots(ELECTION_ID, 2, 2)
        assert [sb.envelope.pseudonym for sb in page] == [bytes([2]) * 32, bytes([3]) * 32]
        assert [sb.sequence_number for sb in page] == [2, 3]

    def test_ballot_write_requires_an_authorized_gateway(self, backend):
        """With a non-empty ``gateway_keys`` the writer set is a real restriction.

        Previously the port carried no signature at all, so a deployer could configure
        ``gateway_keys`` and have it silently ignored on this backend while the chain
        enforced it — anyone reaching the data layer could write ballots directly,
        bypassing the ingress filter (and its replay check).
        """
        backend.register()
        self._open_voting(backend)
        b = backend.ballot(bytes([9]) * 32)

        # An unauthorized signer is refused ...
        with pytest.raises(WriteAuthorizationError):
            backend.dl("gateway").submit_ballot(ELECTION_ID, b, backend.ballot_sig("outsider", b))
        # ... as is a missing signature ...
        with pytest.raises(WriteAuthorizationError):
            backend.dl("gateway").submit_ballot(ELECTION_ID, b, b"")
        assert backend.reader().count_ballots(ELECTION_ID) == 0
        # ... while the registered gateway key is accepted.
        assert backend.write_ballot("gateway", b) == 0

    def test_gateway_signature_is_bound_to_the_ballot(self, backend):
        """The signature authorizes *these bytes*, so a relayed write cannot have its
        ballot swapped in flight for another one the gateway never saw."""
        backend.register()
        self._open_voting(backend)
        signed = backend.ballot(bytes([1]) * 32)
        other = backend.ballot(bytes([2]) * 32)
        with pytest.raises(WriteAuthorizationError):
            backend.dl("gateway").submit_ballot(ELECTION_ID, other, backend.ballot_sig("gateway", signed))

    # -- ballots: the voting-window gate (parity with the chain contract) --- #

    def test_ballot_before_voting_start_rejected(self, backend):
        backend.register()
        self._open_voting(backend, now=999)  # key finalized, but window not yet open
        with pytest.raises(VotingWindowError):
            backend.write_ballot("gateway", backend.ballot(bytes([1]) * 32))

    def test_ballot_after_voting_end_rejected(self, backend):
        backend.register()
        self._open_voting(backend, now=2_000)  # half-open: voting_end itself is closed
        with pytest.raises(VotingWindowError):
            backend.write_ballot("gateway", backend.ballot(bytes([1]) * 32))

    def test_ballot_before_dkg_finalized_rejected(self, backend):
        backend.register()
        backend.set_time(1_500)  # inside the window, but no finalized key
        with pytest.raises(VotingWindowError):
            backend.write_ballot("gateway", backend.ballot(bytes([1]) * 32))

    def test_stored_ballot_carries_receive_time(self, backend):
        """The adapter records its authoritative receive time, so the tally-time
        OUT_OF_WINDOW check has something to verify against."""
        backend.register()
        self._open_voting(backend, now=1_500)
        backend.write_ballot("gateway", backend.ballot(bytes([1]) * 32))
        [sb] = backend.reader().list_ballots(ELECTION_ID, 0, 1)
        assert sb.submitted_at is not None
        assert backend.config.voting_start <= sb.submitted_at < backend.config.voting_end

    # -- DKG finalization quorum rule -------------------------------------- #

    def test_dkg_finalizes_at_quorum(self, backend):
        backend.register()
        pk, committee = backend.pk_and_committee()
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        assert backend.reader().get_finalized_key(ELECTION_ID) is None  # 1 < t+1
        backend.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper2", pk, committee))
        fk = backend.reader().get_finalized_key(ELECTION_ID)
        assert fk is not None and fk.pk_election == pk

    def test_dkg_divergent_submissions_do_not_finalize(self, backend):
        backend.register()
        pk_a, com_a = backend.pk_and_committee(0xA0)
        pk_b, com_b = backend.pk_and_committee(0xB0)
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk_a, com_a, backend.dkg_sig("keyper1", pk_a, com_a))
        backend.dl("keyper2").submit_dkg_result(ELECTION_ID, pk_b, com_b, backend.dkg_sig("keyper2", pk_b, com_b))
        assert backend.reader().get_finalized_key(ELECTION_ID) is None

    def test_dkg_non_keyper_rejected(self, backend):
        backend.register()
        pk, committee = backend.pk_and_committee()
        with pytest.raises(WriteAuthorizationError):
            backend.dl("outsider").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("outsider", pk, committee))

    def test_dkg_append_only_per_dealer(self, backend):
        backend.register()
        pk, committee = backend.pk_and_committee()
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        # Identical resend: no-op.
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        # Different submission from same dealer: rejected.
        pk2, com2 = backend.pk_and_committee(0xC0)
        with pytest.raises(ImmutabilityError):
            backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk2, com2, backend.dkg_sig("keyper1", pk2, com2))
        assert len(backend.reader().get_dkg_submissions(ELECTION_ID)) == 1

    def test_dkg_vote_after_voting_start_rejected(self, backend):
        """A late vote could finalize the key of an election that had already failed
        (DKGFailed) for lack of one. An identical resend stays a no-op."""
        backend.register()
        pk, committee = backend.pk_and_committee()
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        backend.set_time(backend.config.voting_start)
        with pytest.raises(VotingWindowError):
            backend.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper2", pk, committee))
        assert backend.reader().get_finalized_key(ELECTION_ID) is None

    # -- decryption shares: authz + idempotency ---------------------------- #

    def _finalize_aggregate(self, backend):
        """Advance past voting_end and reach the t+1 quorum on a canonical aggregate
        (keyper1 + keyper2 submit an identical artifact) — the precondition for shares."""
        backend.set_time(2_001)
        agg = backend.aggregate()
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg

    def test_share_submit_and_idempotent_resend(self, backend):
        backend.register()
        self._finalize_aggregate(backend)  # decryption shares require a canonical aggregate
        share = backend.share(1)
        backend.dl("keyper1").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper1", share))
        backend.dl("keyper1").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper1", share))
        assert len(backend.reader().list_decryption_shares(ELECTION_ID)) == 1

    def test_share_non_keyper_rejected(self, backend):
        backend.register()
        self._finalize_aggregate(backend)  # pass the ordering gates so the authz check is reached
        share = backend.share(1)
        with pytest.raises(WriteAuthorizationError):
            backend.dl("result_publisher").submit_decryption_share(ELECTION_ID, share, backend.share_sig("result_publisher", share))

    def test_share_keyper_index_must_match_signer(self, backend):
        backend.register()
        self._finalize_aggregate(backend)  # pass the ordering gates so the authz check is reached
        share = backend.share(1)  # claims keyper_index 1
        with pytest.raises(WriteAuthorizationError):
            # signed by keyper 2 but the envelope claims keyper_index 1
            backend.dl("keyper2").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper2", share))

    # -- aggregate + result ------------------------------------------------- #

    def test_aggregate_none_before_publish(self, backend):
        backend.register()
        assert backend.reader().get_aggregate(ELECTION_ID) is None

    # -- ordering guards: no tally artifact before voting_end (parity with chain) -- #

    def test_aggregate_before_voting_end_rejected(self, backend):
        backend.register()  # clock defaults to 0 < voting_end (2000)
        agg = backend.aggregate()
        with pytest.raises(VotingWindowError):
            backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))

    def test_decryption_share_before_voting_end_rejected(self, backend):
        backend.register()
        share = backend.share(1)
        with pytest.raises(VotingWindowError):
            backend.dl("keyper1").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper1", share))

    def test_decryption_share_before_aggregate_rejected(self, backend):
        backend.register()
        backend.set_time(2_001)  # past voting_end, but no canonical aggregate published yet
        share = backend.share(1)
        with pytest.raises(VotingWindowError):
            backend.dl("keyper1").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper1", share))

    def test_aggregate_quorum_authz_and_idempotent(self, backend):
        backend.register()
        backend.set_time(2_001)  # tally artifacts require voting_end (2000) passed
        agg = backend.aggregate()

        # Non-keyper (result_publisher) cannot submit the aggregate — it is a keyper write now.
        with pytest.raises(WriteAuthorizationError):
            backend.dl("result_publisher").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("result_publisher", agg))

        # One keyper is not a quorum (t+1 = 2): not yet canonical.
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) is None
        # Identical resend by the same keyper: no-op.
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) is None

        # A byte-identical submission from a second keyper reaches the quorum → canonical.
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg

    def test_aggregate_keyper_can_override_until_finalized(self, backend):
        backend.register()
        backend.set_time(2_001)  # tally artifacts require voting_end (2000) passed
        agg = backend.aggregate()
        other = backend.aggregate(fill=0x50)
        assert agg != other
        # A keyper may correct a wrong/stale submission while the aggregate is not yet
        # canonical (deterministic re-derivation → honest keypers re-converge).
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper1", other))
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))  # override
        assert backend.reader().get_aggregate(ELECTION_ID) is None  # still 1 vote for agg
        # keyper2 agrees with keyper1's (overridden) aggregate → quorum → canonical.
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg
        # Once finalized, further submissions (even overrides) are frozen out.
        with pytest.raises(ImmutabilityError):
            backend.dl("keyper3").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper3", other))

    def test_aggregate_divergent_submissions_do_not_finalize(self, backend):
        backend.register()
        backend.set_time(2_001)  # tally artifacts require voting_end (2000) passed
        agg = backend.aggregate()
        other = backend.aggregate(fill=0x50)
        # Two keypers disagree → neither artifact has a t+1 quorum.
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper2", other))
        assert backend.reader().get_aggregate(ELECTION_ID) is None
        # keyper2 overrides to agree with keyper1 → quorum on that artifact.
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg

    # -- tally-stalled advisory flag (recoverable) -------------------------- #
    #
    # These writes bind no content -- they toggle a flag -- so the signature carries a
    # timestamp and the backend spends it once.  keeps the signed value and
    # the passed value the same; they are two halves of one claim and a test that let
    # them drift would be asserting nothing.

    @staticmethod
    def _stall(backend, role: str, op: str, stalled: bool, at: int) -> None:
        payload = authz.request_nonce_payload(at)
        backend.dl(role).set_tally_stalled(ELECTION_ID, stalled, backend.sig(role, op, payload), at)

    def test_tally_stalled_marked_by_publisher_cleared_by_admin(self, backend):
        backend.register()
        backend.set_time(2_001)  # past voting_end
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is False
        # MARK — result publisher (the coordinator) only.
        self._stall(backend, "result_publisher", "tally_stall", True, 2_001)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is True
        # CLEAR (retry) — the election admin only.
        self._stall(backend, "admin", "tally_resume", False, 2_001)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is False

    def test_tally_mark_requires_result_publisher(self, backend):
        backend.register()
        backend.set_time(2_001)
        with pytest.raises(WriteAuthorizationError):  # admin cannot mark
            self._stall(backend, "admin", "tally_stall", True, 2_001)
        with pytest.raises(WriteAuthorizationError):  # a keyper cannot mark
            self._stall(backend, "keyper1", "tally_stall", True, 2_001)

    def test_tally_clear_requires_admin(self, backend):
        backend.register()
        backend.set_time(2_001)
        self._stall(backend, "result_publisher", "tally_stall", True, 2_001)
        # The result publisher (coordinator) cannot clear — clearing is admin-only.
        with pytest.raises(WriteAuthorizationError):
            self._stall(backend, "result_publisher", "tally_resume", False, 2_001)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is True  # still stalled

    # -- replay rejection (M-1) --------------------------------------------- #

    def test_tally_stall_signature_cannot_be_replayed(self, backend):
        """The whole point of the timestamp: one signature, one use.

        Signing is RFC 6979 deterministic, so a re-signed stall at the same timestamp is
        byte-identical to a captured one — which is exactly what an attacker replays after
        an admin retry. Rejecting it is what stops a confidential tally being denied forever.
        """
        backend.register()
        backend.set_time(2_001)
        self._stall(backend, "result_publisher", "tally_stall", True, 2_001)
        self._stall(backend, "admin", "tally_resume", False, 2_001)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is False

        # Replay of the stall, still inside the freshness window.
        with pytest.raises(WriteAuthorizationError):
            self._stall(backend, "result_publisher", "tally_stall", True, 2_001)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is False

        # A genuine re-stall at a new timestamp is still accepted.
        backend.set_time(2_050)
        self._stall(backend, "result_publisher", "tally_stall", True, 2_050)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is True

    def test_tally_stall_rejects_a_stale_timestamp(self, backend):
        """Freshness is what makes a captured signature useless later — the replay that
        matters happens after an admin retry, long after the signature was made."""
        backend.register()
        backend.set_time(10_000)
        with pytest.raises(WriteAuthorizationError):
            self._stall(backend, "result_publisher", "tally_stall", True, 10_000 - 3_600)
        with pytest.raises(WriteAuthorizationError):
            self._stall(backend, "result_publisher", "tally_stall", True, 10_000 + 3_600)
        assert backend.reader().get_election(ELECTION_ID).tally_stalled is False

    def test_result_publish_authz_and_read(self, backend):
        backend.register()
        assert backend.reader().get_result(ELECTION_ID) is None
        with pytest.raises(WriteAuthorizationError):
            backend.dl("admin").publish_result(ELECTION_ID, backend.result(), backend.result_sig("admin"))
        backend.dl("result_publisher").publish_result(ELECTION_ID, backend.result(), backend.result_sig("result_publisher"))
        assert backend.reader().get_result(ELECTION_ID) == backend.result()

    def test_result_signature_is_bound_to_the_totals(self, backend):
        """A result credential must not carry over to *different* totals.

        Before the fix the signature covered only ("result", electionId), so this forged
        artifact — different totals, different credited keypers, different bound — was
        accepted under a signature taken over the honest one.
        """
        backend.register()
        honest = backend.result()
        forged = ResultArtifact(
            election_id=ELECTION_ID, totals=(6, 0, 0), keyper_indices=(1, 3), bsgs_bound=6
        )
        assert forged != honest
        credential_for_honest = backend.result_sig("result_publisher", honest)
        with pytest.raises(WriteAuthorizationError):
            backend.dl("result_publisher").publish_result(ELECTION_ID, forged, credential_for_honest)
        assert backend.reader().get_result(ELECTION_ID) is None
        # ...and the same credential still authorizes the artifact it was taken over.
        backend.dl("result_publisher").publish_result(ELECTION_ID, honest, credential_for_honest)
        assert backend.reader().get_result(ELECTION_ID) == honest

    # -- capability --------------------------------------------------------- #

    def test_verifiability_tier_is_zero(self, backend):
        assert backend.reader().verifiability_tier() == 0
