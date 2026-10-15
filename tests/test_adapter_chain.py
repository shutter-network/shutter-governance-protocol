"""Chain adapter behavioral conformance (HTTP → Anvil → extended contracts).

The chain is a lifecycle state machine (unlike the availability-only memory/DB
backends), so the shared DataLayerConformance suite can't run verbatim. This
harness asserts the SAME port properties — ordering, immutability, the DKG
quorum rule, the authz matrix (tx-sender), idempotent shares, public reads —
sequenced within a valid on-chain lifecycle. Authorization is per-actor Ethereum
keys; time is Anvil block time.

Skips entirely if the ``anvil`` binary is unavailable.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.envelopes.types import (
    AggregateArtifact,
    Attestation,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
)
from shutter_governance_protocol.ports.data_layer import ImmutabilityError, VotingWindowError, WriteAuthorizationError

# Well-known Anvil dev keys (public test keys — safe to hardcode).
ANVIL_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
]
ELECTION_ID = (1).to_bytes(32, "big")  # registry-assigned first id
N, T, NUM_CANDIDATES, BUDGET = 3, 2, 3, 3  # T = quorum


def _b(size, fill):
    return bytes([fill % 256]) * size


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def anvil():
    if shutil.which("anvil") is None:
        pytest.skip("anvil not installed")
    from web3 import Web3

    port = _free_port()
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--timestamp", "0", "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}"))
    try:
        for _ in range(50):
            if w3.is_connected():
                break
            time.sleep(0.1)
        else:
            pytest.skip("anvil did not start")
        yield w3
    finally:
        proc.terminate()
        proc.wait()


class ChainEnv:
    """Per-test chain fixture: fresh registry + per-actor adapters + eth identities."""

    def __init__(self, w3):
        from eth_account import Account

        from shutter_governance_protocol.adapters.chain.client import BlockchainDataLayer
        from shutter_governance_protocol.adapters.chain.deploy import chain_now, deploy_registry

        self.w3 = w3
        self._Adapter = BlockchainDataLayer
        self.accounts = {
            "admin": Account.from_key(ANVIL_KEYS[0]),
            "result_publisher": Account.from_key(ANVIL_KEYS[1]),
            "gateway": Account.from_key(ANVIL_KEYS[2]),
            "keyper1": Account.from_key(ANVIL_KEYS[3]),
            "keyper2": Account.from_key(ANVIL_KEYS[4]),
            "keyper3": Account.from_key(ANVIL_KEYS[5]),
            "outsider": Account.from_key(ANVIL_KEYS[6]),
        }
        self.registry = deploy_registry(w3, self.accounts["admin"])
        self.base = chain_now(w3)
        self._adapters = {}
        self.config = self._build_config()

    def _addr(self, role):
        return bytes.fromhex(self.accounts[role].address[2:])

    def _build_config(self):
        return ElectionConfig(
            election_id=ELECTION_ID, num_candidates=NUM_CANDIDATES, budget=BUDGET,
            mode=Mode.EXACT, variant=Variant.A, weighted=True,
            duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=self.base + 1000, voting_end=self.base + 2000, threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self._addr(f"keyper{i}"), url=f"http://keyper{i}:8100")
                          for i in range(1, N + 1)),
            eligibility_key=_b(48, 0xE1), result_publisher_key=self._addr("result_publisher"),
            gateway_keys=(self._addr("gateway"),), admin_key=self._addr("admin"), protocol_version="v1",
        )

    def dl(self, role):
        if role not in self._adapters:
            self._adapters[role] = self._Adapter(self.w3, self.registry, self.accounts[role])
        return self._adapters[role]

    def reader(self):
        return self.dl("admin")

    def warp(self, offset):
        from shutter_governance_protocol.adapters.chain.deploy import anvil_set_time

        anvil_set_time(self.w3, self.base + offset)

    # -- artifact builders (well-formed, satisfy contract structural checks) - #

    def pk_and_committee(self, fill=0xA0):
        return _b(96, fill), [_b(96, fill + 1 + i) for i in range(N)]

    def ballot(self, pseudonym):
        att = Attestation(election_id=ELECTION_ID, pseudonym=pseudonym, vk=_b(48, 0x33),
                          weight=1, signature=_b(80, 0x44))
        return BallotEnvelope(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk=_b(48, 0x33),
            ciphertexts=tuple(Ciphertext(c1=_b(96, 1), c2=_b(96, 2)) for _ in range(NUM_CANDIDATES)),
            zk_proof=b"\x01\x02\x03", voter_signature=_b(80, 0x55), attestation=att,
        )

    def aggregate(self):
        return AggregateArtifact(
            election_id=ELECTION_ID,
            aggregates=tuple(Ciphertext(c1=_b(96, 7), c2=_b(96, 8)) for _ in range(NUM_CANDIDATES)),
            admitted=(0, 1), exclusions=(), total_admitted_weight=2,
        )

    def share(self, keyper_index):
        return DecryptionShareEnvelope(
            election_id=ELECTION_ID, keyper_index=keyper_index,
            entries=tuple(DecryptionShareEntry(sigma=_b(96, 9), proof=_b(64, 0x0A)) for _ in range(NUM_CANDIDATES)),
        )

    def _key(self, role) -> int:
        return int.from_bytes(self.accounts[role].key, "big")

    def dkg_sig(self, role, pk, committee) -> bytes:
        from shutter_governance_protocol.core import write_auth
        return write_auth.sign_dkg_result(self._key(role), ELECTION_ID, pk, committee)

    def share_sig(self, role, share) -> bytes:
        from shutter_governance_protocol.core import write_auth
        sigmas = [e.sigma for e in share.entries]
        proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
        return write_auth.sign_decryption_share(self._key(role), ELECTION_ID, sigmas, proofs)

    def aggregate_sig(self, role, aggregate) -> bytes:
        from shutter_governance_protocol.core import write_auth
        return write_auth.sign_aggregate(self._key(role), ELECTION_ID, aggregate)

    def register(self):
        return self.dl("admin").register_election(self.config, b"")

    def finalize_dkg(self):
        pk, committee = self.pk_and_committee()
        self.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, self.dkg_sig("keyper1", pk, committee))
        self.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, self.dkg_sig("keyper2", pk, committee))


@pytest.fixture
def env(anvil):
    return ChainEnv(anvil)


# --------------------------------------------------------------------------- #
#  Lifecycle + authz
# --------------------------------------------------------------------------- #

def test_register_and_get_round_trip(env):
    env.register()
    rec = env.reader().get_election(ELECTION_ID)
    assert rec.config.election_id == ELECTION_ID
    assert rec.cancelled is False
    assert rec.finalized_key is None
    assert rec.config.num_candidates == NUM_CANDIDATES
    # keyper (address, URL) pairs are stored on chain (in the KeyperSet) and read back
    # index-aligned through the port — k_i always pairs with u_i (DKG + decryption).
    assert [(k.signing_key, k.url) for k in rec.config.keypers] == [
        (env._addr(f"keyper{i}"), f"http://keyper{i}:8100") for i in range(1, N + 1)
    ]
    # The quorum-semantics guard: `t` survives a chain round-trip UNCHANGED. `threshold.t` is the
    # quorum and `KeyperSet.getThreshold()` stores the quorum, so deploy and read-back are
    # both straight pass-throughs. This assertion is what would have caught the old
    # arrangement, where a `+1` on write and a `-1` on read cancelled out invisibly — and
    # would catch it again if either half were ever reintroduced alone.
    assert rec.config.threshold.t == T == 2
    assert rec.config.threshold.n == N == 3
    assert rec.config.threshold.quorum == T


def test_register_unauthorized_rejected(env):
    with pytest.raises(WriteAuthorizationError):
        env.dl("result_publisher").register_election(env.config, b"")  # not registry admin


def test_register_assigns_sequential_ids(env):
    # Registry assigns dense sequential ids; each register yields a new election. The
    # config asserts the id it expects, so the second one must be built for id 2 —
    # re-sending the first body is refused (the register replay guard).
    from dataclasses import replace

    assert env.register() == (1).to_bytes(32, "big")
    cfg2 = replace(env.config, election_id=(2).to_bytes(32, "big"))
    assert env.dl("admin").register_election(cfg2, b"") == (2).to_bytes(32, "big")


def test_register_body_cannot_be_replayed(env):
    """On chain: the replay is refused BEFORE any transaction, so a replayer cannot
    drain the admin's gas (the KeyperSet deploy alone would otherwise cost it)."""
    env.register()
    with pytest.raises(ImmutabilityError):
        env.dl("admin").register_election(env.config, b"")
    assert env.reader().list_elections() == [ELECTION_ID]


def test_list_elections_and_filter(env):
    from shutter_governance_protocol.ports.data_layer import ElectionFilter

    env.register()
    assert ELECTION_ID in env.reader().list_elections()
    assert env.reader().list_elections(ElectionFilter(admin_key=env._addr("admin"))) == [ELECTION_ID]
    assert env.reader().list_elections(ElectionFilter(admin_key=env._addr("outsider"))) == []


def test_cancel_before_start_ok(env):
    env.register()
    env.warp(500)
    env.dl("admin").cancel_election(ELECTION_ID, b"")
    assert env.reader().get_election(ELECTION_ID).cancelled is True


def test_cancel_after_start_rejected(env):
    env.register()
    env.warp(1000)
    with pytest.raises(ImmutabilityError):
        env.dl("admin").cancel_election(ELECTION_ID, b"")


def test_cancel_unauthorized_rejected(env):
    env.register()
    env.warp(500)
    with pytest.raises(WriteAuthorizationError):
        env.dl("result_publisher").cancel_election(ELECTION_ID, b"")


# --------------------------------------------------------------------------- #
#  DKG finalization quorum rule
# --------------------------------------------------------------------------- #

def test_dkg_finalizes_at_quorum(env):
    env.register()
    pk, committee = env.pk_and_committee()
    env.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper1", pk, committee))
    assert env.reader().get_finalized_key(ELECTION_ID) is None  # 1 < t+1
    env.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper2", pk, committee))
    fk = env.reader().get_finalized_key(ELECTION_ID)
    assert fk is not None and fk.pk_election == pk


def test_dkg_divergent_does_not_finalize(env):
    env.register()
    pk_a, com_a = env.pk_and_committee(0xA0)
    pk_b, com_b = env.pk_and_committee(0xB0)
    env.dl("keyper1").submit_dkg_result(ELECTION_ID, pk_a, com_a, env.dkg_sig("keyper1", pk_a, com_a))
    env.dl("keyper2").submit_dkg_result(ELECTION_ID, pk_b, com_b, env.dkg_sig("keyper2", pk_b, com_b))
    assert env.reader().get_finalized_key(ELECTION_ID) is None


def test_dkg_non_keyper_rejected(env):
    env.register()
    pk, committee = env.pk_and_committee()
    with pytest.raises((WriteAuthorizationError, ImmutabilityError)):
        env.dl("outsider").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("outsider", pk, committee))


def test_dkg_append_only_per_dealer(env):
    env.register()
    pk, committee = env.pk_and_committee()
    env.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper1", pk, committee))
    env.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper1", pk, committee))  # identical → no-op
    pk2, com2 = env.pk_and_committee(0xC0)
    with pytest.raises(ImmutabilityError):
        env.dl("keyper1").submit_dkg_result(ELECTION_ID, pk2, com2, env.dkg_sig("keyper1", pk2, com2))
    assert len(env.reader().get_dkg_submissions(ELECTION_ID)) == 1


# --------------------------------------------------------------------------- #
#  Ballots (lifecycle: DKG finalized + voting open)
# --------------------------------------------------------------------------- #

def test_ballot_ordering_and_pagination(env):
    env.register()
    env.finalize_dkg()
    env.warp(1500)  # voting open
    seqs = [env.dl("gateway").submit_ballot(ELECTION_ID, env.ballot(bytes([i + 1]) * 32)) for i in range(5)]
    assert seqs == [0, 1, 2, 3, 4]
    assert env.reader().count_ballots(ELECTION_ID) == 5
    page = env.reader().list_ballots(ELECTION_ID, 2, 2)
    assert [sb.envelope.pseudonym for sb in page] == [bytes([3]) * 32, bytes([4]) * 32]
    assert [sb.sequence_number for sb in page] == [2, 3]
    # Block time is the one adversarially authoritative receive time in the system.
    # (The chain env uses absolute unix timestamps offset from env.base.)
    assert all(env.base + 1_000 <= sb.submitted_at < env.base + 2_000 for sb in page)


def test_writes_outside_voting_window_raise_voting_window_error(env):
    env.register()
    env.finalize_dkg()
    agg = env.aggregate()
    # Warps must be monotonic (Anvil rejects a past timestamp), so walk the lifecycle
    # forward: before start → during voting → after end.
    env.warp(500)  # before voting_start
    with pytest.raises(VotingWindowError):  # ballot too early → VotingNotStarted
        env.dl("gateway").submit_ballot(ELECTION_ID, env.ballot(b"\x01" * 32))
    env.warp(1500)  # voting open, before voting_end
    with pytest.raises(VotingWindowError):  # tally write too early → VotingStillOpen
        env.dl("keyper1").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("keyper1", agg))
    env.warp(2500)  # after voting_end
    with pytest.raises(VotingWindowError):  # ballot too late → VotingClosed
        env.dl("gateway").submit_ballot(ELECTION_ID, env.ballot(b"\x02" * 32))


def test_ballot_attestation_round_trips_through_wrattestation(env):
    env.register()
    env.finalize_dkg()
    env.warp(1500)
    env.dl("gateway").submit_ballot(ELECTION_ID, env.ballot(b"\x01" * 32))
    got = env.reader().list_ballots(ELECTION_ID, 0, 1)[0].envelope
    assert got.attestation.weight == 1
    assert got.attestation.election_id == ELECTION_ID


# --------------------------------------------------------------------------- #
#  Decryption shares + aggregate + result (lifecycle: voting ended)
# --------------------------------------------------------------------------- #

def test_share_submit_idempotent_and_authz(env):
    env.register()
    env.finalize_dkg()
    env.warp(2500)  # voting ended
    # Publish a canonical aggregate (t+1 quorum) — precondition for decryption shares.
    agg = env.aggregate()
    env.dl("keyper1").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("keyper1", agg))
    env.dl("keyper2").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("keyper2", agg))
    share1 = env.share(1)
    env.dl("keyper1").submit_decryption_share(ELECTION_ID, share1, env.share_sig("keyper1", share1))
    env.dl("keyper1").submit_decryption_share(ELECTION_ID, share1, env.share_sig("keyper1", share1))  # idempotent
    assert len(env.reader().list_decryption_shares(ELECTION_ID)) == 1
    with pytest.raises(WriteAuthorizationError):
        env.dl("result_publisher").submit_decryption_share(ELECTION_ID, share1, env.share_sig("result_publisher", share1))


def test_share_keyper_index_must_match_signer(env):
    env.register()
    env.finalize_dkg()
    env.warp(2500)
    share1 = env.share(1)  # claims keyper_index 1
    with pytest.raises(WriteAuthorizationError):
        env.dl("keyper2").submit_decryption_share(ELECTION_ID, share1, env.share_sig("keyper2", share1))


def test_aggregate_quorum_authz_idempotent_and_read(env):
    env.register()
    env.finalize_dkg()
    env.warp(2500)
    agg = env.aggregate()
    assert env.reader().get_aggregate(ELECTION_ID) is None

    # Non-keyper signer rejected (aggregate is a keyper write now, meta-tx ecrecover).
    with pytest.raises(WriteAuthorizationError):
        env.dl("result_publisher").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("result_publisher", agg))

    other = AggregateArtifact(
        election_id=ELECTION_ID,
        aggregates=tuple(Ciphertext(c1=_b(96, 0x50), c2=_b(96, 0x51)) for _ in range(NUM_CANDIDATES)),
        admitted=(0, 1), exclusions=(), total_admitted_weight=2,
    )
    # keyper1 submits a wrong aggregate, then OVERRIDES it while not yet canonical.
    env.dl("keyper1").submit_aggregate(ELECTION_ID, other, env.aggregate_sig("keyper1", other))
    env.dl("keyper1").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("keyper1", agg))  # override
    assert env.reader().get_aggregate(ELECTION_ID) is None  # 1 vote for agg, no quorum
    # Identical resend by the same keyper: no-op.
    env.dl("keyper1").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("keyper1", agg))
    assert env.reader().get_aggregate(ELECTION_ID) is None

    # A byte-identical submission from a second keyper reaches quorum → canonical.
    env.dl("keyper2").submit_aggregate(ELECTION_ID, agg, env.aggregate_sig("keyper2", agg))
    assert env.reader().get_aggregate(ELECTION_ID) == agg
    # Frozen after finalization: a different submission can no longer change it.
    with pytest.raises(ImmutabilityError):
        env.dl("keyper3").submit_aggregate(ELECTION_ID, other, env.aggregate_sig("keyper3", other))


def test_result_authz_and_read(env):
    env.register()
    env.finalize_dkg()
    env.warp(2500)
    assert env.reader().get_result(ELECTION_ID) is None
    result = _b_result()
    with pytest.raises(WriteAuthorizationError):
        env.dl("keyper1").publish_result(ELECTION_ID, result, b"")
    env.dl("result_publisher").publish_result(ELECTION_ID, result, b"")
    got = env.reader().get_result(ELECTION_ID)
    assert got is not None and tuple(got.totals) == (1, 1, 1)


def test_verifiability_tier_is_zero(env):
    assert env.reader().verifiability_tier() == 0


def _b_result():
    from shutter_governance_protocol.envelopes.types import ResultArtifact

    return ResultArtifact(election_id=ELECTION_ID, totals=(1, 1, 1), keyper_indices=(1, 2), bsgs_bound=6)


# --------------------------------------------------------------------------- #
#  Undecodable ballot records (the contract stores wrAttestation as opaque bytes)
# --------------------------------------------------------------------------- #

def _poison(env, wr: bytes):
    """Append, as an unprivileged account calling submitVote directly, a ballot whose
    credential bytes are ``wr``. The contract checks only shapes, so it accepts them."""
    from shutter_governance_protocol.adapters.chain import codec

    good = codec.ballot_to_tuple(env.ballot(b"\x02" * 32))
    out = env.dl("outsider")
    out._send(out._election(ELECTION_ID).functions.submitVote((*good[:5], wr)))


def _weight_zero_credential(env) -> bytes:
    import json

    from shutter_governance_protocol.adapters.chain import codec

    d = json.loads(codec.ballot_to_tuple(env.ballot(b"\x02" * 32))[5])
    d["weight"] = 0
    return json.dumps(d).encode()


@pytest.mark.parametrize("wr", [b"x", b"\xff", b"{}", b"[]", "weight0"],
                         ids=["not-json", "not-utf8", "missing-fields", "wrong-shape", "weight-0"])
def test_undecodable_credential_is_read_as_malformed(env, wr):
    """One undecodable record used to make every read that included it raise, which
    halted the keypers, the auditor and the ingest filter. It must read as a malformed
    record in its own slot, with its neighbours intact."""
    from shutter_governance_protocol.services.common.reads import read_all_ballots
    from shutter_governance_protocol.services.gateway.gateway import _max_stored_nonce

    env.register()
    env.finalize_dkg()
    env.warp(1100)
    env.dl("gateway").submit_ballot(ELECTION_ID, env.ballot(b"\x01" * 32))
    _poison(env, _weight_zero_credential(env) if wr == "weight0" else wr)

    rows = read_all_ballots(env.reader(), ELECTION_ID)
    assert [sb.sequence_number for sb in rows] == [0, 1]
    assert rows[0].envelope is not None and rows[0].malformed_reason is None
    assert rows[1].envelope is None and rows[1].malformed_reason
    assert rows[1].submitted_at is not None
    # The ingest filter keeps working for the next voter.
    assert _max_stored_nonce(env.reader(), ELECTION_ID, b"\x03" * 32) == 0
