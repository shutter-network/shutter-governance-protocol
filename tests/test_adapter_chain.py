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


@pytest.mark.parametrize("wr", [b"x", b"\xff", b"{}", b"[]", b"[" * 5_000, "weight0"],
                         ids=["not-json", "not-utf8", "missing-fields", "wrong-shape", "deeply-nested", "weight-0"])
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


def test_dkg_votes_are_read_back_as_cast(env):
    """Each vote comes back with the committee it voted for and its submitter: the keyper's
    own signature for a relayed vote, or the contract-authenticated sender for a vote the
    keyper sent itself. The read used to return empty signatures and a copied committee."""
    from shutter_governance_protocol.services.auditor.auditor import _submitter_index

    env.register()
    pk, committee = env.pk_and_committee()
    k1 = env.dl("keyper1")
    k1._send(k1._election(ELECTION_ID).functions.voteDKGResult(pk, committee))  # sent by keyper 1 itself
    env.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper2", pk, committee))

    subs = env.reader().get_dkg_submissions(ELECTION_ID)
    assert [s.committee_pks for s in subs] == [tuple(committee)] * 2
    assert subs[0].keyper_signature == b"" and subs[0].submitter == env._addr("keyper1")
    assert subs[1].keyper_signature and subs[1].submitter is None
    assert [_submitter_index(env.config, ELECTION_ID, s) for s in subs] == [1, 2]


# --------------------------------------------------------------------------- #
#  Scale: concurrent writes and large ballot lists
# --------------------------------------------------------------------------- #

def test_concurrent_writes_from_one_account_are_all_mined(env):
    """The API relays every ballot from one gateway account, on several threads. Reading the
    mined nonce without a lock gave two threads the same nonce: 7 of 8 concurrent votes were
    rejected ("replacement transaction underpriced") and lost."""
    import threading

    env.register()
    env.finalize_dkg()
    env.warp(1100)
    gw, errors = env.dl("gateway"), []

    def vote(i):
        try:
            gw.submit_ballot(ELECTION_ID, env.ballot((i + 1).to_bytes(32, "big")))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=vote, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and gw.count_ballots(ELECTION_ID) == 8


def _real_sized_ballot(env, i):
    """A ballot with a real three-candidate, budget-3 proof size (3147 bytes). The fixture's
    3-byte proof would understate the gas of reading it back."""
    import os
    from dataclasses import replace

    return replace(env.ballot((i + 1).to_bytes(32, "big")), zk_proof=os.urandom(3147))


def test_more_than_a_hundred_ballots_read_back_completely(env, monkeypatch):
    """One getBallots call for a whole page ran out of gas beyond ~83 real-sized ballots, so
    keypers, the auditor and the API's ingest filter could not read the election. Reads are
    now chunked, and a chunk that still runs out is halved."""
    from shutter_governance_protocol.adapters.chain import client as chain_client
    from shutter_governance_protocol.services.common.reads import read_all_ballots

    env.register()
    env.finalize_dkg()
    env.warp(1100)
    gw = env.dl("gateway")
    for i in range(100):
        gw.submit_ballot(ELECTION_ID, _real_sized_ballot(env, i))

    rows = read_all_ballots(env.reader(), ELECTION_ID)
    assert [r.sequence_number for r in rows] == list(range(100))
    assert all(r.envelope is not None and len(r.envelope.zk_proof) == 3147 for r in rows)

    # A provider with a 5M eth_call cap: a default chunk (~6.5M) runs out and must halve.
    reader = env.reader()
    real_call, out_of_gas = reader.w3.eth.call, []

    def capped(tx, *a, **kw):
        try:
            return real_call({**tx, "gas": 5_000_000}, *a, **kw)
        except Exception as exc:
            out_of_gas.append(chain_client._is_out_of_gas(exc))
            raise

    monkeypatch.setattr(reader.w3.eth, "call", capped)
    assert len(read_all_ballots(reader, ELECTION_ID)) == 100
    assert out_of_gas and all(out_of_gas)


# --------------------------------------------------------------------------- #
#  Bulky data in event logs, a commitment in storage
# --------------------------------------------------------------------------- #

def test_ballot_proof_is_stored_as_a_hash_and_read_back_from_its_log(env):
    """Storage keeps keccak256(zkProof); the proof is in VoteSubmitted. Storing the proof
    made a real ballot cost ~3.5M gas to cast and ~360k to read."""
    import os
    from dataclasses import replace

    from eth_utils import keccak

    env.register()
    env.finalize_dkg()
    env.warp(1100)
    proof = os.urandom(3147)
    ballot = replace(env.ballot(b"\x01" * 32), zk_proof=proof)
    env.dl("gateway").submit_ballot(ELECTION_ID, ballot)

    raw = env.reader()._election(ELECTION_ID).functions.getBallots(0, 1).call()
    assert bytes(raw[0][0][3]) == keccak(proof)  # only the commitment is in storage
    [row] = env.reader().list_ballots(ELECTION_ID, 0, 1)
    assert row.envelope == ballot


def test_large_budget_ballot_can_be_cast(env):
    """A budget-100 ballot carries a ~78 KB proof. Stored, it needed ~49M gas, more than a
    block, so such an election could not be voted in on chain at all."""
    import os
    from dataclasses import replace

    env.register()
    env.finalize_dkg()
    env.warp(1100)
    ballot = replace(env.ballot(b"\x01" * 32), zk_proof=os.urandom(3 * 101 * 256 + 64))
    env.dl("gateway").submit_ballot(ELECTION_ID, ballot)
    assert env.reader().list_ballots(ELECTION_ID, 0, 1)[0].envelope == ballot


def test_aggregate_with_thousands_of_admitted_ballots_becomes_canonical(env):
    """The quorum vote stored the whole aggregate, at ~22.5k gas per admitted ballot: out of
    gas past ~1,300. Storage now keeps its digest; the artifact is in AggregatePublished,
    read back and checked against that digest."""
    from shutter_governance_protocol.envelopes.types import AggregateArtifact, Ciphertext, Exclusion, ExclusionReason

    env.register()
    env.finalize_dkg()
    env.warp(2500)
    n = 3000
    agg = AggregateArtifact(
        election_id=ELECTION_ID,
        aggregates=tuple(Ciphertext(c1=_b(96, 7), c2=_b(96, 8)) for _ in range(3)),
        admitted=tuple(range(n)), exclusions=(Exclusion(n, ExclusionReason.MALFORMED),),
        total_admitted_weight=n, total_scaled_weight=n,
    )
    for k in ("keyper1", "keyper2"):
        env.dl(k).submit_aggregate(ELECTION_ID, agg, env.aggregate_sig(k, agg))
    assert env.reader().get_aggregate(ELECTION_ID) == agg



def test_dkg_vote_after_voting_start_is_a_voting_window_error(env):
    """A late vote used to finalize the key of an election that had already failed."""
    env.register()
    pk, committee = env.pk_and_committee()
    env.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper1", pk, committee))
    env.warp(1000)  # voting_start
    with pytest.raises(VotingWindowError):
        env.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, env.dkg_sig("keyper2", pk, committee))
    assert env.reader().get_finalized_key(ELECTION_ID) is None


def test_log_queries_start_at_the_elections_deploy_block(env):
    """Proofs, DKG votes and the aggregate come from logs. Scanning from block 0 is slow on a
    long chain and refused outright by many RPC providers' block-range limits."""
    env.register()
    reader = env.reader()
    election = reader._election(ELECTION_ID)
    deployed = election.functions.deployBlock().call()
    assert deployed > 0 and reader._from_block(election) == deployed


def test_wei_scale_election_registers_and_reads_back(env):
    """Token weights are often in wei, so a useful scale is ~1e15. The contract held scale
    as uint32, so registering one failed (HTTP 500) after the KeyperSet was already paid for."""
    from dataclasses import replace

    env.config = replace(env.config, weighted=True, scale=10**15)
    env.register()
    assert env.reader().get_election(ELECTION_ID).config.scale == 10**15


def test_config_the_contract_cannot_hold_fails_before_any_transaction(env, monkeypatch):
    """The publish call is encoded before the KeyperSet deploy, so the admin pays nothing."""
    admin = env.dl("admin")
    real = admin._config_to_params
    monkeypatch.setattr(admin, "_config_to_params", lambda c: (*real(c)[:3], 2**40, *real(c)[4:]))
    nonce = env.w3.eth.get_transaction_count(env._addr("admin"))
    with pytest.raises(ValueError, match="does not fit"):
        env.register()
    assert env.w3.eth.get_transaction_count(env._addr("admin")) == nonce


def test_concurrent_aggregate_relays_all_land(env):
    """Every keyper relays its aggregate through the coordinator at the same moment. Each
    gas estimate saw no quorum yet; the one mined second reached it, did far more work
    (store the digest, emit the artifact) and ran out of gas. Seen live on chain-devnet."""
    import threading

    env.register()
    env.finalize_dkg()
    env.warp(2500)
    agg, errors = env.aggregate(), []

    def submit(k):
        try:
            env.dl(k).submit_aggregate(ELECTION_ID, agg, env.aggregate_sig(k, agg))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    w3 = env.w3
    w3.provider.make_request("evm_setAutomine", [False])
    w3.provider.make_request("evm_setIntervalMining", [1])  # like the devnet: one block a second
    try:
        threads = [threading.Thread(target=submit, args=(k,)) for k in ("keyper1", "keyper2", "keyper3")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
    finally:
        w3.provider.make_request("evm_setIntervalMining", [0])
        w3.provider.make_request("evm_setAutomine", [True])
    assert errors == [] and env.reader().get_aggregate(ELECTION_ID) == agg
