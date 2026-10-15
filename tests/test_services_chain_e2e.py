"""Full election through the services against the BLOCKCHAIN backend (Anvil).

The same services that ran on in-memory and Postgres run here over per-actor
``BlockchainDataLayer`` instances against the extended bulletin-board contracts on
a local Anvil devnet. Authorization is by Ethereum tx-sender (a ``ChainSigner``
whose ``sign`` is a no-op, since the chain ignores the port's sig args); time is
Anvil block time. This is the payoff of the port: swap the backend, the protocol
and services are unchanged. Skips if ``anvil`` is unavailable.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.crypto import ballot as ballot_crypto
from shutter_governance_protocol.crypto import schnorr
from shutter_governance_protocol.crypto.points import g1_to_compressed, g2_from_compressed
from shutter_governance_protocol.envelopes.types import BallotEnvelope, Ciphertext
from shutter_governance_protocol.ports.eligibility import AttestationRequest
from shutter_governance_protocol.services import admin
from shutter_governance_protocol.services.coordinator import dkg_coordinator as coord
from shutter_governance_protocol.services import tally_aggregator as agg
from shutter_governance_protocol.services.gateway import submit_ballot

from test_adapter_chain import ANVIL_KEYS  # reuse dev keys

ELECTION_ID = (1).to_bytes(32, "big")
DKG_LEAD_TIME = 100


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def anvil_w3():
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


class ChainWorld:
    def __init__(self, w3):
        from shutter_governance_protocol.adapters.chain.client import BlockchainDataLayer
        from shutter_governance_protocol.adapters.chain.deploy import chain_now, deploy_registry
        from shutter_governance_protocol.adapters.eligibility_stub import StubEligibilityService
        from shutter_governance_protocol.core.authz import Signer
        from shutter_governance_protocol.services.keyper import KeyperService

        self.w3 = w3
        # Unified identities: every actor is an Ethereum secp256k1 Signer; its
        # BlockchainDataLayer is bound to that same account.
        names = ["admin", "result_publisher", "gateway", "keyper1", "keyper2", "keyper3"]
        signers = {name: Signer.from_sk(int(ANVIL_KEYS[i], 16)) for i, name in enumerate(names)}
        self.signers = signers
        self.registry = deploy_registry(w3, signers["admin"].account)
        self.base = chain_now(w3)
        self.clock = lambda: chain_now(w3)
        self.n, self.t = 3, 2  # 2-of-3: t IS the quorum, and must be a majority

        elig_sk, _ = schnorr.keygen()
        self.elig = StubEligibilityService(elig_sk)

        def ab(role):
            return signers[role].identity

        self.admin_dl = BlockchainDataLayer(w3, self.registry, signers["admin"].account)
        self.result_publisher_dl = BlockchainDataLayer(w3, self.registry, signers["result_publisher"].account)
        self.gateway_dl = BlockchainDataLayer(w3, self.registry, signers["gateway"].account)
        self.admin_signer = signers["admin"]
        self.result_publisher_signer = signers["result_publisher"]

        # Keypers hold NO chain account and pay no gas. They content-sign
        # their DKG result and decryption shares; the result_publisher/coordinator acts as
        # the relayer that sends the ...Signed tx (pays gas), and the contract
        # ecrecovers the keyper as the on-chain author. Here the result_publisher account
        # is that relayer, so every keyper's data layer is the relayer's adapter.
        self.relayer_dl = BlockchainDataLayer(w3, self.registry, signers["result_publisher"].account)
        self.keypers = [
            KeyperService(i, signers[f"keyper{i}"], self.relayer_dl, clock=self.clock)
            for i in range(1, self.n + 1)
        ]

        self.config = ElectionConfig(
            election_id=ELECTION_ID, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=self.base + 1000, voting_end=self.base + 2000, threshold=Threshold(t=self.t, n=self.n),
            keypers=tuple(KeyperIdentity(signing_key=ab(f"keyper{i}"), url="") for i in range(1, self.n + 1)),
            eligibility_key=self.elig.eligibility_key, result_publisher_key=ab("result_publisher"),
            gateway_keys=(ab("gateway"),), admin_key=ab("admin"), protocol_version="v1",
        )

    def warp(self, offset):
        from shutter_governance_protocol.adapters.chain.deploy import anvil_set_time
        anvil_set_time(self.w3, self.base + offset)

    def voter_ballot(self, votes, pseudonym, weight=1):
        mpk = g2_from_compressed(self.admin_dl.get_finalized_key(ELECTION_ID).pk_election)
        sk, vk = schnorr.keygen()
        vk_bytes = g1_to_compressed(vk)
        att = self.elig.issue_attestation(AttestationRequest(ELECTION_ID, pseudonym, vk_bytes, weight))
        built = ballot_crypto.build_ballot(
            mpk=mpk, election_id=ELECTION_ID, pseudonym=pseudonym, sk=sk, vk=vk,
            attestation=att, votes=votes, num_candidates=3, budget=3,
        )
        return BallotEnvelope(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk=vk_bytes,
            ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
            zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
        )


def test_full_weighted_election_over_chain(anvil_w3):
    world = ChainWorld(anvil_w3)

    # Admin registers (lead-time gate passes: voting_start - now >= 100).
    admin.register_election(world.admin_dl, world.config, world.admin_signer.sign_register(world.config),
                            admin_identity=world.admin_signer.identity, clock=world.clock, dkg_lead_time=DKG_LEAD_TIME)

    # DKG coordinator drives the ceremony; result finalizes on chain.
    assert coord.ensure_dkg(
        ELECTION_ID, world.keypers, world.admin_dl, n=world.n, t=world.t,
        clock=world.clock, deadline=world.config.voting_start,
    )
    assert world.admin_dl.get_finalized_key(ELECTION_ID) is not None

    # Voting window: two weighted ballots via the gateway.
    world.warp(1500)
    submit_ballot(world.gateway_dl, ELECTION_ID, world.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=world.clock)
    submit_ballot(world.gateway_dl, ELECTION_ID, world.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=world.clock)
    assert world.admin_dl.count_ballots(ELECTION_ID) == 2

    # Tally: aggregate → trigger keypers → recover → publish, all on chain.
    world.warp(2500)
    result = agg.run_tally(world.result_publisher_dl, ELECTION_ID, world.result_publisher_signer, world.keypers, clock=world.clock)
    assert result is not None
    # [2*3, 5*3, 0] = [6, 15, 0]
    assert list(result.totals) == [6, 15, 0]

    # Result is durably on chain: a fresh reader sees it.
    from shutter_governance_protocol.adapters.chain.client import BlockchainDataLayer
    fresh = BlockchainDataLayer(anvil_w3, world.registry, world.signers["admin"].account)
    assert list(fresh.get_result(ELECTION_ID).totals) == [6, 15, 0]

    # An honest chain election audits clean. The chain read used to return every DKG vote
    # with an empty signature and a copied committee, so the auditor found "no quorum".
    from shutter_governance_protocol.services import auditor
    report = auditor.audit(fresh, ELECTION_ID)
    assert report.ok, report.discrepancies


def test_tally_completes_despite_an_undecodable_ballot_on_chain(anvil_w3):
    """An outsider stores a ballot whose credential bytes are not a credential. Voting
    through the gateway must continue after it, and the tally must exclude it as
    MALFORMED and count everyone else."""
    from shutter_governance_protocol.adapters.chain import codec
    from shutter_governance_protocol.adapters.chain.client import BlockchainDataLayer
    from shutter_governance_protocol.envelopes.types import ExclusionReason
    from eth_account import Account

    world = ChainWorld(anvil_w3)
    admin.register_election(world.admin_dl, world.config, world.admin_signer.sign_register(world.config),
                            admin_identity=world.admin_signer.identity, clock=world.clock, dkg_lead_time=DKG_LEAD_TIME)
    assert coord.ensure_dkg(
        ELECTION_ID, world.keypers, world.admin_dl, n=world.n, t=world.t,
        clock=world.clock, deadline=world.config.voting_start,
    )

    world.warp(1500)
    submit_ballot(world.gateway_dl, ELECTION_ID, world.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=world.clock)
    # The attack: a direct submitVote (fee 0 here) from an account with no role.
    outsider = BlockchainDataLayer(anvil_w3, world.registry, Account.from_key(ANVIL_KEYS[6]))
    good = codec.ballot_to_tuple(world.voter_ballot([0, 0, 3], b"\x09" * 32))
    outsider._send(outsider._election(ELECTION_ID).functions.submitVote((*good[:5], b"x")))
    # Voting through the gateway still works after it.
    submit_ballot(world.gateway_dl, ELECTION_ID, world.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=world.clock)
    assert world.admin_dl.count_ballots(ELECTION_ID) == 3

    world.warp(2500)
    result = agg.run_tally(world.result_publisher_dl, ELECTION_ID, world.result_publisher_signer, world.keypers, clock=world.clock)
    assert result is not None
    assert list(result.totals) == [6, 15, 0]
    aggregate = world.admin_dl.get_aggregate(ELECTION_ID)
    assert [(x.sequence_number, x.reason) for x in aggregate.exclusions] == [(1, ExclusionReason.MALFORMED)]
