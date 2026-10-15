"""``BlockchainDataLayer`` — the per-actor chain adapter.

Maps the ``ElectionDataLayer`` port onto the extended bulletin-board contracts.
Authorization is by transaction sender (this adapter is bound to one actor's
Ethereum key); the port's ``*_sig`` byte arguments are ignored on chain. A thin
emulation layer reads chain state before writes so the adapter presents the exact
uniform port semantics (idempotent resend, divergent-write rejection) the
conformance suite asserts, even where the raw contract would revert differently.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from eth_abi import decode as eth_abi_decode
from eth_utils import keccak
from web3 import Web3

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.adapters.chain import codec
from shutter_governance_protocol.adapters.chain.tx import quorum_write_lock, send_and_confirm
from shutter_governance_protocol.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from shutter_governance_protocol.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    StoredBallot,
)
from shutter_governance_protocol.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    ElectionRecord,
    FinalizedKey,
    ImmutabilityError,
    VotingWindowError,
    WriteAuthorizationError,
)

_ABI_DIR = Path(__file__).parent / "abis"
_ZERO = "0x0000000000000000000000000000000000000000"


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


# Custom-error selectors mapped to port exceptions (the Election ABI does not carry
# AccessControl's error defs, so reverts arrive as raw selector data we decode here).
_AUTHZ_SELECTORS = {
    _selector("AccessControlUnauthorizedAccount(address,bytes32)"),
    _selector("UnauthorizedKeyper(address)"),
    _selector("InvalidMember(address)"),
}
_IMMUTABILITY_SELECTORS = {
    _selector("AlreadyCancelled()"),
    _selector("VotingAlreadyStarted(uint256)"),  # cancel attempted at/after voting_start
    _selector("AlreadyVoted(address)"),
    _selector("AlreadyFinalized()"),
    _selector("ElectionIdTaken(uint256)"),
}
# Writes attempted at the wrong point in the voting lifecycle (the chain is a state
# machine; availability-only backends don't gate these). VotingAlreadyStarted stays an
# ImmutabilityError above — it's a cancel-after-start, not a window-timing violation.
_VOTING_WINDOW_SELECTORS = {
    _selector("VotingNotStarted(uint256)"),  # ballot before voting_start
    _selector("VotingClosed(uint256)"),      # ballot after voting_end
    _selector("VotingStillOpen(uint256)"),   # tally write (aggregate/share/result) before voting_end
    _selector("AggregateNotPublished()"),    # decryption share before a canonical aggregate exists
    _selector("DKGClosed(uint256)"),         # DKG vote once voting has opened
}


# Ballots per getBallots call. Returning a ballot from contract storage costs gas in the
# eth_call: about 128k for a three-candidate ballot (the proof is in the VoteSubmitted log,
# not storage), so a 50-ballot chunk is ~6.5M. Nodes cap a call at the block gas limit or
# lower, and each candidate adds ~13k per ballot; list_ballots halves the chunk when a
# call runs out.
_BALLOT_READ_CHUNK = 50


def _is_out_of_gas(exc: Exception) -> bool:
    # Nodes word it differently: "EVM error OutOfGas" from eth_call, "Out of gas: gas
    # required exceeds allowance" from estimation, "out of gas" elsewhere.
    msg = str(exc).lower().replace(" ", "").replace("_", "")
    return "outofgas" in msg or "gasrequiredexceeds" in msg


# abi.encode(VotingTypes.EncryptedTally): (aggregates[(c1,c2)], admitted[], exclusions[(seq,reason)],
# totalAdmittedWeight, totalScaledWeight), as emitted in AggregatePublished.
_ENCRYPTED_TALLY_TYPE = "((bytes,bytes)[],uint256[],(uint256,uint8)[],uint256,uint256)"


def _abi(name: str):
    return json.loads((_ABI_DIR / f"{name}.json").read_text())


ELECTION_ABI = _abi("Election")
REGISTRY_ABI = _abi("ElectionRegistry")
KEYPERSET_ABI = _abi("KeyperSet")


def _addr_bytes(checksummed: str) -> bytes:
    return bytes.fromhex(checksummed[2:])


class BlockchainDataLayer(ElectionDataLayer):
    def __init__(self, w3: Web3, registry_address: str, account):
        self.w3 = w3
        self.account = account  # eth_account LocalAccount (None => read-only)
        self.registry = w3.eth.contract(address=Web3.to_checksum_address(registry_address), abi=REGISTRY_ABI)

    # -- tx plumbing -------------------------------------------------------- #

    def _send(self, fn):
        acct = self.account
        try:
            gas = fn.estimate_gas({"from": acct.address})
        except Exception as exc:  # noqa: BLE001 — revert surfaces here (pre-flight)
            raise self._map_revert(exc) from exc
        return send_and_confirm(self.w3, acct, fn, gas=gas * 12 // 10)

    @staticmethod
    def _map_revert(exc: Exception) -> Exception:
        msg = str(exc)
        # Decoded error names (when the ABI carried the error def).
        if any(s in msg for s in ("VotingNotStarted", "VotingClosed", "VotingStillOpen", "AggregateNotPublished",
                                  "DKGClosed")):
            return VotingWindowError(msg)
        if any(s in msg for s in ("AlreadyCancelled", "VotingAlreadyStarted", "AlreadyVoted", "AlreadyFinalized", "ElectionIdTaken")):
            return ImmutabilityError(msg)
        if any(s in msg for s in ("AccessControl", "UnauthorizedKeyper", "InvalidMember", "missing role")):
            return WriteAuthorizationError(msg)
        # Raw custom-error selectors in the revert data (web3 leaves these undecoded
        # when the error is caught at gas-estimation / the ABI def isn't consulted).
        selectors = {m[:10] for m in re.findall(r"0x[0-9a-fA-F]{8,}", msg)}
        if selectors & _VOTING_WINDOW_SELECTORS:
            return VotingWindowError(msg)
        if selectors & _IMMUTABILITY_SELECTORS:
            return ImmutabilityError(msg)
        if selectors & _AUTHZ_SELECTORS:
            return WriteAuthorizationError(msg)
        return ValueError(msg)

    def _from_block(self, election) -> int:
        """Where this election's log queries start: the block it was created in.

        Proofs, DKG votes and the aggregate are read from event logs. Querying from
        genesis is refused or times out on most public RPC providers.
        """
        cache = self.__dict__.setdefault("_deploy_blocks", {})
        addr = election.address
        if addr not in cache:
            cache[addr] = int(election.functions.deployBlock().call())
        return cache[addr]

    def _ballot_proofs(self, election, start: int, count: int) -> dict[int, bytes]:
        """``ballotIndex -> zkProof`` from the ``VoteSubmitted`` logs of ballots
        ``start .. start+count-1``: one query, filtered on the indexed ``ballotIndex``."""
        logs = election.events.VoteSubmitted().get_logs(
            from_block=self._from_block(election),
            argument_filters={"ballotIndex": list(range(start, start + count))},
        )
        out: dict[int, bytes] = {}
        for log in logs:
            out.setdefault(int(log["args"]["ballotIndex"]), bytes(log["args"]["zkProof"]))
        return out

    def _election(self, election_id: bytes):
        addr = self.registry.functions.elections(codec.eid_to_uint(election_id)).call()
        if int(addr, 16) == 0:
            raise KeyError(f"unknown election {election_id.hex()}")
        return self.w3.eth.contract(address=addr, abi=ELECTION_ABI)

    def _keyper_set_of(self, election):
        ks_addr = election.functions.keyperSet().call()
        return self.w3.eth.contract(address=ks_addr, abi=KEYPERSET_ABI)

    # -- election lifecycle ------------------------------------------------- #

    def register_election(self, config: ElectionConfig, admin_sig: bytes) -> bytes:
        # Replay guard, BEFORE any transaction. The signed config asserts the id it
        # expects; the registry assigns ++electionCount. If they disagree this body has
        # already been registered (or the sequence moved on), so refuse here — the
        # KeyperSet deploy below is itself a tx, so checking later would still burn the
        # admin's gas, which is exactly the drain this guard exists to prevent.
        expected = (int(self.registry.functions.electionCount().call()) + 1).to_bytes(32, "big")
        if config.election_id != expected:
            raise ImmutabilityError(
                f"register: expected election id {config.election_id.hex()} but the next id is "
                f"{expected.hex()} — the sequence moved on; re-read it and sign again"
            )
        # Deploy a fresh KeyperSet from the config's keyper addresses + URLs
        # (fresh DKG per election). Storing URLs on-chain lets any service read
        # keyper URLs through the data-layer port — no off-chain URL registry.
        members = [Web3.to_checksum_address(k.signing_key) for k in config.keypers]
        urls = [k.url for k in config.keypers]
        # threshold.t IS the quorum, and KeyperSet stores the quorum, so this is now a
        # straight pass-through — the old `+1` (and the matching `-1` on read) existed
        # only because the two sides disagreed on what `t` meant.
        quorum = config.threshold.quorum
        params = self._config_to_params(config)
        # Encode the publish call before the KeyperSet deploy: a config the contract
        # types cannot hold must fail here, not after the admin has paid for a KeyperSet.
        try:
            self.registry.functions.publishElection(Web3.to_checksum_address("0x" + "00" * 20), params)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"register: config does not fit the election contract: {exc}") from exc
        ks = self._deploy(KEYPERSET_ABI, "KeyperSet", members, urls, quorum)
        # The registry assigns the next sequential id; read it back from the event.
        # The receipt also carries the KeyperSet/Election deploy + role-grant logs, so
        # DISCARD non-matching ones instead of warning on each.
        from web3.logs import DISCARD

        receipt = self._send(self.registry.functions.publishElection(ks, params))
        ev = self.registry.events.ElectionCreated().process_receipt(receipt, errors=DISCARD)[0]
        return codec.uint_to_eid(int(ev["args"]["electionId"]))

    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        self._send(self._election(election_id).functions.cancelElection())

    def get_election(self, election_id: bytes) -> ElectionRecord:
        election = self._election(election_id)
        config_raw, dkg_raw = election.functions.getElection().call()
        config = self._config_from_view(config_raw)  # keyper URLs included (from getElection)
        finalized = None
        if election.functions.isDKGFinalized().call():
            finalized = FinalizedKey(
                pk_election=bytes(dkg_raw[0]),
                committee_pks=tuple(bytes(p) for p in dkg_raw[1]),
            )
        return ElectionRecord(
            config=config, cancelled=bool(config_raw[16]),
            tally_stalled=bool(election.functions.tallyStalled().call()),
            finalized_key=finalized,
        )

    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        # Ids are dense (1..electionCount), so enumerate by index — one paged read,
        # no event-log scan (cheap + provider-friendly on a real chain).
        count = int(self.registry.functions.electionCount().call())
        if count == 0:
            return []
        addrs = self.registry.functions.getElections(1, count).call()
        out = []
        for i, addr in enumerate(addrs, start=1):
            if int(addr, 16) == 0:
                continue
            election = self.w3.eth.contract(address=addr, abi=ELECTION_ABI)
            if filter and filter.admin_key is not None:
                if _addr_bytes(election.functions.adminAddr().call()) != filter.admin_key:
                    continue
            out.append(codec.uint_to_eid(i))
        return out

    # -- DKG ---------------------------------------------------------------- #

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        election = self._election(election_id)
        pk = bytes(pk_election)
        committee = [bytes(p) for p in committee_pks]
        # Meta-tx: the keyper signed the content; recover it (the on-chain author),
        # not the relaying tx sender (this adapter's account, which just pays gas).
        keyper_addr = Web3.to_checksum_address(
            write_auth.recover_digest(write_auth.dkg_result_digest(election_id, pk, committee), keyper_sig)
        )
        with quorum_write_lock(election.address):  # see tx.quorum_write_lock
            if election.functions.isDKGFinalized().call():
                _, dkg_raw = election.functions.getElection().call()
                if bytes(dkg_raw[0]) == pk:
                    return
                raise ImmutabilityError("DKG already finalized with a different key")
            # Emulate append-only-per-dealer: inspect this keyper's prior vote via events.
            mine = [
                ev for ev in election.events.DKGVoteRegistered().get_logs(from_block=self._from_block(election))
                if ev["args"]["keyper"] == keyper_addr
            ]
            if mine:
                if bytes(mine[-1]["args"]["pkElection"]) == pk:
                    return  # identical resend → no-op
                raise ImmutabilityError("keyper already submitted a different DKG result")
            self._send(election.functions.voteDKGResultSigned(pk, committee, keyper_sig))

    def get_dkg_submissions(self, election_id) -> list[DKGResultSubmission]:
        """Every DKG vote, rebuilt from the transaction that cast it.

        The vote event carries only the voter and the public key, but the transaction's
        input holds the whole vote: ``voteDKGResultSigned(pkElection, committeePKs,
        keyperSig)`` for a relayed keyper vote, or ``voteDKGResult(pkElection,
        committeePKs)`` sent by the keyper itself. Returning what each keyper actually
        voted, with its own signature, lets an auditor recount the quorum exactly as on
        the other backends. A vote without a signature carries ``submitter``, the
        address the contract authenticated as its sender.
        """
        election = self._election(election_id)
        out = []
        for ev in election.events.DKGVoteRegistered().get_logs(from_block=self._from_block(election)):
            tx = self.w3.eth.get_transaction(ev["transactionHash"])
            fn, args = election.decode_function_input(tx["input"])
            signature = bytes(args["keyperSig"]) if fn.fn_name == "voteDKGResultSigned" else b""
            out.append(DKGResultSubmission(
                election_id=election_id,
                pk_election=bytes(args["pkElection"]),
                committee_pks=tuple(bytes(p) for p in args["committeePKs"]),
                keyper_signature=signature,
                submitter=None if signature else _addr_bytes(ev["args"]["keyper"]),
            ))
        return out

    def get_finalized_key(self, election_id) -> FinalizedKey | None:
        election = self._election(election_id)
        if not election.functions.isDKGFinalized().call():
            return None
        _, dkg_raw = election.functions.getElection().call()
        return FinalizedKey(pk_election=bytes(dkg_raw[0]), committee_pks=tuple(bytes(p) for p in dkg_raw[1]))

    # -- ballots ------------------------------------------------------------ #

    def submit_ballot(self, election_id, ballot: BallotEnvelope, gateway_sig: bytes = b"") -> int:
        # gateway_sig is ignored on chain: the contract authorizes by msg.sender holding
        # VOTE_PROXY_ROLE (or charging selfSubmitFee), so the writer is already
        # authenticated by the transaction itself.
        election = self._election(election_id)
        receipt = self._send(election.functions.submitVote(codec.ballot_to_tuple(ballot)))
        logs = election.events.VoteSubmitted().process_receipt(receipt)
        return int(logs[0]["args"]["ballotIndex"])

    def list_ballots(self, election_id, start: int, count: int) -> list[StoredBallot]:
        election = self._election(election_id)
        total = election.functions.getNumBallots().call()
        count = min(count, max(0, total - start))
        if count <= 0:
            return []
        # getBallots returns BallotRecord[] (payload + block-time submittedAt), so the
        # window check has an authoritative receive time. Ballot index == sequence number.
        out: list[StoredBallot] = []
        at, chunk = start, min(count, _BALLOT_READ_CHUNK)
        while at < start + count:
            k = min(chunk, start + count - at)
            try:
                raw = election.functions.getBallots(at, k).call()
            except Exception as exc:  # noqa: BLE001
                if k == 1 or not _is_out_of_gas(exc):
                    raise
                chunk = max(1, k // 2)  # larger ballots than the chunk was sized for
                continue
            proofs = self._ballot_proofs(election, at, k)
            out.extend(codec.ballot_record_from_contract(rec, election_id, at + offset, proofs.get(at + offset))
                       for offset, rec in enumerate(raw))
            at += k
        return out

    def count_ballots(self, election_id) -> int:
        return int(self._election(election_id).functions.getNumBallots().call())

    # -- tally artifacts ---------------------------------------------------- #

    def submit_aggregate(self, election_id, aggregate: AggregateArtifact, keyper_sig) -> None:
        election = self._election(election_id)
        # Meta-tx: the keyper signed the aggregate content; recover it (the on-chain
        # author), not the relaying tx sender. The digest is byte-identical to the
        # contract's ``_aggregateDigest`` and groups the quorum vote.
        digest = write_auth.aggregate_digest_of(election_id, aggregate)
        keyper_addr = Web3.to_checksum_address(write_auth.recover_digest(digest, keyper_sig))
        # If the aggregate is already canonical (t+1 quorum on chain), it is frozen:
        # a matching resend is a no-op; anything else can no longer become canonical.
        with quorum_write_lock(election.address):  # see tx.quorum_write_lock
            existing = self._read_aggregate(election, election_id)
            if existing is not None:
                if existing == aggregate:
                    return
                raise ImmutabilityError("aggregate already finalized with a different artifact")
            # Not finalized: submissions are mutable per keyper (override allowed). Skip the
            # tx only if this keyper's current on-chain vote already equals this digest.
            mine = [
                ev for ev in election.events.AggregateVoteRegistered().get_logs(from_block=self._from_block(election))
                if ev["args"]["keyper"] == keyper_addr
            ]
            if mine and bytes(mine[-1]["args"]["resultDigest"]) == digest:
                return  # this keyper's current vote is already this aggregate → no-op
            self._send(election.functions.submitAggregateSigned(codec.aggregate_to_tuple(aggregate), keyper_sig))

    def get_aggregate(self, election_id) -> AggregateArtifact | None:
        return self._read_aggregate(self._election(election_id), election_id)

    def _read_aggregate(self, election, election_id):
        """The canonical aggregate, or ``None`` before the quorum.

        Storage holds only the digest the keypers signed; the artifact is in the
        ``AggregatePublished`` event. It is returned only if it hashes to that digest, so
        a node serving a different event cannot substitute a different aggregate.
        """
        digest = bytes(election.functions.aggregateDigest().call())
        if digest == bytes(32):
            return None
        for log in election.events.AggregatePublished().get_logs(from_block=self._from_block(election)):
            if bytes(log["args"]["digest"]) != digest:
                continue
            raw = eth_abi_decode([_ENCRYPTED_TALLY_TYPE], bytes(log["args"]["tally"]))[0]
            artifact = codec.aggregate_from_contract(raw, election_id)
            if write_auth.aggregate_digest_of(election_id, artifact) == digest:
                return artifact
        raise ValueError(f"election {election_id.hex()}: no AggregatePublished event matches the stored digest")

    def submit_decryption_share(self, election_id, share: DecryptionShareEnvelope, keyper_sig) -> None:
        election = self._election(election_id)
        ks = self._keyper_set_of(election)
        shares, proofs = codec.share_to_contract(share)
        # Meta-tx: recover the keyper that signed the content (the on-chain author).
        keyper_addr = Web3.to_checksum_address(
            write_auth.recover_digest(write_auth.decryption_share_digest(election_id, shares, proofs), keyper_sig)
        )
        try:
            idx0 = int(ks.functions.getMemberIndex(keyper_addr).call())
        except Exception as exc:  # noqa: BLE001 — non-member reverts InvalidMember
            raise WriteAuthorizationError("submit_decryption_share: signer is not a registered keyper") from exc
        if share.keyper_index != idx0 + 1:
            raise WriteAuthorizationError(
                f"share keyper_index {share.keyper_index} does not match signer index {idx0 + 1}"
            )
        existing = {s.keyper_index: s for s in self.list_decryption_shares(election_id)}
        if share.keyper_index in existing:
            if existing[share.keyper_index] != share:
                raise ImmutabilityError(f"keyper {share.keyper_index} already submitted different shares")
            return
        self._send(election.functions.submitDecryptionShareSigned(shares, proofs, keyper_sig))

    def list_decryption_shares(self, election_id) -> list[DecryptionShareEnvelope]:
        election = self._election(election_id)
        raw = election.functions.getDecryptionShares().call()
        return [codec.share_from_contract(s, election_id) for s in raw]

    def publish_result(self, election_id, result, result_publisher_sig) -> None:
        election = self._election(election_id)
        if election.functions.isResultFinalized().call():
            existing = self.get_result(election_id)
            if existing is not None and tuple(existing.totals) != tuple(result.totals):
                raise ImmutabilityError("result already published (append-only)")
            return
        totals = [int(t) for t in result.totals]
        keyper_indices = [int(i) for i in result.keyper_indices]
        self._send(election.functions.publishResult(totals, keyper_indices))

    def get_result(self, election_id):
        election = self._election(election_id)
        if not election.functions.isResultFinalized().call():
            return None
        raw = election.functions.getResult().call()
        totals = tuple(int(t) for t in raw[0])
        keyper_indices = tuple(int(i) for i in raw[1])
        # bsgs_bound is derived (not stored on chain): budget * total *scaled* weight.
        # The scaled total is what the aggregate was built from; using the raw one
        # would name a bound the plaintext cannot reach whenever scale > 1.
        agg = self.get_aggregate(election_id)
        budget = int(election.functions.budget().call())
        bound = budget * (agg.total_scaled_weight if agg else 0)
        from shutter_governance_protocol.envelopes.types import ResultArtifact
        return ResultArtifact(election_id=election_id, totals=totals, keyper_indices=keyper_indices, bsgs_bound=bound)

    def set_tally_stalled(self, election_id, stalled: bool, sig, issued_at: int) -> None:
        # Direction-split, tx-sender-authorized (the relayed sig is unused on chain):
        #   mark (true)  → sent by the coordinator's account (RESULT_PUBLISHER_ROLE),
        #   clear (false)→ sent by the admin's account (DEFAULT_ADMIN_ROLE).
        # Each service's adapter is bound to the appropriate key, so msg.sender authorizes.
        election = self._election(election_id)
        fn = election.functions.markTallyStalled() if stalled else election.functions.clearTallyStalled()
        self._send(fn)

    def verifiability_tier(self) -> int:
        return 0

    # -- config <-> params -------------------------------------------------- #

    def _config_to_params(self, config: ElectionConfig):
        # The chain contract requires a non-zero vote-proxy (ElectionBase reverts on
        # address(0)); unlike the database backend it has no "open writes" mode. Fail early
        # with a clear message instead of an IndexError → 500.
        if not config.gateway_keys:
            raise ValueError(
                "On the blockchain backend you must set exactly one authorized ballot-writer "
                "(vote-proxy) address — the account that submits ballots (the gateway/api "
                "sender). The registration left it blank."
            )
        return (
            config.voting_start,
            config.voting_end,
            int(config.self_submit_fee_wei),  # selfSubmitFee (wei); 0 = free self-submission
            config.num_candidates,
            config.budget,
            codec.MODE_TO_U8[config.mode],
            codec.VARIANT_TO_U8[config.variant],
            config.weighted,
            config.scale,
            codec.DUP_TO_U8[config.duplicate_policy],
            config.protocol_version,
            config.eligibility_key,  # pkWR
            Web3.to_checksum_address(config.result_publisher_key),
            Web3.to_checksum_address(config.gateway_keys[0]),
        )

    def _config_from_view(self, v) -> ElectionConfig:
        # Indices track VotingTypes.ElectionConfigView field order (tallyDeadline removed,
        # so everything after votingEnd shifts down one vs the previous layout).
        keyper_addrs = [_addr_bytes(a) for a in v[14]]
        keyper_urls = [str(e) for e in v[20]]  # index-aligned with keyperAddresses
        threshold_n = int(v[12])
        # No `-1`: `thresholdT` is the quorum and so is `Threshold.t`.
        threshold_t = int(v[13])
        return ElectionConfig(
            election_id=codec.uint_to_eid(int(v[0])),
            num_candidates=int(v[4]),
            budget=int(v[5]),
            mode=codec.U8_TO_MODE[int(v[6])],
            variant=codec.U8_TO_VARIANT[int(v[7])],
            weighted=bool(v[8]),
            # Same slot the removed `maxWeight` cap occupied, so no index shifts.
            scale=int(v[9]),
            duplicate_policy=codec.U8_TO_DUP[int(v[10])],
            voting_start=int(v[1]),
            voting_end=int(v[2]),
            threshold=Threshold(t=threshold_t, n=threshold_n),
            keypers=tuple(
                KeyperIdentity(signing_key=a, url=e) for a, e in zip(keyper_addrs, keyper_urls)
            ),
            eligibility_key=bytes(v[15]),
            result_publisher_key=_addr_bytes(v[18]),
            gateway_keys=(_addr_bytes(v[19]),),
            admin_key=_addr_bytes(v[17]),
            protocol_version=str(v[11]),
            self_submit_fee_wei=int(v[3]),  # ElectionConfigView.selfSubmitFee
        )

    # -- deploy helper ------------------------------------------------------ #

    def _deploy(self, abi, name: str, *args) -> str:
        """Deploy a contract from the forge artifact bytecode and return its address."""
        from shutter_governance_protocol.adapters.chain.deploy import bytecode_of

        contract = self.w3.eth.contract(abi=abi, bytecode=bytecode_of(name))
        receipt = self._send(contract.constructor(*args))
        return receipt.contractAddress
