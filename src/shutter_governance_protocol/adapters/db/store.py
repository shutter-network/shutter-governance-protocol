"""``PostgresStore`` — the database adapter's enforcement engine.

Implements the ``ElectionDataLayer`` contract against Postgres, server-side:
stable total ballot ordering (a per-election 0-based sequence assigned under a row
lock), config immutability after ``voting_start``, append-only artifacts and
idempotent shares (via primary keys + read-compare), the DKG finalization quorum
rule, the write-authorization matrix (:mod:`shutter_governance_protocol.authz` request signatures), and
public reads. It enforces the *same* contract as the in-memory reference and
passes the *same* conformance suite.

Time is injected via ``clock`` (the service's NTP-disciplined wall clock in
production; a controllable clock in tests) so immutability/cancellation windows
are deterministic — matching "the authoritative timestamp source is the adapter's"
.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Callable

import psycopg
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from shutter_governance_protocol.core import authz, write_auth
from shutter_governance_protocol.core.quorum import resolve_unique
from shutter_governance_protocol.adapters.db.schema import DDL
from shutter_governance_protocol.core.config import ElectionConfig
from shutter_governance_protocol.core.state import ElectionState, StateFacts, derive_state
from shutter_governance_protocol.envelopes import codecs
from shutter_governance_protocol.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    ResultArtifact,
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


# Upper bound on concurrent Postgres connections held by one store. Bounded so a burst of
# requests queues rather than exhausting the server's connection slots.
POOL_MAX_SIZE = 10

# Arbitrary constant keying the advisory lock that serializes registrations (so the
# election-id peek and the nextval that follows it cannot interleave).
_REGISTER_LOCK_KEY = 0x7367705F72656769  # "sgp_regi" (Shutter Governance Protocol registration)


class PostgresStore(ElectionDataLayer):
    def __init__(self, dsn: str, clock: Callable[[], int] | None = None):
        self._dsn = dsn
        # `open=False` then an explicit `open()`: psycopg_pool deprecates implicit opening,
        # and open() does not block on Postgres being reachable — important because the
        # service constructs the store at startup, before the DB may be accepting.
        self._pool = ConnectionPool(dsn, min_size=1, max_size=POOL_MAX_SIZE, open=False)
        self._pool.open()
        self._clock = clock or (lambda: 0)

    # -- connection + schema ------------------------------------------------ #

    def _conn(self):
        """A pooled connection. Every store method opens one, so without a pool each call
        paid a full TCP + TLS + auth round trip to Postgres — cheap to exhaust from the
        outside, since the data-layer routes are one-call-per-request."""
        return self._pool.connection()

    def init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(DDL)

    def truncate_all(self) -> None:
        """Wipe all rows (test helper)."""
        from shutter_governance_protocol.adapters.db.schema import TABLES

        with self._conn() as conn:
            conn.execute("TRUNCATE " + ", ".join(TABLES) + " CASCADE")
            conn.execute("ALTER SEQUENCE election_id_seq RESTART WITH 1")

    def _config(self, conn, election_id: bytes) -> ElectionConfig:
        row = conn.execute(
            "SELECT config FROM elections WHERE election_id = %s", (election_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown election {election_id.hex()}")
        return codecs.dec_config(row[0])

    # -- election lifecycle ------------------------------------------------- #

    def register_election(self, config: ElectionConfig, admin_sig: bytes) -> bytes:
        if not authz.verify_register(config.admin_key, admin_sig, config):
            raise WriteAuthorizationError("register: bad admin signature")
        with self._conn() as conn:
            # Serialize registrations so the peek below is consistent with the nextval
            # that follows. Registrations are rare and admin-driven, so a single
            # transaction-scoped advisory lock costs nothing.
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_REGISTER_LOCK_KEY,))
            # Peek the sequence head WITHOUT consuming it: the signed config asserts the
            # id it expects, and a mismatch must not burn an id (that would leave gaps and
            # break the "same dense 1..N ids on every backend" property).
            row = conn.execute(
                "SELECT last_value, is_called FROM election_id_seq"
            ).fetchone()
            peek = int(row[0]) + 1 if row[1] else int(row[0])
            expected = peek.to_bytes(32, "big")
            if config.election_id != expected:
                raise ImmutabilityError(
                    f"register: expected election id {config.election_id.hex()} but the next id is "
                    f"{expected.hex()} — the sequence moved on; re-read it and sign again"
                )
            (next_id,) = conn.execute("SELECT nextval('election_id_seq')").fetchone()
            election_id = int(next_id).to_bytes(32, "big")  # registry-style sequential id
            stored = replace(config, election_id=election_id)
            conn.execute(
                "INSERT INTO elections (election_id, config, admin_key, voting_start) "
                "VALUES (%s, %s, %s, %s)",
                (election_id, Jsonb(codecs.enc_config(stored)), stored.admin_key, stored.voting_start),
            )
        return election_id

    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT admin_key, voting_start FROM elections WHERE election_id = %s FOR UPDATE",
                (election_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            admin_key, voting_start = bytes(row[0]), int(row[1])
            if self._clock() >= voting_start:
                raise ImmutabilityError("Voting has already started; an election can only be cancelled before it opens.")
            if not authz.verify_request(admin_key, admin_sig, "cancel", election_id):
                raise WriteAuthorizationError("cancel: bad admin signature")
            conn.execute("UPDATE elections SET cancelled = TRUE WHERE election_id = %s", (election_id,))

    def get_election(self, election_id: bytes) -> ElectionRecord:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT config, cancelled, tally_stalled FROM elections WHERE election_id = %s", (election_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            config = codecs.dec_config(row[0])
            return ElectionRecord(
                config=config, cancelled=bool(row[1]), tally_stalled=bool(row[2]),
                finalized_key=self._finalized_key(conn, config),
            )

    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        with self._conn() as conn:
            if filter and filter.admin_key is not None:
                rows = conn.execute(
                    "SELECT election_id FROM elections WHERE admin_key = %s ORDER BY election_id",
                    (filter.admin_key,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT election_id FROM elections ORDER BY election_id").fetchall()
            return [bytes(r[0]) for r in rows]

    # -- DKG ---------------------------------------------------------------- #

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            committee = [bytes(p) for p in committee_pks]
            digest = write_auth.dkg_result_digest(election_id, bytes(pk_election), committee)
            idx = authz.keyper_index_by_recovery(config, digest, keyper_sig)
            submission = DKGResultSubmission(
                election_id=election_id,
                pk_election=bytes(pk_election),
                committee_pks=tuple(bytes(p) for p in committee_pks),
                keyper_signature=keyper_sig,
            )
            existing = conn.execute(
                "SELECT submission FROM dkg_submissions WHERE election_id = %s AND keyper_index = %s",
                (election_id, idx),
            ).fetchone()
            if existing is not None:
                prev = codecs.dec_dkg_result(existing[0])
                if (prev.pk_election, prev.committee_pks) != (submission.pk_election, submission.committee_pks):
                    raise ImmutabilityError(f"keyper {idx} already submitted a different DKG result")
                return
            # A new vote once voting has opened could finalize the key of an election that
            # has already failed for lack of one (the chain contract refuses it too).
            if self._clock() >= config.voting_start:
                raise VotingWindowError("DKG vote submitted after voting_start")
            conn.execute(
                "INSERT INTO dkg_submissions (election_id, keyper_index, submission) VALUES (%s, %s, %s)",
                (election_id, idx, Jsonb(codecs.enc_dkg_result(submission))),
            )

    def get_dkg_submissions(self, election_id) -> list[DKGResultSubmission]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT submission FROM dkg_submissions WHERE election_id = %s ORDER BY keyper_index",
                (election_id,),
            ).fetchall()
            return [codecs.dec_dkg_result(r[0]) for r in rows]

    def get_finalized_key(self, election_id) -> FinalizedKey | None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            return self._finalized_key(conn, config)

    def _finalized_key(self, conn, config: ElectionConfig) -> FinalizedKey | None:
        rows = conn.execute(
            "SELECT keyper_index, submission FROM dkg_submissions WHERE election_id = %s",
            (config.election_id,),
        ).fetchall()
        groups: dict[tuple, set[int]] = {}
        for idx, sub_json in rows:
            sub = codecs.dec_dkg_result(sub_json)
            groups.setdefault((sub.pk_election, sub.committee_pks), set()).add(int(idx))
        winner = resolve_unique(
            (((pk, com), kps) for (pk, com), kps in groups.items()),
            config.threshold.quorum, artifact="dkg result", election_id=config.election_id,
        )
        return FinalizedKey(pk_election=winner[0], committee_pks=winner[1]) if winner else None

    # -- ballots ------------------------------------------------------------ #

    def submit_ballot(self, election_id, ballot: BallotEnvelope, gateway_sig: bytes = b"") -> int:
        with self._conn() as conn:
            # Closed ballot-writer set. Empty gateway_keys = open writes.
            gateway_keys = self._config(conn, election_id).gateway_keys
            if gateway_keys:
                try:
                    recovered = write_auth.recover_digest(
                        write_auth.ballot_digest(election_id, ballot), gateway_sig)
                except Exception as exc:  # noqa: BLE001
                    raise WriteAuthorizationError("submit_ballot: bad gateway signature") from exc
                if recovered not in gateway_keys:
                    raise WriteAuthorizationError("submit_ballot: signature matches no registered gateway key")
            # Lock the election row to serialize sequence assignment (stable total order).
            locked = conn.execute(
                "SELECT 1 FROM elections WHERE election_id = %s FOR UPDATE", (election_id,)
            ).fetchone()
            if locked is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            now = self._clock()
            self._require_voting_open(conn, election_id, now)
            row = conn.execute(
                "SELECT COALESCE(MAX(seq) + 1, 0) FROM ballots WHERE election_id = %s", (election_id,)
            ).fetchone()
            seq = int(row[0])
            conn.execute(
                "INSERT INTO ballots (election_id, seq, ballot, submitted_at) VALUES (%s, %s, %s, %s)",
                (election_id, seq, Jsonb(codecs.enc_ballot(ballot)), now),
            )
            return seq

    def _require_voting_open(self, conn, election_id: bytes, now: int) -> None:
        """Reject a ballot written outside the open voting window.

        Mirrors the chain contract's ``submitVote`` gate set exactly
        (``_requireNotCancelled`` + ``dkgFinalized`` + ``[votingStart, votingEnd)``),
        which is precisely ``derive_state(...) is VOTING``. Using the same predicate
        the gateway and tally-time admission use means a ballot accepted here can
        never be excluded as ``OUT_OF_WINDOW`` later — the two checks cannot drift.

        Runs inside the caller's ``FOR UPDATE`` transaction, so the state it reads is
        consistent with the sequence number it is about to assign.
        """
        config = self._config(conn, election_id)
        cancelled = bool(
            conn.execute(
                "SELECT cancelled FROM elections WHERE election_id = %s", (election_id,)
            ).fetchone()[0]
        )
        result_published = (
            conn.execute(
                "SELECT 1 FROM results WHERE election_id = %s", (election_id,)
            ).fetchone()
            is not None
        )
        facts = StateFacts(
            cancelled=cancelled,
            key_finalized=self._finalized_key(conn, config) is not None,
            result_published=result_published,
        )
        if derive_state(config, facts, now) is not ElectionState.VOTING:
            raise VotingWindowError("ballot submitted outside the open voting window")

    def list_ballots(self, election_id, start: int, count: int) -> list[StoredBallot]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT seq, ballot, submitted_at FROM ballots "
                "WHERE election_id = %s AND seq >= %s ORDER BY seq LIMIT %s",
                (election_id, start, count),
            ).fetchall()
            out = []
            for seq, ballot, submitted_at in rows:
                envelope, reason = codecs.dec_stored_ballot(ballot)
                out.append(StoredBallot(
                    sequence_number=int(seq),
                    envelope=envelope,
                    submitted_at=None if submitted_at is None else int(submitted_at),
                    malformed_reason=reason,
                ))
            return out

    def count_ballots(self, election_id) -> int:
        with self._conn() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM ballots WHERE election_id = %s", (election_id,)
                ).fetchone()[0]
            )

    # -- tally artifacts ---------------------------------------------------- #

    def submit_aggregate(self, election_id, aggregate: AggregateArtifact, keyper_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            # reject an aggregate submitted before voting has closed
            if self._clock() < config.voting_end:
                raise VotingWindowError("aggregate submitted before voting_end")
            digest = write_auth.aggregate_digest_of(election_id, aggregate)
            idx = authz.keyper_index_by_recovery(config, digest, keyper_sig)
            # Lock the election row to serialize concurrent submissions (the finalize
            # check + override must be atomic — otherwise two overrides could race the
            # quorum). Mirrors submit_ballot's serialization.
            if conn.execute(
                "SELECT 1 FROM elections WHERE election_id = %s FOR UPDATE", (election_id,)
            ).fetchone() is None:
                raise KeyError(f"unknown election {election_id.hex()}")
            existing = conn.execute(
                "SELECT aggregate FROM aggregates WHERE election_id = %s AND keyper_index = %s",
                (election_id, idx),
            ).fetchone()
            if existing is not None and codecs.dec_aggregate(existing[0]) == aggregate:
                return  # idempotent resend of this keyper's current submission
            # Mutable per keyper *until the quorum finalizes*: a keyper that submitted a
            # wrong/stale aggregate can override it so honest keypers re-converge (a
            # deterministic re-derivation, unlike the append-only one-shot DKG result).
            if self._aggregate_finalized(conn, config):
                raise ImmutabilityError("aggregate already finalized (quorum reached)")
            conn.execute(
                """INSERT INTO aggregates (election_id, keyper_index, aggregate) VALUES (%s, %s, %s)
                   ON CONFLICT (election_id, keyper_index) DO UPDATE SET aggregate = EXCLUDED.aggregate""",
                (election_id, idx, Jsonb(codecs.enc_aggregate(aggregate))),
            )

    def _aggregate_group_counts(self, conn, election_id) -> dict[bytes, tuple[AggregateArtifact, set[int]]]:
        rows = conn.execute(
            "SELECT keyper_index, aggregate FROM aggregates WHERE election_id = %s",
            (election_id,),
        ).fetchall()
        groups: dict[bytes, tuple[AggregateArtifact, set[int]]] = {}
        for idx, agg_json in rows:
            agg = codecs.dec_aggregate(agg_json)
            key = write_auth.aggregate_digest_of(election_id, agg)
            _, keypers = groups.setdefault(key, (agg, set()))
            keypers.add(int(idx))
        return groups

    def _aggregate_finalized(self, conn, config: ElectionConfig) -> bool:
        return resolve_unique(
            self._aggregate_group_counts(conn, config.election_id).values(),
            config.threshold.quorum, artifact="aggregate", election_id=config.election_id,
        ) is not None

    def get_aggregate(self, election_id) -> AggregateArtifact | None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            return resolve_unique(
                self._aggregate_group_counts(conn, election_id).values(),
                config.threshold.quorum, artifact="aggregate", election_id=election_id,
            )

    def submit_decryption_share(self, election_id, share: DecryptionShareEnvelope, keyper_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            if self._clock() < config.voting_end:
                raise VotingWindowError("decryption share submitted before voting_end")
            if not self._aggregate_finalized(conn, config):  # in-tx (avoid a nested connection)
                raise VotingWindowError("decryption share submitted before a canonical aggregate exists")
            shares = [e.sigma for e in share.entries]
            proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
            digest = write_auth.decryption_share_digest(election_id, shares, proofs)
            idx = authz.keyper_index_by_recovery(config, digest, keyper_sig)
            if idx != share.keyper_index:
                raise WriteAuthorizationError(
                    f"share keyper_index {share.keyper_index} does not match signer {idx}"
                )
            existing = conn.execute(
                "SELECT share FROM decryption_shares WHERE election_id = %s AND keyper_index = %s",
                (election_id, idx),
            ).fetchone()
            if existing is not None:
                if codecs.dec_decryption_share(existing[0]) != share:
                    raise ImmutabilityError(f"keyper {idx} already submitted different shares")
                return
            conn.execute(
                "INSERT INTO decryption_shares (election_id, keyper_index, share) VALUES (%s, %s, %s)",
                (election_id, idx, Jsonb(codecs.enc_decryption_share(share))),
            )

    def list_decryption_shares(self, election_id) -> list[DecryptionShareEnvelope]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT share FROM decryption_shares WHERE election_id = %s ORDER BY keyper_index",
                (election_id,),
            ).fetchall()
            return [codecs.dec_decryption_share(r[0]) for r in rows]

    def publish_result(self, election_id, result: ResultArtifact, result_publisher_sig) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            if not authz.verify_request(
                config.result_publisher_key, result_publisher_sig, "result", election_id,
                write_auth.result_digest(election_id, result),
            ):
                raise WriteAuthorizationError("publish_result: bad result-publisher signature")
            existing = conn.execute(
                "SELECT result FROM results WHERE election_id = %s", (election_id,)
            ).fetchone()
            if existing is not None:
                if codecs.dec_result(existing[0]) != result:
                    raise ImmutabilityError("result already published (append-only)")
                return
            conn.execute(
                "INSERT INTO results (election_id, result) VALUES (%s, %s)",
                (election_id, Jsonb(codecs.enc_result(result))),
            )

    def set_tally_stalled(self, election_id, stalled: bool, sig, issued_at: int) -> None:
        with self._conn() as conn:
            config = self._config(conn, election_id)
            op = "tally_stall" if stalled else "tally_resume"
            # This write toggles a flag, so the digest has no content to bind and one
            # valid signature would otherwise authorise the toggle forever. The signer
            # binds a timestamp; it must be recent, and it is spent on use.
            if not authz.request_is_fresh(issued_at, self._clock()):
                raise WriteAuthorizationError(
                    f"{op}: issued_at {issued_at} is outside the "
                    f"+/-{authz.REQUEST_FRESHNESS_S}s acceptance window"
                )
            payload = authz.request_nonce_payload(issued_at)
            if stalled:
                # MARK — result publisher (coordinator) only; post-voting_end, no result yet.
                if self._clock() < config.voting_end:
                    raise VotingWindowError("cannot mark stalled: voting has not ended")
                if conn.execute("SELECT 1 FROM results WHERE election_id = %s", (election_id,)).fetchone() is not None:
                    raise ImmutabilityError("result already published; tally cannot be marked stalled")
                if not authz.verify_request(config.result_publisher_key, sig, op, election_id, payload):
                    raise WriteAuthorizationError("mark tally stalled: bad result-publisher signature")
            else:
                # CLEAR (retry) — election admin only.
                if not authz.verify_request(config.admin_key, sig, op, election_id, payload):
                    raise WriteAuthorizationError("clear tally stalled: bad admin signature")
            # The primary key is the check: a concurrent replay loses the insert rather
            # than racing a read. Spent after authorisation so an unauthenticated caller
            # cannot fill the table.
            spent = conn.execute(
                "INSERT INTO request_nonces (election_id, op, issued_at) VALUES (%s, %s, %s)"
                " ON CONFLICT DO NOTHING",
                (election_id, op, int(issued_at)),
            ).rowcount
            if not spent:
                raise WriteAuthorizationError(f"{op}: this request has already been used")
            conn.execute(
                "UPDATE elections SET tally_stalled = %s WHERE election_id = %s", (bool(stalled), election_id)
            )

    def get_result(self, election_id) -> ResultArtifact | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT result FROM results WHERE election_id = %s", (election_id,)
            ).fetchone()
            return codecs.dec_result(row[0]) if row else None

    def verifiability_tier(self) -> int:
        return 0
