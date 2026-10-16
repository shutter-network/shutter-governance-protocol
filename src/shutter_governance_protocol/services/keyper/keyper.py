"""Keyper service.

A committee member: participates in the fresh per-election DKG, re-derives and
submits the deterministic aggregate (canonical at the t+1 quorum), and produces
precondition-guarded partial decryptions of the canonical aggregate. Keypers are
triggered automatically by the coordinator but **never trust the trigger** — before
producing shares a keyper re-derives the necessary facts from the data layer itself
. Aggregate integrity comes from the **t+1 keyper quorum** (a bogus aggregate
can't become canonical under the threshold assumption), so decryption needs no
separate honesty re-check.

The DKG round exchange here is in-process (driven by the coordinator); a
multi-operator deployment wraps the same round methods behind authenticated P2P
HTTP, which is a transport concern, not a protocol one.
"""

from __future__ import annotations

from shutter_governance_protocol.core import write_auth
from shutter_governance_protocol.core.admission import admit
from shutter_governance_protocol.services.common.reads import read_all_ballots
from shutter_governance_protocol.core.aggregation import build_aggregate_artifact
from shutter_governance_protocol.core.authz import Signer
from shutter_governance_protocol.crypto import proofs
from shutter_governance_protocol.crypto.dkg import KeyperDKGState, committee_keys, derive_joint_mpk
from shutter_governance_protocol.crypto.points import g2_from_compressed, g2_to_compressed
from shutter_governance_protocol.envelopes.types import DecryptionShareEntry, DecryptionShareEnvelope
from shutter_governance_protocol.ports.data_layer import ElectionDataLayer
from shutter_governance_protocol.core.state import ElectionState, StateFacts, derive_state


class KeyperRefusal(RuntimeError):
    """Raised when a keyper refuses to decrypt because a precondition fails."""


class KeyperService:
    def __init__(self, index: int, signer: Signer, data_layer: ElectionDataLayer, *, clock):
        self.index = index  # 1-based DKG id / keyper index
        self.signer = signer
        self.dl = data_layer
        self._clock = clock
        self.dkg = KeyperDKGState()

    # -- DKG (round methods; sequenced by the coordinator) ------------------ #

    def dkg_round1(self, n: int, t: int):
        """Generate this keyper's commitments and shares. Returns (commitments, shares)."""
        return self.dkg.round1(self.index, n, t)

    def dkg_round2(self, all_commitments: dict, received_shares: dict):
        """Verify received shares and form the combined secret share."""
        return self.dkg.round2(all_commitments, received_shares)

    def submit_dkg_result(self, election_id: bytes, all_commitments: dict) -> None:
        """Derive the joint key from all commitments and submit it (signed).

        Honest keypers submit byte-identical ``(pk_election, committee_pks)``, so
        the data layer's quorum rule finalizes the key.
        """
        quorum = self.dkg.quorum
        pk = derive_joint_mpk(all_commitments, quorum)
        committee = committee_keys(self.dkg.n, all_commitments, quorum)
        pk_b = g2_to_compressed(pk)
        committee_b = [g2_to_compressed(c) for c in committee]
        sig = write_auth.sign_dkg_result(self.signer.private_key, election_id, pk_b, committee_b)
        self.dl.submit_dkg_result(election_id, pk_b, committee_b, sig) # TODO

    # -- aggregation (keyper-quorum, mirrors the DKG-result quorum) ---------- #

    def check_can_aggregate(self, election_id: bytes):
        """The cheap self-guards :meth:`produce_aggregate` applies, without the expensive
        part. Returns the ``ElectionRecord`` so the caller need not re-read it.

        Split out so the HTTP layer can answer a genuine refusal *synchronously* (409)
        while the aggregation itself — which verifies every ballot and can run for many
        minutes — proceeds in the background. Raises :class:`KeyperRefusal`.
        """
        rec = self.dl.get_election(election_id)  # raises if unknown
        facts = StateFacts(
            cancelled=rec.cancelled,
            key_finalized=rec.finalized_key is not None,
            result_published=self.dl.get_result(election_id) is not None,
        )
        state = derive_state(rec.config, facts, self._clock())
        if state not in (ElectionState.TALLYING, ElectionState.COMPLETE):
            raise KeyperRefusal(f"refuse: state is {state.value}, not tallying")
        if rec.finalized_key is None:
            raise KeyperRefusal("refuse: no finalized key")
        return rec

    def produce_aggregate(self, election_id: bytes):
        """Re-derive the canonical aggregate from the data layer and sign it.

        Coupling aggregation into the committee: the keyper reads the ordered
        ballot list, runs the deterministic admission (``admit`` verifies every
        ballot and keeps only the valid, non-duplicate ones) and builds the
        weighted aggregate artifact. Because admission + aggregation are
        deterministic over the same stable-ordered ballots, honest keypers produce
        **byte-identical** artifacts; the data layer makes the aggregate canonical
        once ``t+1`` keypers submit the same one (see ``submit_aggregate``).

        Like decryption, the keyper never trusts the trigger — it self-guards
        on the derived state (must be ``Tallying`` or later, i.e. ``votingEnd``
        passed, key finalized). Returns ``(aggregate, signature)`` to submit, or
        ``None`` if this keyper already submitted (idempotent no-op). Reads only;
        the caller decides where to write.
        """
        rec = self.check_can_aggregate(election_id)
        cfg = rec.config

        # Idempotent: don't resubmit if this keyper already contributed.
        # get_aggregate returns the canonical (quorum) artifact — resubmitting an
        # already-canonical aggregate is a harmless no-op the data layer would
        # accept, but we skip the work when our own submission is already in.

        # Paged, and verified complete: ballot pages are capped server-side,
        # and a silently short read here would make this keyper aggregate a different
        # subset from the rest of the committee, so the t+1 byte-identical quorum would
        # never form. Rows carry the adapter's (sequence_number, submitted_at), so admit()'s
        # OUT_OF_WINDOW check runs against storage's own receive time.
        stored = read_all_ballots(self.dl, election_id)
        admission = admit(stored, cfg, rec.finalized_key.pk_election)  # only valid ballots admitted
        artifact = build_aggregate_artifact(cfg, admission)
        sig = write_auth.sign_aggregate(self.signer.private_key, election_id, artifact)
        return artifact, sig

    def aggregate_and_submit(self, election_id: bytes) -> bool:
        """Produce the aggregate and write it directly via ``self.dl``.

        **In-process test/simulation path only** (driven by
        ``tally_aggregator.trigger_aggregate``). The deployed keyper instead serves the
        HTTP ``/aggregate`` endpoint, which calls :meth:`produce_aggregate` and POSTs the
        signed artifact to the coordinator relay. Both share :meth:`produce_aggregate` —
        only the write transport differs. Idempotent per keyper: the data layer no-ops
        an identical resend; a changed submission overrides until the quorum finalizes.
        """
        produced = self.produce_aggregate(election_id)
        if produced is None:
            return True
        artifact, sig = produced
        self.dl.submit_aggregate(election_id, artifact, sig)
        return True

    # -- partial decryption with its preconditions ------------------------ #

    def produce_decryption_share(self, election_id: bytes):
        """Check the preconditions and produce this keyper's signed decryption share.

        Returns ``(share, signature)`` to submit, or ``None`` if this keyper already
        submitted for this election (idempotent no-op). Raises :class:`KeyperRefusal`
        if any precondition fails. All reads are against ``self.dl`` (the data layer);
        the caller decides where to *write* the result (directly, or via the
        coordinator relay), so this method never writes.

        The aggregate it decrypts is **canonical only at the t+1 byte-identical keyper
        quorum** (`get_aggregate`), so a bogus aggregate can't reach it under the
        threshold assumption — no separate honesty re-check is needed here.
        """
        rec = self.dl.get_election(election_id)  # raises if unknown → precondition 1
        cfg = rec.config

        # Precondition 1: voting has ended (derived state Tallying or later).
        facts = StateFacts(
            cancelled=rec.cancelled,
            key_finalized=rec.finalized_key is not None,
            result_published=self.dl.get_result(election_id) is not None,
        )
        state = derive_state(cfg, facts, self._clock())
        if state not in (ElectionState.TALLYING, ElectionState.COMPLETE):
            raise KeyperRefusal(f"refuse: state is {state.value}, not tallying")
        if rec.finalized_key is None:
            raise KeyperRefusal("refuse: no finalized key")

        # Precondition 2: a canonical aggregate exists — i.e. reached the t+1 keyper
        # quorum (get_aggregate returns it only then), the integrity guarantee.
        agg = self.dl.get_aggregate(election_id)
        if agg is None:
            raise KeyperRefusal("refuse: no aggregate published")

        # Precondition 3: not already decrypted (idempotent resend allowed).
        mine = [s for s in self.dl.list_decryption_shares(election_id) if s.keyper_index == self.index]
        if mine:
            return None

        entries = []
        for j, ct in enumerate(agg.aggregates):
            c1 = g2_from_compressed(ct.c1)
            c2 = g2_from_compressed(ct.c2)
            sigma = self.dkg.partial_decrypt(c1)
            t = proofs.make_decrypt_transcript(election_id, j)
            e, z = proofs.prove_decryption_share(
                t, c1, c2, self.dkg.public_key_share, sigma, self.dkg.combined_share, self.index
            )
            entries.append(DecryptionShareEntry(sigma=g2_to_compressed(sigma), proof=proofs.encode_dleq(e, z)))

        share = DecryptionShareEnvelope(election_id=election_id, keyper_index=self.index, entries=tuple(entries))
        sigmas = [e.sigma for e in entries]
        dleq_proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in entries]
        sig = write_auth.sign_decryption_share(self.signer.private_key, election_id, sigmas, dleq_proofs)
        return share, sig

    def decrypt_and_submit(self, election_id: bytes) -> bool:
        """Produce the share and write it directly via ``self.dl``.

        **In-process test/simulation path only** (driven by
        ``tally_aggregator.trigger_keypers``). The deployed keyper instead serves the
        HTTP ``/decrypt`` endpoint, which calls :meth:`produce_decryption_share` and
        POSTs the result to the coordinator relay. Both share
        :meth:`produce_decryption_share` — only the write transport differs. Idempotent:
        a keyper that already submitted is a no-op.
        """
        produced = self.produce_decryption_share(election_id)
        if produced is None:
            return True  # already submitted
        share, sig = produced
        self.dl.submit_decryption_share(election_id, share, sig)
        return True
