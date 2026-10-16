#!/usr/bin/env python3
"""Check every ballot in a live election carries a valid voter binding.

The binding is what ties a ballot to the credential it was cast with. Admission
already enforces it — a bad one is excluded as INVALID_ATTESTATION — but an
exclusion tells you a ballot was refused, not *why*, and a tally that silently
drops every ballot looks much like an eligibility misconfiguration. This checks
the property directly, against ballots the data layer actually served.

Read-only. Point it at whichever backend is running:

    python3 scripts/verify_binding_live.py --url http://localhost:8500/port \
        --election 0x<32-byte hex>

The `api` service mounts the read surface at `/port` (:8500 in the db stack); the
coordinator's own root surface (:8400) serves the full contract. Either works —
this only reads.
"""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="data-layer base URL")
    ap.add_argument("--election", required=True, help="0x-prefixed 32-byte election id")
    args = ap.parse_args()

    from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient
    from shutter_governance_protocol.core.admission import validate_ballot
    # The paging + completeness read the committee itself uses, rather than a
    # hand-rolled loop that could disagree with it about what "all ballots" means.
    from shutter_governance_protocol.services.common.reads import read_all_ballots
    from shutter_governance_protocol.crypto.binding import (
        ballot_message_digest,
        envelope_binding_message,
        verify_binding_sig,
    )
    from shutter_governance_protocol.crypto.points import g2_from_compressed

    eid = bytes.fromhex(args.election.removeprefix("0x"))
    dl = HttpDataLayerClient(args.url)

    config = dl.get_election(eid).config
    mpk_bytes = dl.get_finalized_key(eid).pk_election
    mpk = g2_from_compressed(mpk_bytes)
    ballots = read_all_ballots(dl, eid)
    print(f"election {args.election}: {len(ballots)} ballot(s)")

    failures = 0
    for sb in ballots:
        env = sb.envelope
        if env is None:
            print(f"  #{sb.sequence_number}: malformed record ({sb.malformed_reason})")
            failures += 1
            continue
        att = env.attestation
        bound = verify_binding_sig(
            env.vk,
            envelope_binding_message(env, ballot_message_digest(env)),
            env.voter_attestation_signature,
        )
        # `validate_ballot` is the committee's own verdict — reported beside the
        # binding so a ballot refused for some *other* reason is not mistaken for
        # a binding failure.
        reason = validate_ballot(sb, config, mpk)
        ok = bound and reason is None
        failures += 0 if ok else 1
        print(
            f"  seq={sb.sequence_number:<4} weight={att.weight:<8} nonce={att.nonce:<8}"
            f" binding={'ok' if bound else 'FAILED'}"
            f" admission={'ok' if reason is None else reason.value}"
        )

    # An empty election is not a pass. Reporting success over zero ballots is how a
    # checker tells you everything is fine when nothing was checked at all — the
    # same hole the sx port-contract script had, where a stub hub returning count=0
    # satisfied every assertion.
    if not ballots:
        print("RESULT: NOTHING CHECKED — the election has no ballots")
        return 2
    print("RESULT:", "all bindings valid" if failures == 0 else f"{failures} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
