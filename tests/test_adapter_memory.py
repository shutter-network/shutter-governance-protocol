"""Run the shared conformance suite against the in-memory adapter.

The in-memory adapter is the executable reference; the database and blockchain
adapters subclass ``DataLayerConformance`` the same way and must pass it
unmodified (each via its own backend seam).
"""

from __future__ import annotations

import pytest

from conformance import DataLayerConformance, ManualClock, SignatureBackend

from shutter_governance_protocol.adapters.memory import InMemoryDataLayer


class TestInMemoryConformance(DataLayerConformance):
    @pytest.fixture
    def backend(self):
        clock = ManualClock(0)
        return SignatureBackend(InMemoryDataLayer(clock=clock), clock)


def test_concurrent_aggregate_read_and_write_do_not_race(monkeypatch):
    """Keyper threads write aggregates while others read them. The quorum read iterates
    the per-keyper submissions, and a write landing mid-iteration raised
    "dictionary changed size during iteration" (seen as a flaky distributed-tally test).
    The reader's digest is slowed so the write reliably lands inside the read."""
    import threading
    import time

    from shutter_governance_protocol.core import write_auth
    from conformance import ELECTION_ID

    clock = ManualClock(0)
    backend = SignatureBackend(InMemoryDataLayer(clock=clock), clock)
    backend.register()
    backend.set_time(2_001)
    agg, other = backend.aggregate(), backend.aggregate(fill=0x50)
    backend.dl("keyper1").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper1", other))

    real = write_auth.aggregate_digest_of
    reading = threading.Event()

    def slow_digest(eid, a):
        if threading.current_thread() is reader:  # only the read is slowed
            reading.set()
            time.sleep(0.3)
        return real(eid, a)

    errors = []

    def read():
        try:
            backend.reader().get_aggregate(ELECTION_ID)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    sig = backend.aggregate_sig("keyper2", agg)  # signed before the digest is slowed
    monkeypatch.setattr(write_auth, "aggregate_digest_of", slow_digest)
    reader = threading.Thread(target=read)
    reader.start()
    reading.wait(5)
    backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, sig)
    reader.join(5)
    assert errors == []
