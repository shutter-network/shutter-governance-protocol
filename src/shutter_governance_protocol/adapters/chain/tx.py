"""Sign, send and confirm a transaction from a local account.

Shared by the chain adapter and the deploy helpers so every transaction gets the same
nonce handling and the same revert check.
"""

from __future__ import annotations

import threading

# One lock per sending address, shared by every adapter instance in the process. The API
# serves requests on several threads, and each ballot it relays is a transaction from the
# same gateway account: without the lock two threads read the same nonce, and all but one
# transaction is rejected ("replacement transaction underpriced"), losing those ballots.
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(address: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(address.lower(), threading.Lock())


# One lock per election contract, for quorum writes (DKG votes, aggregates). Whichever of
# two such writes is mined second may reach the quorum and do far more work (store the
# key or digest, emit the artifact) than its gas estimate, made before the first was
# mined, allowed for: it then runs out of gas. Holding this lock from the read-before-write
# check to the receipt makes each estimate see the state the previous write left.
_QUORUM_LOCKS: dict[str, threading.Lock] = {}


def quorum_write_lock(contract_address: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _QUORUM_LOCKS.setdefault(contract_address.lower(), threading.Lock())


def send_and_confirm(w3, account, fn, *, gas: int, value: int = 0):
    """Send ``fn`` from ``account`` and wait for it to be mined; raise if it reverted.

    The nonce is read as the *pending* count inside the per-address lock, so concurrent
    senders in this process get consecutive nonces. The lock is released before waiting
    for the receipt, so transactions are mined in parallel rather than one at a time.

    Covers one process per key. Two processes sending from the same key would need a
    shared nonce manager; the bundled services each use their own key.
    """
    with _lock_for(account.address):
        tx = fn.build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address, "pending"),
            "gas": int(gas),
            "gasPrice": w3.eth.gas_price,
            "value": int(value),
        })
        tx_hash = w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"transaction {tx_hash.hex()} reverted on chain")
    return receipt
