"""Encrypted on-disk persistence for a keyper's durable state.

A keyper's secret ``combined_share`` is created at DKG (before ``voting_start``)
but needed for decryption (after ``voting_end``) — days later — so it must
survive restarts. State lives under ``KEYPER_STATE_DIR`` in Fernet-encrypted
files, the key derived from the keyper's own signing key (so a stolen file
without the key is useless):

  - ``dkg_secrets.enc``      per-election combined shares + retention/pruning
  - ``encryption_key.enc``   the X25519 keypair used to unseal /auth/bootstrap
  - ``bootstrap_tokens.enc`` installed api/peer tokens + peers map

Shares carry an ``expires_at`` (a TTL past the election's ``voting_end``); a prune
loop drops expired entries so secrets don't pile up over time.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import pathlib
import threading
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from eth_utils import keccak

from shutter_governance_protocol.crypto.points import G2, mul


def default_state_dir() -> pathlib.Path:
    """CLI default: ``KEYPER_STATE_DIR`` env or ``/keyper-state``."""
    return pathlib.Path(os.environ.get("KEYPER_STATE_DIR", "/keyper-state"))


def derive_fernet(signing_sk: int) -> Fernet:
    """Derive the state-encryption key from the keyper's signing key."""
    material = keccak(b"KEYPER-FERNET-v1" + int(signing_sk).to_bytes(32, "big"))
    return Fernet(base64.urlsafe_b64encode(material))


@dataclass
class DkgEntry:
    combined_share: int
    expires_at: int | None = None
    # The key this share belongs to, fixed when round 2 completes. Publishing re-sends
    # exactly this, so a retried or post-restart publish can never produce a different
    # key: DKG votes are append-only per keyper, and a keyper that voted for one key and
    # then derived another could never help finalize either.
    pk_election: bytes | None = None
    committee_pks: tuple[bytes, ...] | None = None
    # Set once this keyper's vote for ``pk_election`` was accepted. From then on the
    # keyper refuses to start a new ceremony for the election.
    published: bool = False

    @property
    def public_key_share(self):
        return mul(G2, self.combined_share)


def _ensure(state_dir: pathlib.Path) -> pathlib.Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


def _write_atomic(path: pathlib.Path, data: bytes) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def save_dkg_secrets(fernet: Fernet, completed: dict[str, DkgEntry], state_dir: pathlib.Path) -> None:
    data = {}
    for eid, entry in completed.items():
        row: dict = {"share": hex(entry.combined_share)}
        if entry.expires_at is not None:
            row["expires_at"] = entry.expires_at
        if entry.pk_election is not None:
            row["pk_election"] = entry.pk_election.hex()
            row["committee_pks"] = [c.hex() for c in entry.committee_pks or ()]
        if entry.published:
            row["published"] = True
        data[eid] = row
    _write_atomic(_ensure(state_dir) / "dkg_secrets.enc", fernet.encrypt(json.dumps(data).encode()))


def load_dkg_secrets(fernet: Fernet, completed: dict[str, DkgEntry], state_dir: pathlib.Path, logger: logging.Logger) -> None:
    path = _ensure(state_dir) / "dkg_secrets.enc"
    if not path.exists():
        return
    try:
        data = json.loads(fernet.decrypt(path.read_bytes()))
        for eid, raw in data.items():
            exp = raw.get("expires_at")
            pk = raw.get("pk_election")
            completed[eid] = DkgEntry(
                int(raw["share"], 16), int(exp) if exp is not None else None,
                pk_election=bytes.fromhex(pk) if pk else None,
                committee_pks=tuple(bytes.fromhex(c) for c in raw["committee_pks"]) if pk else None,
                published=bool(raw.get("published", False)),
            )
        logger.info("op=load_dkg_secrets status=ok elections=%d", len(data))
    except InvalidToken:
        logger.error("op=load_dkg_secrets status=error reason=decryption_failed (starting empty)")
    except Exception as err:  # noqa: BLE001
        logger.error("op=load_dkg_secrets status=error err=%s", err)


def prune_expired(fernet: Fernet, completed: dict[str, DkgEntry], state_dir: pathlib.Path, logger: logging.Logger) -> list[str]:
    now = time.time()
    expired = [e for e, v in completed.items() if v.expires_at is not None and v.expires_at <= now]
    for e in expired:
        del completed[e]
    if expired:
        save_dkg_secrets(fernet, completed, state_dir)
        logger.info("op=prune_dkg_secrets removed=%d", len(expired))
    return expired


def load_or_create_x25519(fernet: Fernet, state_dir: pathlib.Path, logger: logging.Logger) -> X25519PrivateKey:
    """Load (or first-run generate + persist) the X25519 key that unseals
    bootstrap payloads — persisted so the coordinator's cached pubkey stays valid."""
    path = _ensure(state_dir) / "encryption_key.enc"
    if path.exists():
        try:
            return X25519PrivateKey.from_private_bytes(fernet.decrypt(path.read_bytes()))
        except InvalidToken:
            logger.error("op=load_encryption_key status=error reason=decryption_failed (regenerating)")
    key = X25519PrivateKey.generate()
    _write_atomic(path, fernet.encrypt(key.private_bytes_raw()))
    return key


def save_bootstrap_tokens(fernet: Fernet, api_token: str, peer_token: str, peers: dict,
                          state_dir: pathlib.Path, relay_token: str | None = None) -> None:
    payload = {"api_token": api_token, "peer_token": peer_token, "peers": peers, "relay_token": relay_token}
    _write_atomic(_ensure(state_dir) / "bootstrap_tokens.enc", fernet.encrypt(json.dumps(payload).encode()))


def load_bootstrap_tokens(fernet: Fernet, state_dir: pathlib.Path, logger: logging.Logger) -> dict | None:
    path = _ensure(state_dir) / "bootstrap_tokens.enc"
    if not path.exists():
        return None
    try:
        return json.loads(fernet.decrypt(path.read_bytes()))
    except Exception as err:  # noqa: BLE001
        logger.error("op=load_bootstrap_tokens status=error err=%s", err)
        return None


def start_prune_loop(completed, fernet, state_dir, logger, lock, *, interval_s: float = 3600.0) -> None:
    if interval_s <= 0:
        return

    def _loop():
        while True:
            time.sleep(interval_s)
            try:
                with lock:
                    prune_expired(fernet, completed, state_dir, logger)
            except Exception as err:  # noqa: BLE001
                logger.error("op=prune_dkg_secrets status=error err=%s", err)

    threading.Thread(target=_loop, name="dkg-prune", daemon=True).start()
