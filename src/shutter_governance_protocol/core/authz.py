"""Write-authorization identities — secp256k1 / ecrecover.

Unified with the on-chain authorization model: a write identity is an **Ethereum
secp256k1 key**, its ``identity`` is the 20-byte address, and a write is
authorized by an EIP-191 signature that the verifier recovers with ``ecrecover``.
The same identity/signature works for the in-memory, database (verify by
``ecrecover``), and blockchain (relayed as a meta-tx the contract ``ecrecover``s)
data layers, so keypers/services are backend-agnostic.

This is defense-in-depth against spam, **not a trust anchor** — every stored
artifact is self-verifying. Voter **ballot** and **attestation** keys are
unrelated and remain Schnorr-G1 (see :mod:`shutter_governance_protocol.crypto`).
"""

from __future__ import annotations

from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak


REQUEST_DST = b"SHUTTER-GOVERNANCE-PROTOCOL-REQUEST-v1"


def request_digest(op: str, election_id: bytes, payload: bytes = b"") -> bytes:
    """32-byte digest a write signature is taken over.

    Each field is **length-framed** (4-byte big-endian length, then the bytes) under a
    domain-separation tag, matching the DKG digests in :mod:`shutter_governance_protocol.core.write_auth`.

    The previous encoding joined the three fields with a ``b"|"`` separator and no
    framing, which is ambiguous whenever a field can contain the separator:
    ``("a", b"b", b"c|d")`` and ``("a", b"b|c", b"d")`` both produced ``keccak(b"a|b|c|d")``
    and so shared one signature. It was not reachable in practice — the ops are fixed
    constants with no ``|``, and election ids are 32 bytes by convention — but nothing
    *enforced* the id length (this function accepted any), so the safety rested on
    convention rather than construction. Framing removes the ambiguity by construction:
    with explicit lengths no field can impersonate a boundary regardless of content.
    """
    op_b = op.encode("utf-8")
    return keccak(
        REQUEST_DST
        + len(op_b).to_bytes(4, "big") + op_b
        + len(election_id).to_bytes(4, "big") + bytes(election_id)
        + len(payload).to_bytes(4, "big") + bytes(payload)
    )


def request_nonce_payload(issued_at: int) -> bytes:
    """The freshness term a stall/resume request carries as its payload.

    request_digest binds the operation and the election, which stops a stall
    signature being presented as a resume or against another election -- but it binds
    nothing that changes, so one valid signature stayed valid forever. An observer who
    captured a legitimate tally_stall could replay it after every admin retry and
    keep a confidential tally from ever completing.

    Deduplicating the signature bytes instead does not work: Account.sign_message
    is RFC 6979 deterministic, so a genuine second stall of the same election is
    byte-identical to a replay. Rejecting duplicates would make re-stalling impossible.

    Eight bytes, big-endian, unsigned seconds. Byte-exact with the hub's
    requestNoncePayload and the browser's copy in helpers/shutterGovernanceProtocolRequest.ts; a
    verifier rejects a timestamp outside its window and accepts each one once.
    """
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at < 0:
        raise ValueError(f"issued_at must be a non-negative int, got {issued_at!r}")
    return int(issued_at).to_bytes(8, "big")


# How far a stall/resume request's issued_at may sit from the verifier's clock.
#
# Wide enough that ordinary clock skew between the coordinator, an admin's browser and
# the data layer never rejects an honest request; narrow enough that a captured
# signature stops being useful long before the next admin retry, which is the replay
# this bounds. Mirrors REQUEST_FRESHNESS_S in the hub.
REQUEST_FRESHNESS_S = 300


def request_is_fresh(issued_at: int, now: int) -> bool:
    """Is issued_at inside the acceptance window? Callers raise their own error."""
    return abs(int(now) - int(issued_at)) <= REQUEST_FRESHNESS_S


def sign_request(private_key: int, op: str, election_id: bytes, payload: bytes = b"") -> bytes:
    """Sign a write request (EIP-191 over the digest); returns the 65-byte signature.

    The key is passed as fixed 32-byte big-endian so an ``int`` with a zero top
    byte doesn't serialize to <32 bytes (which eth_account rejects).
    """
    key = int(private_key).to_bytes(32, "big")
    signed = Account.sign_message(encode_defunct(primitive=request_digest(op, election_id, payload)), key)
    return bytes(signed.signature)


def register_digest(config) -> bytes:
    """Digest a register signature is taken over: the canonical config, **including**
    ``election_id``.

    ``election_id`` carries the id the admin *expects* this registration to be assigned
    — the current sequence head plus one. The backend still assigns the id itself
    (``++electionCount`` / ``nextval``); it just refuses when its own next id disagrees
    with the signed one. So this is an assertion, not a caller-chosen id.

    Signing it is what makes a registration **single-use**: the moment the real
    registration lands, the next id moves on, so every replay of that exact body is
    permanently dead. It is the same construction as an Ethereum account nonce — the
    monotonic sequence *is* the replay guard, which is why no nonce table or expiry
    window is needed anywhere.
    """
    import json

    from shutter_governance_protocol.envelopes import codecs

    d = codecs.enc_config(config)
    return keccak(json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def sign_register(private_key: int, config) -> bytes:
    """Sign a registration request (EIP-191 over the config digest)."""
    key = int(private_key).to_bytes(32, "big")
    return bytes(Account.sign_message(encode_defunct(primitive=register_digest(config)), key).signature)


def verify_register(admin_key: bytes, signature: bytes, config) -> bool:
    """Recover the register signer and check it equals ``admin_key``. Never raises."""
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=register_digest(config)), signature=signature
        )
        return bytes.fromhex(recovered[2:]) == bytes(admin_key)
    except Exception:  # noqa: BLE001
        return False


def verify_request(identity: bytes, signature: bytes, op: str, election_id: bytes, payload: bytes = b"") -> bool:
    """Recover the signer and check it equals ``identity`` (a 20-byte address). Never raises."""
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=request_digest(op, election_id, payload)), signature=signature
        )
        return bytes.fromhex(recovered[2:]) == bytes(identity)
    except Exception:  # noqa: BLE001
        return False


@dataclass
class Signer:
    """A write identity: an Ethereum secp256k1 key whose ``identity`` is its address."""

    account: object  # eth_account LocalAccount

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Account.create())

    @classmethod
    def from_sk(cls, sk: int) -> "Signer":
        return cls(Account.from_key(int(sk).to_bytes(32, "big")))

    @property
    def identity(self) -> bytes:
        return bytes.fromhex(self.account.address[2:])

    @property
    def address(self) -> str:
        return self.account.address

    @property
    def private_key(self) -> int:
        return int.from_bytes(self.account.key, "big")

    def sign(self, op: str, election_id: bytes, payload: bytes = b"") -> bytes:
        return sign_request(self.private_key, op, election_id, payload)

    def sign_register(self, config) -> bytes:
        return sign_register(self.private_key, config)


def keyper_index_by_recovery(config, digest: bytes, sig: bytes) -> int:
    """Recover the keyper from a content signature; return its 1-based index.

    Shared by the in-memory and database adapters, which authorize keyper writes the
    same way.
    """
    from shutter_governance_protocol.core import write_auth
    from shutter_governance_protocol.ports.data_layer import WriteAuthorizationError

    try:
        recovered = write_auth.recover_digest(digest, sig)
    except Exception as exc:  # noqa: BLE001
        raise WriteAuthorizationError("bad keyper signature") from exc
    for i, k in enumerate(config.keypers, start=1):
        if k.signing_key == recovered:
            return i
    raise WriteAuthorizationError("signature matches no registered keyper")
