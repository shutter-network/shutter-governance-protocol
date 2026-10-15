"""Merlin-style Fiat-Shamir transcript and hash-to-scalar.

Byte-faithful reproduction of the SDK's ``Transcript`` (``transcript.ts`` /
``hash.ts``): an append-only, length-prefixed byte log whose ``challenge`` folds
the derived scalar back into the log so multi-challenge proofs stay separated.
Challenges use dual-keccak256 (``0x00``/``0x01`` prefixes) wide-reduced mod
``CURVE_ORDER``. This must stay identical across TS and Python — it is the
interop contract, enforced by the conformance vectors.
"""

from __future__ import annotations

from eth_utils import keccak

from shutter_governance_protocol.crypto.params import (
    CURVE_ORDER,
    DST_FIAT_SHAMIR,
    scalar_to_bytes,
    u32be,
    wide_reduce,
)
from shutter_governance_protocol.crypto.points import g2_to_compressed


class Transcript:
    """Length-prefixed Fiat-Shamir transcript.

    Construct with a label, then push tagged byte slices via ``append`` /
    ``append_point`` / ``append_scalar``. ``challenge(tag)`` returns a scalar in
    ``[0, CURVE_ORDER)`` and folds it back so the verifier reproduces state.
    """

    def __init__(self, label: str):
        self.parts: list[bytes] = [label.encode("utf-8")]

    def append(self, tag: str, value: bytes) -> None:
        tb = tag.encode("utf-8")
        self.parts.append(u32be(len(tb)))
        self.parts.append(tb)
        self.parts.append(u32be(len(value)))
        self.parts.append(bytes(value))

    def append_point(self, tag: str, point) -> None:
        """Append a G2 point by its 96-byte compressed encoding."""
        self.append(tag, g2_to_compressed(point))

    def append_scalar(self, tag: str, s: int) -> None:
        # Reject rather than reduce, as the SDK's ``appendScalar`` does. Reducing would
        # make ``s`` and ``s + CURVE_ORDER`` hash identically, so a signature over one
        # would also verify the other. An attestation's weight and nonce are used as raw
        # integers after verification, so that gap let a voter inflate them.
        if not (0 <= s < CURVE_ORDER):
            raise ValueError(f"{tag}: scalar out of range [0, CURVE_ORDER)")
        self.append(tag, scalar_to_bytes(s))

    def challenge(self, tag: str) -> int:
        tb = tag.encode("utf-8")
        head = DST_FIAT_SHAMIR + u32be(len(tb)) + tb
        preimage = head + b"".join(self.parts)
        h1 = keccak(b"\x00" + preimage)
        h2 = keccak(b"\x01" + preimage)
        e = wide_reduce(h1 + h2)
        self.append_scalar(tag + ":chal", e)
        return e

    def preimage(self) -> bytes:
        """The raw concatenated transcript bytes (label + all appended slices).

        Used by signature schemes (e.g. ATTESTATION_V1) that bind a transcript
        into a single signed message rather than deriving a challenge.
        """
        return b"".join(self.parts)


def hash_to_scalar(domain_sep: bytes, *parts: bytes) -> int:
    """Concatenation-form dual-keccak hash to a scalar (mirrors ``hash.ts``).

    Distinct from :class:`Transcript`, which length-prefixes every slice; this is
    a plain domain-separated concatenation used by the Schnorr challenge.
    """
    preimage = bytes(domain_sep) + b"".join(bytes(p) for p in parts)
    h1 = keccak(b"\x00" + preimage)
    h2 = keccak(b"\x01" + preimage)
    return wide_reduce(h1 + h2)
