"""JSON transport-envelope codecs.

Encode/decode each artifact type to/from a JSON-ready ``dict`` with ``0x``-hex
byte fields. Decoders validate hex formatting and the fixed byte sizes of the
crypto suite (:mod:`shutter_governance_protocol.crypto.params`), so malformed input is rejected
at the boundary rather than surfacing later as an opaque crypto failure.

These dicts are the exact shapes the database adapter and the gateway API
exchange verbatim; the chain adapter maps the same fields onto contract structs.
"""

from __future__ import annotations

from typing import Any

from shutter_governance_protocol.core.config import (
    DuplicatePolicy,
    ElectionConfig,
    KeyperIdentity,
    Mode,
    Threshold,
    Variant,
)
from shutter_governance_protocol.envelopes.types import (
    BYTES32,
    DLEQ_BYTES,
    G1_BYTES,
    G2_BYTES,
    SCHNORR_BYTES,
    AggregateArtifact,
    Attestation,
    AttestationScheme,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    Exclusion,
    ExclusionReason,
    ResultArtifact,
)


class CodecError(ValueError):
    """Raised when an envelope cannot be decoded (malformed or wrong-size field)."""


# --------------------------------------------------------------------------- #
#  Primitive helpers
# --------------------------------------------------------------------------- #

def enc_bytes(b: bytes) -> str:
    """Encode raw bytes as a lowercase ``0x``-prefixed hex string."""
    return "0x" + b.hex()


def dec_bytes(value: Any, *, name: str, size: int | None = None) -> bytes:
    """Decode a ``0x``-hex string to bytes, validating format and optional size."""
    if not isinstance(value, str):
        raise CodecError(f"{name}: expected hex string, got {type(value).__name__}")
    if not value.startswith("0x"):
        raise CodecError(f"{name}: missing '0x' prefix")
    body = value[2:]
    try:
        raw = bytes.fromhex(body)
    except ValueError as exc:
        raise CodecError(f"{name}: invalid hex ({exc})") from exc
    if size is not None and len(raw) != size:
        raise CodecError(f"{name}: expected {size} bytes, got {len(raw)}")
    return raw


def _req(d: dict, key: str) -> Any:
    if not isinstance(d, dict):
        raise CodecError(f"expected object, got {type(d).__name__}")
    if key not in d:
        raise CodecError(f"missing field '{key}'")
    return d[key]


def _int(value: Any, *, name: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CodecError(f"{name}: expected integer, got {type(value).__name__}")
    if minimum is not None and value < minimum:
        raise CodecError(f"{name}: must be >= {minimum}, got {value}")
    return value


def _uint_str(n: int) -> str:
    """An unbounded integer as a decimal string for the wire.

    Weights, nonces and the totals derived from them are sent as strings: a JSON number
    above 2^53 is rounded by browser JSON parsers, and from 10^21 JavaScript also writes it
    back in exponent form. Either way a voter would sign, or post, a different number from
    the one the issuer signed.
    """
    return str(int(n))


def _big_int(value: Any, *, name: str, minimum: int | None = None) -> int:
    """Decode a field written by :func:`_uint_str`: a decimal string (digits only), or a
    JSON integer as earlier versions wrote it, so stored records still decode."""
    if isinstance(value, str):
        if not value.isascii() or not value.isdigit():
            raise CodecError(f"{name}: expected a decimal integer string, got {value!r}")
        value = int(value)
    return _int(value, name=name, minimum=minimum)


def _list(value: Any, *, name: str) -> list:
    if not isinstance(value, list):
        raise CodecError(f"{name}: expected array, got {type(value).__name__}")
    return value


# --------------------------------------------------------------------------- #
#  Ciphertext (shared sub-object)
# --------------------------------------------------------------------------- #

def enc_ciphertext(ct: Ciphertext) -> dict:
    return {"c1": enc_bytes(ct.c1), "c2": enc_bytes(ct.c2)}


def dec_ciphertext(d: Any, *, name: str = "ciphertext") -> Ciphertext:
    return Ciphertext(
        c1=dec_bytes(_req(d, "c1"), name=f"{name}.c1", size=G2_BYTES),
        c2=dec_bytes(_req(d, "c2"), name=f"{name}.c2", size=G2_BYTES),
    )


# --------------------------------------------------------------------------- #
#  Attestation (ATTESTATION_V1)
# --------------------------------------------------------------------------- #

def enc_attestation(a: Attestation) -> dict:
    return {
        "scheme": a.scheme.value,
        "electionId": enc_bytes(a.election_id),
        "pseudonym": enc_bytes(a.pseudonym),
        "vk": enc_bytes(a.vk),
        "weight": _uint_str(a.weight),
        "nonce": _uint_str(a.nonce),
        "signature": enc_bytes(a.signature),
    }


def dec_attestation(d: Any, *, name: str = "attestation") -> Attestation:
    # 'scheme' is optional on the wire; absent means the weighted V1 scheme.
    scheme_raw = d.get("scheme", AttestationScheme.V1.value) if isinstance(d, dict) else None
    try:
        scheme = AttestationScheme(scheme_raw)
    except ValueError as exc:
        raise CodecError(f"{name}.scheme: unknown scheme {scheme_raw!r}") from exc
    # 'nonce' is optional on the wire (absent → 1); V1 signatures bind it, so a wrong or
    # missing nonce simply fails signature verification (→ INVALID_ATTESTATION).
    nonce = _big_int(d["nonce"], name=f"{name}.nonce", minimum=1) if isinstance(d, dict) and "nonce" in d else 1
    return Attestation(
        election_id=dec_bytes(_req(d, "electionId"), name=f"{name}.electionId", size=BYTES32),
        pseudonym=dec_bytes(_req(d, "pseudonym"), name=f"{name}.pseudonym", size=BYTES32),
        vk=dec_bytes(_req(d, "vk"), name=f"{name}.vk", size=G1_BYTES),
        weight=_big_int(_req(d, "weight"), name=f"{name}.weight", minimum=1),
        signature=dec_bytes(_req(d, "signature"), name=f"{name}.signature", size=SCHNORR_BYTES),
        scheme=scheme,
        nonce=nonce,
    )


# --------------------------------------------------------------------------- #
#  Ballot
# --------------------------------------------------------------------------- #

#: What decoding untrusted ballot data can raise. ``CodecError``, ``JSONDecodeError`` and
#: ``UnicodeDecodeError`` are all ``ValueError``s; the others come from JSON of the wrong
#: shape (a list or a number where an object belongs), and ``RecursionError`` from
#: deeply nested JSON.
BALLOT_DECODE_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError)


def dec_stored_ballot(d: Any) -> tuple[BallotEnvelope | None, str | None]:
    """Decode a *stored* ballot: ``(envelope, None)``, or ``(None, reason)`` if it cannot be.

    For read paths only. A write must still reject a bad ballot with :func:`dec_ballot`,
    but a record that is already stored has to stay readable so admission can exclude
    it; see :class:`StoredBallot`.
    """
    if d is None:
        return None, "missing ballot"
    try:
        return dec_ballot(d), None
    except BALLOT_DECODE_ERRORS as exc:
        return None, f"{type(exc).__name__}: {exc}"


def enc_ballot(b: BallotEnvelope) -> dict:
    return {
        "electionId": enc_bytes(b.election_id),
        "pseudonym": enc_bytes(b.pseudonym),
        "vk": enc_bytes(b.vk),
        "ciphertexts": [enc_ciphertext(ct) for ct in b.ciphertexts],
        "zkProof": enc_bytes(b.zk_proof),
        "voterSignature": enc_bytes(b.voter_signature),
        "attestation": enc_attestation(b.attestation),
    }


def dec_ballot(d: Any) -> BallotEnvelope:
    cts = _list(_req(d, "ciphertexts"), name="ciphertexts")
    return BallotEnvelope(
        election_id=dec_bytes(_req(d, "electionId"), name="electionId", size=BYTES32),
        pseudonym=dec_bytes(_req(d, "pseudonym"), name="pseudonym", size=BYTES32),
        vk=dec_bytes(_req(d, "vk"), name="vk", size=G1_BYTES),
        ciphertexts=tuple(
            dec_ciphertext(ct, name=f"ciphertexts[{i}]") for i, ct in enumerate(cts)
        ),
        zk_proof=dec_bytes(_req(d, "zkProof"), name="zkProof"),
        voter_signature=dec_bytes(
            _req(d, "voterSignature"), name="voterSignature", size=SCHNORR_BYTES
        ),
        attestation=dec_attestation(_req(d, "attestation")),
        # Required, not optional. Nothing is deployed, so there is no ballot in
        # existence without one — and an optional binding is no binding at all:
        # an assembler would simply omit it.
    )


# --------------------------------------------------------------------------- #
#  DKG result submission
# --------------------------------------------------------------------------- #

def enc_dkg_result(s: DKGResultSubmission) -> dict:
    return {
        "electionId": enc_bytes(s.election_id),
        "pkElection": enc_bytes(s.pk_election),
        "committeePKs": [enc_bytes(p) for p in s.committee_pks],
        "keyperSignature": enc_bytes(s.keyper_signature),
        **({"submitter": enc_bytes(s.submitter)} if s.submitter is not None else {}),
    }


def dec_dkg_result(d: Any) -> DKGResultSubmission:
    pks = _list(_req(d, "committeePKs"), name="committeePKs")
    return DKGResultSubmission(
        election_id=dec_bytes(_req(d, "electionId"), name="electionId", size=BYTES32),
        pk_election=dec_bytes(_req(d, "pkElection"), name="pkElection", size=G2_BYTES),
        committee_pks=tuple(
            dec_bytes(p, name=f"committeePKs[{i}]", size=G2_BYTES) for i, p in enumerate(pks)
        ),
        keyper_signature=dec_bytes(_req(d, "keyperSignature"), name="keyperSignature"),
        # ``submitter`` is deliberately not read back: it is an unsigned claim, trusted
        # only when the chain adapter reads it from the contract itself. Accepting it from
        # the wire would let a dishonest data layer forge DKG votes the auditor counts.
    )


# --------------------------------------------------------------------------- #
#  Decryption share
# --------------------------------------------------------------------------- #

def enc_decryption_share(s: DecryptionShareEnvelope) -> dict:
    return {
        "electionId": enc_bytes(s.election_id),
        "keyperIndex": s.keyper_index,
        "entries": [
            {"sigma": enc_bytes(e.sigma), "proof": enc_bytes(e.proof)} for e in s.entries
        ],
    }


def dec_decryption_share(d: Any) -> DecryptionShareEnvelope:
    entries = _list(_req(d, "entries"), name="entries")
    return DecryptionShareEnvelope(
        election_id=dec_bytes(_req(d, "electionId"), name="electionId", size=BYTES32),
        keyper_index=_int(_req(d, "keyperIndex"), name="keyperIndex", minimum=0),
        entries=tuple(
            DecryptionShareEntry(
                sigma=dec_bytes(_req(e, "sigma"), name=f"entries[{i}].sigma", size=G2_BYTES),
                proof=dec_bytes(_req(e, "proof"), name=f"entries[{i}].proof", size=DLEQ_BYTES),
            )
            for i, e in enumerate(entries)
        ),
    )


# --------------------------------------------------------------------------- #
#  Aggregate (with admitted set)
# --------------------------------------------------------------------------- #

def enc_aggregate(a: AggregateArtifact) -> dict:
    return {
        "electionId": enc_bytes(a.election_id),
        "aggregates": [enc_ciphertext(ct) for ct in a.aggregates],
        "admitted": list(a.admitted),
        "exclusions": [
            {"sequenceNumber": x.sequence_number, "reason": x.reason.value}
            for x in a.exclusions
        ],
        "totalAdmittedWeight": _uint_str(a.total_admitted_weight),
        "totalScaledWeight": _uint_str(a.total_scaled_weight),
    }


def _dec_exclusion(d: Any, *, name: str) -> Exclusion:
    reason_raw = _req(d, "reason")
    try:
        reason = ExclusionReason(reason_raw)
    except ValueError as exc:
        raise CodecError(f"{name}.reason: unknown reason code {reason_raw!r}") from exc
    return Exclusion(
        sequence_number=_int(_req(d, "sequenceNumber"), name=f"{name}.sequenceNumber", minimum=0),
        reason=reason,
    )


def dec_aggregate(d: Any) -> AggregateArtifact:
    aggs = _list(_req(d, "aggregates"), name="aggregates")
    admitted = _list(_req(d, "admitted"), name="admitted")
    exclusions = _list(_req(d, "exclusions"), name="exclusions")
    return AggregateArtifact(
        election_id=dec_bytes(_req(d, "electionId"), name="electionId", size=BYTES32),
        aggregates=tuple(
            dec_ciphertext(ct, name=f"aggregates[{i}]") for i, ct in enumerate(aggs)
        ),
        admitted=tuple(
            _int(s, name=f"admitted[{i}]", minimum=0) for i, s in enumerate(admitted)
        ),
        exclusions=tuple(
            _dec_exclusion(x, name=f"exclusions[{i}]") for i, x in enumerate(exclusions)
        ),
        total_admitted_weight=_big_int(
            _req(d, "totalAdmittedWeight"), name="totalAdmittedWeight", minimum=0
        ),
        # Absent means a pre-scale artifact, produced before scaling existed. Those
        # were necessarily unscaled, so the scaled total equals the raw one and this
        # decodes them faithfully rather than rejecting them. See H10: the arity
        # check that distinguishes the two lives in `write_auth`, where a digest
        # mismatch would otherwise read as a bad signature.
        total_scaled_weight=_big_int(
            d.get("totalScaledWeight", _req(d, "totalAdmittedWeight")),
            name="totalScaledWeight",
            minimum=0,
        ),
    )


# --------------------------------------------------------------------------- #
#  Result
# --------------------------------------------------------------------------- #

def enc_result(r: ResultArtifact) -> dict:
    return {
        "electionId": enc_bytes(r.election_id),
        "totals": [_uint_str(t) for t in r.totals],
        "keyperIndices": list(r.keyper_indices),
        "bsgsBound": _uint_str(r.bsgs_bound),
    }


def dec_result(d: Any) -> ResultArtifact:
    totals = _list(_req(d, "totals"), name="totals")
    indices = _list(_req(d, "keyperIndices"), name="keyperIndices")
    return ResultArtifact(
        election_id=dec_bytes(_req(d, "electionId"), name="electionId", size=BYTES32),
        totals=tuple(_big_int(t, name=f"totals[{i}]", minimum=0) for i, t in enumerate(totals)),
        keyper_indices=tuple(
            _int(k, name=f"keyperIndices[{i}]", minimum=0) for i, k in enumerate(indices)
        ),
        bsgs_bound=_big_int(_req(d, "bsgsBound"), name="bsgsBound", minimum=0),
    )


# --------------------------------------------------------------------------- #
#  Election config (stored by the database adapter; also a transport shape)
# --------------------------------------------------------------------------- #

def enc_config(c: ElectionConfig) -> dict:
    return {
        "electionId": enc_bytes(c.election_id),
        "numCandidates": c.num_candidates,
        "budget": c.budget,
        "mode": c.mode.value,
        "variant": c.variant.value,
        "weighted": c.weighted,
        "scale": c.scale,
        "duplicatePolicy": c.duplicate_policy.value,
        "votingStart": c.voting_start,
        "votingEnd": c.voting_end,
        "threshold": {"t": c.threshold.t, "n": c.threshold.n},
        "keypers": [
            {"signingKey": enc_bytes(k.signing_key), "url": k.url} for k in c.keypers
        ],
        "eligibilityKey": enc_bytes(c.eligibility_key),
        "resultPublisherKey": enc_bytes(c.result_publisher_key),
        "gatewayKeys": [enc_bytes(g) for g in c.gateway_keys],
        "adminKey": enc_bytes(c.admin_key),
        "protocolVersion": c.protocol_version,
        # Decimal wei string (not a JSON number): fees can exceed JS's 2^53 safe-integer
        # range, and the register digest must byte-match between Python and the browser.
        "selfSubmitFee": str(c.self_submit_fee_wei),
    }


def _enum(cls, value, *, name: str):
    try:
        return cls(value)
    except ValueError as exc:
        raise CodecError(f"{name}: invalid {cls.__name__} {value!r}") from exc


def dec_config(d: Any) -> ElectionConfig:
    th = _req(d, "threshold")
    keypers = _list(_req(d, "keypers"), name="keypers")
    try:
        return ElectionConfig(
            election_id=dec_bytes(_req(d, "electionId"), name="electionId", size=BYTES32),
            num_candidates=_int(_req(d, "numCandidates"), name="numCandidates", minimum=1),
            budget=_int(_req(d, "budget"), name="budget", minimum=1),
            mode=_enum(Mode, _req(d, "mode"), name="mode"),
            variant=_enum(Variant, _req(d, "variant"), name="variant"),
            weighted=bool(_req(d, "weighted")),
            # Optional on the wire: a config written before scaling existed is an
            # unscaled one, and `1` is exactly that.
            scale=_int(d.get("scale", 1), name="scale", minimum=1),
            duplicate_policy=_enum(DuplicatePolicy, _req(d, "duplicatePolicy"), name="duplicatePolicy"),
            voting_start=_int(_req(d, "votingStart"), name="votingStart"),
            voting_end=_int(_req(d, "votingEnd"), name="votingEnd"),
            threshold=Threshold(t=_int(_req(th, "t"), name="threshold.t"),
                                n=_int(_req(th, "n"), name="threshold.n")),
            keypers=tuple(
                KeyperIdentity(
                    signing_key=dec_bytes(_req(k, "signingKey"), name=f"keypers[{i}].signingKey"),
                    url=str(_req(k, "url")),
                )
                for i, k in enumerate(keypers)
            ),
            eligibility_key=dec_bytes(_req(d, "eligibilityKey"), name="eligibilityKey"),
            result_publisher_key=dec_bytes(_req(d, "resultPublisherKey"), name="resultPublisherKey"),
            gateway_keys=tuple(
                dec_bytes(g, name=f"gatewayKeys[{i}]") for i, g in enumerate(_list(_req(d, "gatewayKeys"), name="gatewayKeys"))
            ),
            admin_key=dec_bytes(_req(d, "adminKey"), name="adminKey"),
            protocol_version=str(_req(d, "protocolVersion")),
            # Optional on the wire (absent → 0) for back-compat with configs written before
            # the field existed; accepts a decimal string or number.
            self_submit_fee_wei=int(d.get("selfSubmitFee", 0) or 0),
        )
    except ValueError as exc:
        # ElectionConfig.__post_init__ raises ValueError on invalid combinations.
        if isinstance(exc, CodecError):
            raise
        raise CodecError(f"invalid election config: {exc}") from exc
