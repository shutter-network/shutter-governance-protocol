"""Retention default for a keyper's per-election secrets.

Retention itself is deliberate — operators need the secret for late or repeated
decryption — so the 90-day window is unchanged. What the fix changes is the *fallback*:
an unset `KEYPER_SECRET_TTL_S` used to produce `expires_at=None` and nothing was ever
pruned, so safe behaviour depended on the compose file passing the variable and a bare
`python -m shutter_governance_protocol.services.keyper` kept every historical share for ever.
"""

from __future__ import annotations

import pytest

from shutter_governance_protocol.services.keyper.keyper_server import _DEFAULT_SECRET_RETENTION_S, _parse_secret_ttl


def test_code_default_matches_the_compose_default():
    """Pinned so the two cannot drift apart (docker-compose.keyper.yml passes 7776000)."""
    assert _DEFAULT_SECRET_RETENTION_S == 7_776_000 == 90 * 24 * 3600


@pytest.mark.parametrize("raw", [None, "", "  "])
def test_unset_or_blank_is_finite_not_forever(raw):
    """The regression this closes. Blank matters as much as unset: a compose var or env
    file entry that is set-but-empty arrives as "", which a plain getenv default misses."""
    assert _parse_secret_ttl(raw) == _DEFAULT_SECRET_RETENTION_S


@pytest.mark.parametrize("raw,want", [("3600", 3600), (" 60 ", 60), ("0", 0)])
def test_explicit_values_keep_their_meaning(raw, want):
    assert _parse_secret_ttl(raw) == want


def test_indefinite_retention_stays_available_but_must_be_stated():
    assert _parse_secret_ttl("never") is None
    assert _parse_secret_ttl("NEVER") is None


def test_malformed_value_raises_rather_than_retaining_forever():
    """Silently falling back to indefinite retention is the failure mode being closed."""
    with pytest.raises(ValueError):
        _parse_secret_ttl("90d")


def test_dkg_entry_round_trips_its_key_and_published_flag(tmp_path):
    """The key fixed at round 2 and the published flag survive a restart. Entries written
    before these fields existed still load, with no key and not published."""
    import json
    import logging

    from shutter_governance_protocol.services.keyper import keyper_persistence as persist

    fernet = persist.derive_fernet(0x1234)
    entry = persist.DkgEntry(5, 99, pk_election=b"\x01" * 96, committee_pks=(b"\x02" * 96, b"\x03" * 96),
                             published=True)
    persist.save_dkg_secrets(fernet, {"aa": entry}, tmp_path)
    loaded: dict = {}
    persist.load_dkg_secrets(fernet, loaded, tmp_path, logging.getLogger("t"))
    assert loaded["aa"] == entry

    (tmp_path / "dkg_secrets.enc").write_bytes(fernet.encrypt(json.dumps({"bb": {"share": "0x7"}}).encode()))
    old: dict = {}
    persist.load_dkg_secrets(fernet, old, tmp_path, logging.getLogger("t"))
    assert old["bb"] == persist.DkgEntry(7)
