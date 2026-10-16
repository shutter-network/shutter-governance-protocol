#!/usr/bin/env python3
"""Generate a consistent deployment identity set (env files only).

**Local / testing convenience — NOT a production tool.** It mints ALL identities
(including the keypers' private keys) in one place so a single machine can run the
whole stack for demos and the RUNNING.md walkthroughs. A real deployment does the
opposite: each keyper operator holds their own key on their own machine and only
shares their address, and the admin fills a real ``deploy/.env`` from ``.env.example``
by hand. Do not use the keys this emits for anything real — they are throwaway.

Its reason to exist is *coherence*: these secp256k1 identities are cross-referential
and hand-authoring them consistently is error-prone — each keyper's
``KEYPER_SIGNING_KEY`` must match the address the admin registers (the form resolves it
from the keyper's ``/status``), the coordinator's key must produce the
``COORDINATOR_IDENTITY`` keypers pin, and the eligibility private key must match the
eligibility *public* key the admin enters in the register form. This wires it up in one
shot:

    python scripts/gen_deploy_env.py

Writes (under ``deploy/``, relative to repo root):
  * ``.env``               — admin/operator-stack keys + tokens (the coordinator key
                             doubles as the chain relayer + result publisher)
  * ``.env.keyper{1,2,3}`` — one self-contained env per keyper stack (its key, pinned
                             coordinator address, port, state dir, plus the two admin
                             URLs it needs: ``SHUTTER_GOVERNANCE_PROTOCOL_API_URL`` for reads and
                             ``COORDINATOR_URL`` for its relayed writes)
  * ``.env.eligibility``   — the eligibility issuer's env (its private key + service
                             config), run with its own ``--env-file``

The election is registered through the admin frontend — this script does NOT emit a
config. The values the admin types into the register form (operator addresses + the
eligibility public key) are printed to stdout and noted in the env files.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from eth_account import Account

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from shutter_governance_protocol.crypto import schnorr  # noqa: E402
from shutter_governance_protocol.crypto.points import g1_to_compressed  # noqa: E402

N_KEYPERS = 3
T = 2  # (t, n) = (2, 3): any 2 of 3 decrypt — t IS the quorum

# Well-known Anvil dev accounts (default mnemonic "test test … junk"), accounts [0..2].
# This is a LOCAL-DEV generator, so the operator EOAs (admin / gateway / coordinator) use
# these PRE-FUNDED Anvil accounts — on the chain devnet they already hold ETH (no funding
# needed); on the db backend funding is irrelevant anyway. These keys are
# PUBLIC — never use this generated env against a real chain (real deploys supply their own
# funded keys via .env.example). Voters should use Anvil accounts [3+] to avoid clashing
# with the operator accounts.
_ANVIL_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # [0] admin
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",  # [1] gateway
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",  # [2] coordinator
]

# Eligibility issuer key. NOT an EOA — it's a Schnorr-on-G1 (BLS12-381) key, so its public
# key is a 48-byte G1 point, not an address. We seed it from a fixed Anvil private key
# (account [9], distinct from the operators [0..2] and the voter examples [3..6]) so the
# issuer's public key is DETERMINISTIC across runs. Public throwaway; never use on a real chain.
_ELIGIBILITY_DEV_KEY = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073d0b4a5c12a"  # Anvil [9]


def _key():
    acct = Account.create()
    return acct.key.hex(), acct.address  # (0x-hex privkey, 0x checksummed address)


def _anvil(i: int):
    """A well-known pre-funded Anvil account [i] as ``(0x-hex privkey, address)``."""
    acct = Account.from_key(_ANVIL_KEYS[i])
    return acct.key.hex(), acct.address


def main() -> None:
    # Operator EOAs = pre-funded Anvil accounts [0..2] (local-dev generator; see _ANVIL_KEYS).
    # So the chain devnet accounts are already funded, and it's harmless on the db backend.
    admin_sk, admin_addr = _anvil(0)
    gw_sk, gw_addr = _anvil(1)
    coord_sk, coord_addr = _anvil(2)  # coordinator: bootstrap identity + result publisher + chain relayer
    # Keypers hold NO chain key (writes are relayed; ecrecover'd from the content signature),
    # so they never pay gas and need no funding — random identities are fine.
    keypers = [_key() for _ in range(N_KEYPERS)]

    elig_sk, elig_vk = schnorr.keygen(int(_ELIGIBILITY_DEV_KEY, 16))  # deterministic dev issuer key
    elig_pub_hex = "0x" + g1_to_compressed(elig_vk).hex()  # register-form eligibility_key (== GET :8600/health)

    out = REPO / "deploy"
    out.mkdir(exist_ok=True)

    coordinator_api_token = secrets.token_urlsafe(32)  # shared: coordinator relay ↔ keypers

    # Comments live on their own lines (never inline after a value) so the file
    # parses cleanly with `source`/`grep|cut`, not just docker compose --env-file.
    env_lines = [
        "# Generated by scripts/gen_deploy_env.py — one coherent identity set.",
        "# LOCAL DEV ONLY: admin/gateway/coordinator are the PUBLIC pre-funded Anvil accounts",
        "# [0..2], already funded on the chain devnet. Never use these on a real chain.",
        "# This file is git-ignored. Do NOT commit.",
        "",
        "# The admin EOA (Anvil [0]): registers/cancels; on chain the adminAddr; and the key the",
        "# admin wallet signs register/cancel with (no bearer token).",
        f"ADMIN_SIGNING_KEY={admin_sk}",
        "# Gateway = the API's on-chain ballot sender (the vote proxy).",
        f"GATEWAY_SIGNING_KEY={gw_sk}",
        "# Coordinator identity: the address keypers pin for bootstrap, the",
        "# result_publisher (signs the result), AND — on chain — the funded account",
        "# that relays keyper meta-tx and sends publishResult (holds RESULT_PUBLISHER_ROLE).",
        f"COORDINATOR_SIGNING_KEY={coord_sk}",
        f"# coordinator address (give to keyper operators out-of-band): {coord_addr.lower()}",
        "# Bearer token keypers present to the coordinator's write-relay endpoints.",
        f"COORDINATOR_API_TOKEN={coordinator_api_token}",
        "",
        "# Keypers run as SEPARATE stacks — their private keys + the pinned coordinator",
        "# address live in deploy/.env.keyper{1,2,3} (also generated), NOT here.",
        "",
        "# Blockchain backend only (the coordinator's account above is the gas-paying",
        "# relayer for keyper meta-tx and the result publisher):",
        "# SHUTTER_GOVERNANCE_PROTOCOL_CHAIN_RPC=http://anvil:8545",
        "# SHUTTER_GOVERNANCE_PROTOCOL_REGISTRY_ADDRESS: leave UNSET on the devnet — the chain-devnet compose",
        "# auto-deploys the registry on `up` at a deterministic address and defaults to it.",
        "# Set it only for a real chain (registry deployed out of band).",
        "",
        "# The eligibility service is a SEPARATE operator concern — its private key + service",
        "# config live in deploy/.env.eligibility (generated below), NOT here.",
        "",
        "# ---- register-form reference (values the admin types into the register form) ----",
        f"# admin (adminAddr):            {admin_addr.lower()}   (auto-filled from the connected wallet)",
        f"# vote-proxy / gateway (chain): {gw_addr.lower()}",
        f"# result publisher (chain):     {coord_addr.lower()}   (= coordinator)",
        f"# eligibility public key:       {elig_pub_hex}   (also in .env.eligibility; == GET :8600/health)",
        "# keyper URLs:                  http://host.docker.internal:8101 / :8102 / :8103",
        "#                               (the form resolves each keyper's address via its /status)",
        "# --------------------------------------------------------------------------------",
        "",
    ]
    (out / ".env").write_text("\n".join(env_lines))

    # Eligibility operator env (separate stack, separate party). Holds the issuing PRIVATE
    # key; its public key is the eligibility_key the admin enters in the register form. Run
    # the eligibility compose with `--env-file deploy/.env.eligibility`.
    (out / ".env.eligibility").write_text("\n".join([
        "# Eligibility issuer env — generated by gen_deploy_env.py. Run the eligibility",
        "# service with:  docker compose -f deploy/docker-compose.eligibility.yml \\",
        "#                  --env-file deploy/.env.eligibility up -d --build",
        "# The issuing key's public key MUST equal the eligibility_key the admin enters in the",
        "# register form (this script prints it; it also == GET :8600/health):",
        f"#   eligibility public key: {elig_pub_hex}",
        f"ELIGIBILITY_PRIVATE_KEY={hex(elig_sk)}",
        "ELIGIBILITY_PORT=8600",
        "# The public API's base URL: the issuer reads each election's config through it, so an",
        "# unweighted (one per voter) election is issued weight 1.",
        "SHUTTER_GOVERNANCE_PROTOCOL_API_URL=http://host.docker.internal:8500",
        "# Default weight granted to an eligible wallet (dummy issuer).",
        "ELIGIBILITY_DUMMY_WEIGHT=1",
        "# Optional deny path: point at the mounted allowlist to gate issuance. Unset = allow all",
        "# (every wallet gets ELIGIBILITY_DUMMY_WEIGHT above, so the per-wallet weights in the",
        "# allowlist file are IGNORED until this is uncommented). Needs a container recreate.",
        "# ELIGIBILITY_ALLOWLIST=/app/eligibility-allowlist.json",
        "",
    ]))

    # Per-keyper operator env files (one self-contained env per keyper stack) — this is
    # where each keyper's private key + the pinned coordinator address live. The admin URLs
    # default to host.docker.internal (correct for local split testing); a real operator on
    # their own machine edits them, or starts from .env.keyper.example.
    keyper_env_files = []
    for i, (sk, _addr) in enumerate(keypers):
        port = 8101 + i  # keyper N listens on 810N (matches the URL the admin enters)
        (out / f".env.keyper{i + 1}").write_text("\n".join([
            f"# keyper{i + 1} operator env — generated by gen_deploy_env.py.",
            f"KEYPER_SIGNING_KEY={sk}",
            f"COORDINATOR_IDENTITY={coord_addr.lower()}",
            "# (relay bearer token is NOT here — the coordinator pushes it via /auth/bootstrap)",
            "# Reads: the public API's BASE url — the keyper appends its read-surface path itself.",
            "SHUTTER_GOVERNANCE_PROTOCOL_API_URL=http://host.docker.internal:8500",
            "# Writes: signed DKG/aggregate/decryption artifacts, relayed by the coordinator.",
            "COORDINATOR_URL=http://host.docker.internal:8400",
            f"KEYPER_PORT={port}",
            f"KEYPER_STATE_DIR_HOST=../keyper-state{i + 1}",
            "",
        ]))
        keyper_env_files.append(f".env.keyper{i + 1}")

    print(f"wrote {out/'.env'}")
    print(f"wrote {out/'.env.eligibility'}")
    for f in keyper_env_files:
        print(f"wrote {out/f}")
    print("--- register-form reference ---")
    print(f"admin={admin_addr} gateway={gw_addr}")
    print(f"coordinator={coord_addr}  (result publisher + chain relayer)")
    for i, (_sk, addr) in enumerate(keypers, start=1):
        print(f"keyper{i}={addr}")
    print(f"eligibility public key={elig_pub_hex}")


if __name__ == "__main__":
    main()
