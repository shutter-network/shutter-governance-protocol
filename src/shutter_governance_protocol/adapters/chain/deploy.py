"""Deployment + Anvil helpers for the blockchain adapter (test + real-deploy).

Reads compiled bytecode from the Foundry ``contracts/out/`` artifacts, deploys the
registry, and offers Anvil devnet controls (time warp, state reset) used by the
conformance/e2e fixtures.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from web3 import Web3

from shutter_governance_protocol.adapters.chain.client import REGISTRY_ABI

_REPO_ROOT = Path(__file__).parents[4]
_CONTRACTS_OUT = Path(os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_CONTRACTS_OUT", _REPO_ROOT / "contracts" / "out"))

# Foundry link placeholder for an unlinked library reference: ``__$<34 hex>$__``.
_LINK_PLACEHOLDER = re.compile(r"__\$[0-9a-fA-F]{34}\$__")


def bytecode_of(name: str) -> str:
    artifact = json.loads((_CONTRACTS_OUT / f"{name}.sol" / f"{name}.json").read_text())
    return artifact["bytecode"]["object"]


def _link(bytecode_hex: str, address: str) -> str:
    """Substitute a deployed library address into Foundry's link placeholders.

    ``ElectionRegistry`` references the external ``ElectionDeployer`` library, so its
    compiled bytecode carries a ``__$…$__`` placeholder where the 20-byte library
    address must go before deployment (EIP-170 fix: the library, not the registry,
    holds Election's creation code). Only one library is referenced here."""
    addr = address.lower().removeprefix("0x")
    return _LINK_PLACEHOLDER.sub(addr, bytecode_hex)


def deploy_library(w3: Web3, account, name: str) -> str:
    """Deploy a linkable library (no constructor args); return its address."""
    lib = w3.eth.contract(abi=[], bytecode=bytecode_of(name))
    return send_tx(w3, account, lib.constructor()).contractAddress


def send_tx(w3: Web3, account, built_fn):
    """Sign+send a contract function/constructor call; return the receipt.

    Raises if the transaction reverts, so a failed deploy is not reported as a success."""
    from shutter_governance_protocol.adapters.chain.tx import send_and_confirm

    gas = built_fn.estimate_gas({"from": account.address})
    return send_and_confirm(w3, account, built_fn, gas=gas * 12 // 10)


def deploy_registry(w3: Web3, account) -> str:
    """Deploy an ElectionRegistry with ``account`` as DEFAULT_ADMIN_ROLE.

    First deploys the ``ElectionDeployer`` library and links its address into the
    registry bytecode (the registry delegates ``new Election`` to it to stay under
    the EIP-170 code-size limit)."""
    deployer_addr = deploy_library(w3, account, "ElectionDeployer")
    linked = _link(bytecode_of("ElectionRegistry"), deployer_addr)
    registry = w3.eth.contract(abi=REGISTRY_ABI, bytecode=linked)
    receipt = send_tx(w3, account, registry.constructor(account.address))
    return receipt.contractAddress


# -- Anvil devnet controls -------------------------------------------------- #

def anvil_set_time(w3: Web3, timestamp: int) -> None:
    """Warp the devnet clock: the next block is mined exactly at ``timestamp``."""
    w3.provider.make_request("evm_setNextBlockTimestamp", [timestamp])
    w3.provider.make_request("evm_mine", [])


def anvil_reset(w3: Web3) -> None:
    """Reset devnet state to genesis (fresh per-test isolation)."""
    w3.provider.make_request("anvil_reset", [{}])


def chain_now(w3: Web3):
    """A clock callable returning the latest block timestamp (chain time)."""
    return int(w3.eth.get_block("latest")["timestamp"])
