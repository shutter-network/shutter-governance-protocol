# Shutter Governance Protocol

Shutter Governance Protocol is software for running private votes with results that others can check.
Voters make their choices in a browser, which encrypts each ballot before sending
it. After voting closes, the system adds the encrypted ballots together and
reveals the totals for each candidate. The normal counting process never opens
individual ballots.

Control of decryption is shared among a committee whose members are called
**keypers**. For example, an election can require two of three keypers to work
together to reveal the result. Public election records let others check which
ballots were counted and whether the published totals match.

```text
+--------------------------+
| Organiser sets up the    |
| election                 |
+--------------------------+
             |
             v
+--------------------------+
| Keypers prepare a shared |
| election key             |
+--------------------------+
             |
             v
+--------------------------+
| Voters cast encrypted    |
| ballots in their browsers|
+--------------------------+
             |
             v
+--------------------------+
| Voting closes            |
+--------------------------+
             |
             v
+--------------------------+
| Keypers agree on the     |
| encrypted count          |
+--------------------------+
             |
             v
+--------------------------+
| Keypers help reveal the  |
| candidate totals         |
+--------------------------+
             |
             v
+--------------------------+
| Anyone can verify the    |
| published result         |
+--------------------------+
```

The same voting system can store its records in PostgreSQL or on an Ethereum-compatible
blockchain. A blockchain is optional. An in-memory version is also included for tests.

## What you can do

- **Set up an election.** Use the admin app to choose candidates, voting dates,
  voting rules and the keyper committee.
- **Vote from a browser.** Use the voter app to submit an encrypted ballot.
  Voters can change their vote before the deadline; the count uses the valid
  ballot with the newest credential for each voter when the election uses
  `last-wins`. A `first-wins` election keeps the earliest credential instead.
- **Give voters equal or different voting power.** An eligibility service decides
  who may vote and how much each vote counts. Giving everyone a weight of one
  makes each person's vote count equally.
- **Check the count.** The dashboard includes verification tools, and the Python
  auditor can check election records against the published result.
- **Choose how to store records and identify voters.** Storage and eligibility
  connect through separate interfaces, so deployments can adapt them to their needs.
  The bundled eligibility examples use wallets; other identity systems need an
  integration.

## Try it or explore the project

| I want to… | Start here |
| --- | --- |
| Run a complete election locally | [Deployment walkthrough](./RUNNING.md) |
| Run the admin and voter apps | [Frontend guide](./frontend/README.md) |
| Work on the Python implementation | [Install and test](#install--test) |
| Use the blockchain contracts | [Smart contract guide](./contracts/README.md) |
| Estimate the resources needed to count votes | [Coordinator sizing](./COORDINATOR_SIZING.md) |

This repository includes the browser apps, Python services, smart contracts,
Docker Compose setups and tests. The bundled eligibility issuer is reference
code: a real deployment needs an issuer that reliably checks who may vote and
assigns the correct voting power. See [Architecture](#architecture) for the
integration requirements.

## How an election runs

1. **Set the rules.** The organiser registers the candidates, voting window,
   voting power rules and keyper committee before voting begins.
2. **Prepare the encryption key.** Keypers create a fresh shared key for the
   election. Each keeps only its own secret share. The required number of keypers
   must agree on the public key before voting opens.
3. **Cast votes.** The eligibility service gives each eligible voter a signed
   credential. The browser encrypts their choices and attaches mathematical proofs
   that the ballot follows the rules, without revealing those choices.
4. **Count while the ballots are still encrypted.** After voting closes, each
   keyper checks the ballots, applies the rules for repeat votes and voting power,
   and adds the accepted ballots together. The encrypted total is accepted when
   the required number of keypers submit exactly the same result.
5. **Reveal and check the totals.** Keypers provide the pieces needed to decrypt
   the combined count. The coordinator uses enough verified pieces to recover and
   publish the totals. Others can use the public records to check the result.

Privacy depends on fewer than the required number of keypers being compromised
and on a trustworthy data-layer read endpoint: the current keypers trust the
aggregate they receive at decryption time. In a two-of-three committee, one keyper cannot decrypt alone, but two cooperating
keypers could decrypt individual ballots. The browser also needs to be trustworthy:
this version cannot detect a compromised browser that changes or leaks a voter's
choice before encryption.

## Protocol details

The implementation uses **threshold ElGamal encryption over BLS12-381**. This lets
it add votes while they remain encrypted and share control of decryption across
keypers. It builds on the Munich staff-council election and Snapshot X private
voting systems.

- **Committee threshold.** `t` is the number of keypers required out of `n`:
  `(2, 3)` means two of three. The configuration requires `t` to be a strict
  majority. Distributed key generation (DKG) uses two rounds of Feldman VSS;
  confidential shares travel directly between keypers over authenticated HTTP.
  The election key is finalised when at least `t` keypers submit identical public
  results.
- **Voting window and repeat votes.** Ballots are accepted during
  `[votingStart, votingEnd)`, which includes the start time and excludes the end.
  The eligibility service gives each new credential an increasing number, called
  a nonce, for that voter and election. `last-wins` keeps the highest-nonce valid
  ballot; `first-wins` keeps the lowest. Storage order breaks ties. The v2 voter
  signature covers the full credential, preventing credential swaps on a ballot.
- **Voting power.** The eligibility service signs the weight into an
  `ATTESTATION_V1` credential; voters cannot choose their own weight. Admission
  accepts signed weights of at least one. Each ballot's contribution is multiplied
  by its weight divided by the election's `scale`, rounded half up. The default
  `scale = 1` leaves weights unchanged. Larger scales reduce counting costs but
  can round small weights to zero; see [Coordinator sizing](./COORDINATOR_SIZING.md).
- **Recovering and verifying totals.** The coordinator combines `t` verified
  decryption shares using Lagrange interpolation and recovers totals using
  baby-step/giant-step within a bound derived from admitted weights. The auditor
  checks the published totals against the verified shares without repeating that
  search. It also checks key finalisation, ballot admission and aggregation.
- **Election status.** Services calculate status from stored election facts and
  the current time: `Registered → KeyReady → Voting → Tallying → Complete`,
  with `Cancelled` and `DKGFailed` for elections that cannot proceed. A stalled
  tally can be marked `TallyStalled` and retried. There is no protocol deadline
  for completing a tally. Keypers check the required conditions themselves before
  acting on a request.

---

## Architecture

The services use the `ElectionDataLayer` interface to read and write election
records. Storage-specific code lives in its adapters. Services have three roles:

- **Admin plane** — Election Admin (sole config writer) and the coordinator,
  which drives key generation and counting and publishes results.
- **User plane** — Eligibility Service (issues the `ATTESTATION_V1` credential and is
  the sole authority on voter weight + eligibility), the Public API's ballot ingest
  (with an on-by-default filter; the former standalone gateway is now a library on the
  API), the browser crypto SDK.
- **Committee plane** — `n` Keyper services: fresh DKG per election, precondition-
  guarded partial decryption, private state encrypted at rest.

### Storage and eligibility interfaces

1. **`ElectionDataLayer` port** — the bulletin board. Adapters: **in-memory**
   (reference + executable spec), **database** (HTTP microservice over Postgres),
   **blockchain** (web3 over Foundry contracts). All three pass one conformance
   suite. Ballot proofs, signatures and tally checks support independent
   verification. The current implementation still trusts the aggregate returned
   to keypers at decryption time; see
   [the implementation limits below](#current-verification-limits).
2. **`EligibilityService` port** — issues/verifies `ATTESTATION_V1` over
   `(electionId, pseudonym, vk, weight, nonce)`. Issuance is adapter-specific
   (bundled stub and wallet examples; OIDC and Wahlregister require integration) and decides *who* may vote, *at what weight*,
   and allocates the per-(election, voter) re-vote **nonce**; **verification is
   normative and pure**. The bundled dev stub supports an optional allowlist (deny path)
   and a durable nonce store — see [`RUNNING.md`](./RUNNING.md).

**Integrator responsibility.** Voter *eligibility* and *who pays ballot gas* on the
blockchain backend belong to the external service integrating the protocol, not to the protocol
itself. Eligibility is the port above; gas is config-only (on-chain `submitVote` is
authorized by `msg.sender`, so the integrator either sponsors submission with a
funded key or lets voters self-pay). Note the privacy coupling for address-derived
pseudonyms — self-pay exposes the submitting address on-chain. Sponsored
submission hides that transaction-sender link, but the reference wallet adapter's
publicly derived pseudonym can still be matched to a known address. The bundled
HTTP issuer instead uses a secret-keyed HMAC. See
[`RUNNING.md`](./RUNNING.md).

> **The bundled eligibility issuer is reference code, not a production service.** The
> dev stub (`services/eligibility`), the wallet adapter (`adapters/eligibility_wallet`),
> and the chain voting-power reader (`adapters/voting_power`) exist to show the shape of
> the port; a real deployment supplies its own hardened issuer. Because the eligibility
> service is the **sole authority on weight**, a production implementation MUST, at
> minimum:
> - **Pin the voting-power snapshot block** (e.g. to the election's `votingStart` block)
>   rather than reading `"latest"`. `chain_voting_power(...)` defaults to `"latest"` for
>   convenience; left unpinned, a voter can move tokens between wallets and vote twice
>   with the same balance.
> - **Issue each voter's correct weight, and enforce eligibility durably** (the bundled
>   reissue/nonce guards are single-process). In a weighted election the protocol accepts
>   any signed weight of 1 or more, so a wrong weight from the issuer is counted as issued.
>   Weights are visible in every ballot, so an auditor can see a wrong one, but the protocol
>   does not reject it.
> - **Issue weight 1 in an unweighted (one per voter) election.** Admission excludes any
>   other weight there, so a voter given more would lose their ballot. The bundled issuer
>   reads each election's `weighted` setting through the public API and does this.
> - **Bind a freshness/expiry (and ideally a one-time nonce) into the wallet challenge**
>   so a captured signature can't be replayed to mint credentials.
>
> The protocol core verifies the attestation's signature, `weight ≥ 1` (exactly 1 in an
> unweighted election), and the bindings. It trusts the issuer for weight correctness in
> weighted elections by design.

### Source layout (`src/shutter_governance_protocol/`)

Layered top-to-bottom so imports flow downward:

- **`core/`** — the pure protocol kernel (no I/O): `config`, `state` (state
  derivation), `admission` (the correctness kernel), `aggregation` (weighted sum +
  recovery), `authz`, `write_auth`.
- **`crypto/`** — the BLS12-381 suite (ElGamal-G2, Schnorr-G1, DLEQ/OR/budget
  proofs, Feldman DKG, Lagrange + BSGS recovery).
- **`envelopes/`** — JSON transport envelopes + byte codecs (the interop contract).
- **`ports/`** — the abstraction seams (`data_layer`, `eligibility`).
- **`adapters/`** — backends behind the ports (`memory`, `db/`, `chain/`, eligibility).
- **`services/`** — one domain package per actor, each exposing a `__main__` when
  deployable.

---

## Data-layer backends

| Backend | Adapter | Authorization | Notes |
|---|---|---|---|
| **In-memory** | `shutter_governance_protocol.adapters.memory` | request signatures | Reference + executable spec; the conformance suite's baseline |
| **Database** | `shutter_governance_protocol.adapters.db` | request signatures (verified server-side) | Flask microservice + `HttpDataLayerClient` over Postgres; jsonb envelopes, per-election stable ordering under a row lock |
| **Blockchain** | `shutter_governance_protocol.adapters.chain` + `contracts/` | transaction sender + meta-tx | web3 over the Foundry bulletin-board; one adapter instance per actor bound to that actor's key |

All three satisfy the same port and run the same services; only the deployment
config differs.

---

## Services

Deployable packages provide a `python -m shutter_governance_protocol.services.<name>` entry point.
The tally, ballot admission and auditor packages also provide library functions:

| Service | Package | Role |
|---|---|---|
| **Data layer** | `data_layer` | Uniform HTTP service fronting any backend via `SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER=memory\|database\|blockchain` |
| **Public API** | `api` | CORS-enabled HTTP surface for frontends / external callers (port 8500). Reads are backend-blind (through the data-layer service); also hosts **ballot ingest** (`POST .../ballots`, formerly the gateway) with an on-by-default (non-authoritative) filter — signs requests on the database backend and funds `submitVote` transactions on chain |
| **Keyper** (×n) | `keyper` | Holds its identity + encrypted private state; runs DKG over HTTP; checks preconditions before `/publish_decr_share` |
| **Coordinator** | `coordinator` | Drives key generation and counting; relays keyper key-generation, aggregate and decryption writes; recovers and publishes results |
| **Tally aggregator** | `tally_aggregator` | Library used by the coordinator to recover and publish totals after keypers agree on the encrypted count |
| **Ballot admission** | `gateway` | Library (single-ballot filter) used by the API's ballot ingest; no standalone service |
| **Admin** | `admin` | `register`/`cancel` as CLI and admin-only HTTP service, authorized by the admin **wallet's EIP-191 signature** over the request (no bearer token) |
| **Eligibility** | `eligibility` | Standalone credential issuer (run separately): wallet-authenticated `/attest`, optional allowlist deny path, durable re-vote nonce store |
| **Auditor** | `auditor` | Independent re-verification of a finalized election from public reads |

---

## Security & authorization model

- **Write authorization is unified to secp256k1 / Ethereum `ecrecover`** across
  every actor (admin, aggregator, API ballot ingest, coordinator, keyper). On the
  in-memory and database backends this is an EIP-191 request signature verified by
  `shutter_governance_protocol.core.authz`; on chain it is the transaction sender.
- **Voter keys stay separate.** Ballot and attestation keys are Schnorr over G1
  (client-side), unrelated to the write-authz identities.
- **Keypers hold no data-layer write path and no gas.** They content-sign their DKG
  result, aggregate and decryption shares and POST `{payload, signature}` to the
  **coordinator**, which relays them:
  - on the DB backend, the coordinator forwards the signed write to the data-layer
    service;
  - on chain, the admin, coordinator (as result publisher) and API ballot ingest submit their
    own transactions (`msg.sender`), and **only keyper writes are relayed** as meta-transactions —
    the coordinator's relayer pays gas and the contract `ecrecover`s the keyper as
    the true author. Relaying a keyper write requires no on-chain role; the
    coordinator separately holds the result-publisher role.
- **Keyper bootstrap trust set.** A keyper's HTTP API requires bearer tokens
  installed through an X25519-sealed, secp256k1-signed (EIP-191)
  `/auth/bootstrap` request with a replay guard. Each keyper pins the identities
  allowed to bootstrap it. In the bundled deployment, the coordinator drives both
  key generation and counting.
- **Keyper secret storage.** DKG round-2 shares travel directly
  keyper→keyper; no single process observes all shares. Keyper secrets persist
  Fernet-encrypted at rest (key derived from the signing key), so a keyper survives
  the gap between DKG and decryption and reloads on restart.

### Current verification limits

Keypers compute their own aggregate when submitting it, but at decryption time
they trust the aggregate returned by the data-layer read endpoint. They do not
recompute it or verify the underlying quorum signatures at that step. A dishonest
read endpoint could therefore present an individual ballot as the aggregate.
The adapter's write-time quorum checks do not protect against that behaviour.

On the chain backend the auditor checks each DKG vote from the transaction that
cast it, using the keyper's own signature (or, for a vote the keyper sent itself, the
sender the contract authenticated), so it recounts the key quorum from what the keypers
actually voted.

### Trust boundary: the voter's browser

Ballot proofs check that an encrypted vote follows the rules; they cannot confirm
what the voter intended. This version has no **cast-as-intended** check: the browser encrypts the vote, so a compromised browser
can quietly encrypt a different choice (or leak it), and neither the voter nor any
auditor can tell.

---

## Cryptographic suite (protocol v1)

- **Group:** BLS12-381. ElGamal ciphertexts + DKG in **G2** (96-byte compressed);
  Schnorr signatures + attestations in **G1** (48-byte compressed). Zcash byte
  format, subgroup-checked on deserialize.
- **Encryption:** exponential ElGamal `C1 = r·P2`, `C2 = r·mpk + m·P2`; homomorphic
  by point addition.
- **Threshold:** `t`-of-`n` Feldman VSS DKG; partial decrypt `σ_k = msk_k·C1`
  with a DLEQ proof; Lagrange interpolation at zero; baby-step/giant-step recovery.
- **Proofs:** Fiat-Shamir over a Merlin-style transcript; **keccak256** throughout
  (fixed for cross-language vector compatibility).
- **Ballot validity:** Variant A (OR proof over `{0..B}`), weighted, in mode **exact**
  (`Σ = B`, proved by one DLEQ) or **atMost** (`Σ ≤ B`, proved by a `(B+1)`-branch OR
  proof over the sum). In atMost a blank ballot (all zeros) is valid: it counts toward
  turnout and adds no points. Variant B (bit decomposition) is specified and
  test-vectored but not yet implemented (conformance level 2); registration refuses it.

**Byte-for-byte TS↔Python compatibility is a protocol requirement,** enforced by a
cross-language conformance-vector suite (not merely a CI convenience). The browser
crypto is the published npm package `@shutter-network/urban-verified-crypto`; the
Python side reimplements the byte formats and verifies shared vectors. The
TypeScript parity harness is maintained outside this repository; the local
frontend test command does not run it. Current voter signatures use the v2
ballot message, while the proof codec and `ATTESTATION_V1` retain their versions.

---

## Smart contracts

The blockchain backend is a Foundry project under [`contracts/`](./contracts):

- `ElectionRegistry` — admin-gated factory + index; assigns sequential election ids.
- `KeyperSet` — immutable committee: members + per-member HTTP URLs + threshold.
- `Election` — per-election state machine (DKG voting, ballots, decryption shares,
  aggregate, result), assembled from facet contracts.

All curve points are stored as raw `bytes`; there is **no on-chain pairing or proof
verification** — proof validation runs off-chain in the keypers and verification tools, which keeps
gas costs down. The [verification limits above](#current-verification-limits) describe the remaining trust assumptions. Keyper writes support
meta-transaction variants (`voteDKGResultSigned`, `submitAggregateSigned`, `submitDecryptionShareSigned`) so
the relayer pays gas while the contract recovers the keyper as author. See
[`contracts/README.md`](./contracts/README.md) for the full interface.

---

## Layout

```
src/shutter_governance_protocol/
  core/                # pure protocol kernel: config, state, admission,
                       #   aggregation, authz, write_auth
  crypto/              # BLS12-381 crypto suite (ElGamal-G2, Schnorr-G1, proofs, DKG)
  envelopes/           # JSON transport envelopes + codecs
  ports/               # abstraction seams: data_layer, eligibility
  adapters/            # backends behind the ports: memory, db/, chain/, eligibility
  services/            # one domain package per actor: keyper/, coordinator/,
                       #   tally_aggregator/, gateway/, admin/, auditor/, data_layer/
frontend/              # admin and voter apps, shared dashboard and verification tools
contracts/             # Foundry bulletin-board contracts (blockchain backend)
deploy/                # docker-compose (db, chain-devnet, chain) — see RUNNING.md
scripts/               # env generation, sample voter, chain deploy helpers
tests/                 # unit, conformance, and end-to-end suites (+ vectors/)
```

---

## Install & test

Clone with submodules (the Foundry contract dependencies live in
`contracts/lib/` as pinned git submodules):

```sh
git clone --recurse-submodules <repo-url>
# already cloned without them? fetch with:
git submodule update --init --recursive
```

```sh
pip install -e '.[dev,db,chain,keyper]'
pytest
```

The Python test suite includes integration tests across
all three backends — in-memory, Postgres-over-HTTP, and blockchain-over-Anvil —
including the multi-operator HTTP keyper path. The Postgres tests use a dockerized
database (`docker compose -f tests/docker-compose.yml up -d`) and the chain tests
use Anvil (Foundry); both skip cleanly if those aren't available.

The contracts have their own Foundry test suite:

```sh
cd contracts && forge test
```

---

## Running

See [`RUNNING.md`](./RUNNING.md) for the full deployment guide. Two docker-compose
stacks are provided — a Postgres stack (`docker-compose.db.yml`) and a blockchain
stack (`docker-compose.chain-devnet.yml` for a throwaway Anvil devnet,
`docker-compose.chain.yml` for a real chain). Both have been driven through a
complete election by hand (register → DKG → vote → tally → decrypt → result),
producing identical results — the same services, the same wire format, only the
data layer differs.

---

## Status & roadmap

**Implemented end-to-end.** All three data-layer backends satisfy one port; the
same services run a full election on each, validated by the automated suite and by
hand-driven multi-election runs on both the Postgres and chain stacks.

Admin register/cancel is authorized by the admin wallet's EIP-191 signature (no shared
bearer token). Deferred beyond v1: keyper-set rotation/discovery and an optional ballot meta-transaction.
The coordinator already handles keyper orchestration, and aggregates require
agreement from the configured number of keypers.


## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See [LICENSE](LICENSE).
