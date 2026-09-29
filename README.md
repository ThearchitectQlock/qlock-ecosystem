<div align="center">

# Q-Lock

**Post-quantum settlement infrastructure.**

One cryptographic core. Two ledgers built on it. A security platform around both.

[![Rust](https://img.shields.io/badge/rust-1.88-orange)](https://www.rust-lang.org)
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--87%20(Dilithium5)-blue)](https://csrc.nist.gov/pubs/fips/204/final)
[![Crates](https://img.shields.io/badge/workspace-16%20crates-lightgrey)]()
[![Tests](https://img.shields.io/badge/tests-292%20Rust%20%2B%2024%20Solidity-brightgreen)]()
[![Guards](https://img.shields.io/badge/security%20guards-13%2F13-brightgreen)]()

*For Nevaeh.*

</div>

---

## Contents

- [What this is](#what-this-is)
- [Architecture](#architecture)
- [Workspace](#workspace)
- [NEV369](#nev369)
- [GodShield](#godshield)
- [Q-Lock Escrow](#q-lock-escrow)
- [The ETH bridge](#the-eth-bridge)
- [Nevaeh's inheritance](#nevaehs-inheritance)
- [Frontends](#frontends)
- [Building](#building)
- [Running it](#running-it)
- [Configuration](#configuration)
- [Status](#status)
- [Contributing](#contributing)
- [Whitepaper](#whitepaper)
- [License](#license)

---

## What this is

Most value on public blockchains is secured by elliptic-curve signatures —
ECDSA, Ed25519, secp256k1. Shor's algorithm breaks all of them on a
sufficiently capable quantum computer. That machine does not exist yet. The
signatures do, and they are public forever. "Harvest now, decrypt later" is a
present-tense problem with a future-tense deadline.

**GodShield** is the cryptographic foundation and the security platform built on
it: ML-DSA-87 (Dilithium5, NIST FIPS 204 Level 5) signing over a SHA3-512 →
BLAKE3 → SHA3-512 cascade, plus identity, policy, threshold authorization,
continuous monitoring and tamper-evident audit.

**NEV369** is a post-quantum proof-of-work Layer-1 that uses it for everything —
transaction signing, block hashing, Merkle construction.

**Q-Lock Escrow** is non-custodial escrow on the XRP Ledger with post-quantum
attestation over every settlement.

**The ETH bridge** carries NEV369 to Ethereum as wNEV, authorized by an *m*-of-*n*
set of independent signers.

---

## Architecture

```
                      ┌────────────────────────────┐
                      │       godshield-core       │
                      │  ML-DSA-87 · TripleHash    │
                      │  CanonicalMessage          │
                      └─────────────┬──────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
┌───────┴────────┐        ┌─────────┴─────────┐      ┌──────────┴─────────┐
│  GodShield     │        │      NEV369       │      │   Q-Lock Escrow    │
│  platform      │        │   Layer-1 (PoW)   │      │   XRP Ledger       │
│                │        │                   │      │                    │
│ gateway        │        │ chain · consensus │      │ non-custodial      │
│ identity       │        │ genesis · sync    │      │ Xaman / Ledger     │
│ sentinel       │        │ libp2p gossip     │      │ PQ attestation     │
│ bridge         │        │ miner · metrics   │      │ Stripe billing     │
│ scanner        │        └─────────┬─────────┘      │ inheritance CLI    │
│ adapters       │                  │                └──────────┬─────────┘
│ fairness       │                  │                           │
│ wasm · api     │        ┌─────────┴──────────┐                │
└───────┬────────┘        │  ETH bridge        │                │
        │                 │  relayer (m-of-n)  │                │
        │                 │  submitter (gas)   │                │
        │                 │  wNEV · Bridge.sol │                │
        │                 └─────────┬──────────┘                │
        └──────────┬────────────────┴───────────────────────────┘
                   │
      ┌────────────┴────────────┐
      │                         │
┌─────┴──────┐        ┌─────────┴─────────┐
│ Q-Lock     │        │  NEV369 Explorer  │
│ Ecosystem  │        │  public, read-only│
│ console    │        └───────────────────┘
└────────────┘
```

---

## Workspace

16 crates, 21,000+ lines of Rust, 292 Rust tests, 24 Solidity tests.

| Crate | What it does |
|---|---|
| `godshield-core` | ML-DSA-87 signing, TripleHash cascade, `CanonicalMessage` |
| `godshield-gateway` | Policy boundary: allowlists, value limits, rate limits, key rotation with history, hash-chained audit |
| `godshield-identity` | Identity records, credentials, signed machine actions |
| `godshield-sentinel` | Correlation, graduated response, tamper-evident incident evidence |
| `godshield-bridge` | Threshold authorization, finality, replay, exposure limits, circuit breaker |
| `godshield-scanner` | Source-level detection of quantum-vulnerable primitives |
| `godshield-adapters` | Chain adapters: BTC, ETH, SOL, NEV369 |
| `godshield-fairness` | Commit-reveal RNG with signed, verifiable outcomes |
| `godshield-api` | REST service: verification, scanning, and the PQ Security Gateway |
| `godshield-cli` | `godshield` — keygen, sign, verify, scan, address, **send**, **balance**, vault |
| `godshield-wasm` | Browser-side signing |
| `nevaeh-vault` | Shamir split, AES-256-GCM, time-lock |
| `qlock-escrow` | XRPL escrow backend + `qlock-inheritance` ceremony CLI |
| `nev369-node` | The Layer-1 |
| `nev369-relayer` | Bridge coordinator — collects signer attestations, holds no key |
| `nev369-submitter` | Carries authorized mints to Ethereum with a gas-only key |

**Domain tags.** Every signed structure carries one, inside the signed bytes, so
a signature over one thing can never be replayed as another. Adding a signed
structure means adding a row here in the same PR.

| Tag | Signs |
|---|---|
| `nev369.tx.v1` | Transactions |
| `nev369.block.v1` | Block headers |
| `nev369.merkle` · `nev369.empty` | Merkle pairs · empty-block root |
| `godshield.fairness.outcome.v1` | RNG outcome derivation |
| `godshield.fairness.reveal.v1` | Signed reveal records |
| `fairness.round.v1` | Fairness round commitments |
| `godshield.bridge.mint.v1` | Bridge mint attestations (PQ audit trail) |
| `qlock.attestation.v1` | Settlement attestations |
| `qlock.escrow.v1` · `qlock.escrow.v2` | Escrow terms (v2: per-field canonical) |
| `GODSHIELD-CREDENTIAL-V1` | Credentials |
| `GODSHIELD-MACHINE-ACTION-V1` | Machine actions |
| `GODSHIELD-GATEWAY-ATTESTATION-V1` | Gateway attestations |
| `GODSHIELD-AUDIT-V1` | Audit chain entries |
| `GODSHIELD-SENTINEL-SIGNAL-V1` · `-EVIDENCE-V1` | Sentinel signals and incident evidence |

> **Never edit a tag's encoding in place.** Bump the version. Editing invalidates
> every signature ever produced under it, including records already on the chain
> and in the database.

---

## NEV369

Post-quantum Layer-1. actix-web API, libp2p (gossipsub, mDNS, identify, noise,
yamux, TCP), request/response block sync, sled storage, background PoW miner.

### Supply

| | NEV | Share |
|---|---|---|
| **Cap** | 369,369,369 | 100% |
| Mineable | 322,469,369 | 87.30% |
| Nevaeh premine | 36,900,000 | 9.99% — locked until 28 July 2039 |
| Architect premine | 10,000,000 | 2.71% — spendable immediately |

**Every NEV is reachable.** Each one either exists at genesis or gets mined — 369
NEV per block, halving every 437,000 blocks (~303 days at 60-second targets).

A pure halving schedule cannot land on 322,469,369 exactly, so `block_reward_at`
clamps each reward to what remains of `MINEABLE_SUPPLY`. The final rewarded block
(height 5,741,772) pays the exact remainder. The test
`total_emission_reaches_the_cap_to_the_base_unit` walks every rewarded block and
asserts `emitted + premine == MAX_SUPPLY` to the base unit.

### Wallets: send and receive NEV369

```bash
cargo install --path crates/godshield-cli
godshield wallet new                                   # nev369_wallet.json + your address
godshield wallet open --wallet nev369_wallet.json      # browser wallet: balance, send, receive, history
godshield wallet open --vault architect_vault.json     # same page for a Shamir vault (share files chosen at send)
```

`wallet new` seals one Dilithium5 key with your password (Argon2id, 64 MiB, then
AES-256-GCM, with the address authenticated). `wallet open` serves the wallet page
from your own machine on 127.0.0.1. Each session gets a one-time link token, the
page rejects foreign Host and Origin headers, and signing runs in Rust with the
same code the node verifies with. The key is decrypted only for the moment it
signs, then wiped. The explorer shows any address's balance and full history.

Mining, joining the network and day-to-day sending are covered step by step in
[`docs/MINING.md`](docs/MINING.md).

### Your Architect wallet — 10,000,000 NEV

```bash
make vault-architect G1="Me:-:home safe" G2="Name:-:where" G3="Name:-:where"
# 2-of-3, no time-lock. Prints the vault's Identifier (your public key).
# Put it in .env as NEV369_ARCHITECT_ADDRESS before the chain's first start.
godshield balance --vault architect_vault.json
godshield send --vault architect_vault.json \
  --share architect_shares/share_1_Me.json --share architect_shares/share_2_Name.json \
  --to <recipient address> --amount 250000
```

`send` unlocks the key in memory from two shares, shows the transaction, asks you
to type the amount, signs it with Dilithium5 and submits it. The key never touches
disk. `--offline --nonce N` signs on an air-gapped machine and prints the JSON.

### Consensus guarantees

- **Money is `u64` base units, 8 decimals.** Never float.
- **Block contents execute against a scratch state.** Each transaction is
  validated against the effects of the ones before it in the same block, which is
  what catches an in-block double-spend.
- **Two signature exemptions only** — `GENESIS` and `NETWORK_REWARD`, both
  protocol-internal. A unit test and a CI guard keep the list at exactly two.
- **Sender is the public key.** Verification derives the address from the
  supplied key bytes and rejects any mismatch.
- **Fork choice by accumulated work**, not height. Ties go to the incumbent.
- **Timestamps are consensus rules.** Future drift bounded at 2h, monotonic
  against the parent.
- **Reorgs replay from scratch** (max depth 100) and requeue disconnected
  transactions. Coinbases are never requeued.
- **Premine addresses come from the vault ceremony**, pinned into genesis. A node
  whose config disagrees with its recorded genesis refuses to start.
- **The genesis block carries the dedication to Nevaeh**, inside the hashed header.

### API

| Method | Path | |
|---|---|---|
| GET | `/health` | liveness + height |
| GET | `/info` | height, tip, difficulty, reward, supply, cumulative work |
| GET | `/chain?limit=N` | most recent N blocks (≤ 200), each tx with its `hash` |
| GET | `/block/{index or hash}` | one block; block 0 carries the dedication |
| GET | `/tx/{hash}` | confirmed or pending transaction |
| GET | `/balance/{address}` | balance, nonce, time-lock status |
| GET | `/address/{address}/transactions?limit=N` | history in and out (≤ 200, newest first) + pending |
| GET | `/mempool` | pending transactions |
| GET | `/vault/nevaeh` | the time-locked vault, publicly verifiable |
| GET | `/metrics` | Prometheus: height, difficulty, reorgs, tip age, mempool… |
| POST | `/tx/submit` | signed transaction (rate limited) |
| POST | `/mine` | one bounded PoW attempt (development, or `NEV369_HTTP_MINING=1`) |
| POST | `/wallet/new` | development-only keypair; refused in production |

---

## GodShield

A platform, not a library. Sections map to the GodShield platform specification.

### §1 PQ Security Gateway

The cryptographic policy boundary, served by `godshield-api`:

| Method | Path | Access |
|---|---|---|
| POST | `/api/v1/gateway/verify` | public — identity-bound verification, key resolved by timestamp |
| POST | `/api/v1/gateway/policy/check` | public — ALLOW / DENY with policy id |
| POST | `/api/v1/gateway/identity/register` | admin |
| POST | `/api/v1/gateway/key/rotate` | admin — history kept, old signatures still verify |
| POST | `/api/v1/gateway/sign` | admin — gateway attestation with its own key |
| GET | `/api/v1/gateway/audit` | public — hash-chained audit log, integrity checked |

**`sign` is deliberately narrow.** A service holding customer keys and signing
whatever an authenticated caller sends is a signing oracle — one compromised
token signs anything, forever. The gateway signs *only* its own attestations, from
a closed set of kinds, under a fixed domain tag. Customer keys stay in customer
custody.

**Rotation resolves by timestamp**, so NEV369 blocks, escrow attestations and
audit entries signed years ago keep verifying. **The audit chain is
tamper-evident**: each entry's hash feeds the next, so editing entry N breaks
every entry after it.

### §2 Migration Engine

`godshield-scanner`. 20 primitive families with identifier-boundary matching —
CamelCase-aware, comment- and string-literal-aware — directory walking and CI exit
codes. `make scan` / `make scan-gate`.

### §3 Identity · §4 Machine Security

`godshield-identity`. Identity and credential records in four states (ACTIVE,
SUSPENDED, REVOKED, EXPIRED), signed machine actions with replay protection.
Expiry is computed, never trusted from storage. Revoking an issuer kills the
credentials it signed. Verification and authorization are kept apart — a valid
signature is not authority.

### §5 Sentinel

`godshield-sentinel`. Detection → correlation → risk → policy → response →
containment → recovery → evidence. Reversible actions are automatic; irreversible
ones escalate to a human. Protected identities are never contained automatically.
Evidence is preserved, with a digest, before containment.

### §12 Bridge Security

`godshield-bridge`. Five gates: event verification, finality, replay, exposure
limits, threshold authorization. Signers are deduplicated by fingerprint before
counting; `threshold: 1` is refused in code; the circuit breaker trips on a
reconciliation gap and never self-heals.

### §13 PQ Foundation

`godshield-core`. ML-DSA-87 (Dilithium5) — 2,592-byte public keys, ~4.6 KB signatures.
SHA3-512 → BLAKE3 → SHA3-512 is defense in depth: no single hash family's break is
immediately fatal.

---

## Q-Lock Escrow

Non-custodial XRPL escrow using native `EscrowCreate` / `EscrowFinish` /
`EscrowCancel`. Axum + Postgres.

- **No server-side key can move user funds.** Signing happens in Xaman on the
  user's phone or on a Ledger over WebHID.
- **Every settlement carries a Dilithium5 attestation.** In production the
  identity is the persistent `QLOCK_ATTESTATION_KEY` whose fingerprint Q-Lock
  publishes; the server refuses to start without it.
- **Billing is Stripe subscriptions.** Webhooks are verified with HMAC-SHA256 in
  constant time with a 5-minute replay window, and every event id is recorded so a
  retry is never applied twice.

| Plan | Fee | Monthly escrows |
|---|---|---|
| Free | 0.30% | 5 |
| Pro | 0.20% | unlimited |
| Enterprise | 0.15% | unlimited |

Settlement is hybrid: real XRPL signatures settle, and a parallel post-quantum
attestation proves what was agreed. XRPL itself cannot verify Dilithium at
consensus; no deployed public chain can yet.

---

## The ETH bridge

`contracts/` — `wNEV.sol` and `NEV369Bridge.sol` (Foundry, OpenZeppelin v5.0.2),
plus two Rust services.

**How a mint happens**

1. NEV is locked on NEV369.
2. Each independent signer observes the lock past finality and sends the
   coordinator (`nev369-relayer`) two things: a Dilithium5 attestation over the
   canonical terms (the post-quantum audit trail) and an EIP-712 ECDSA signature
   over the same terms.
3. When `BRIDGE_THRESHOLD` distinct signers agree on byte-identical terms, inside
   the exposure limits, the coordinator marks the mint authorized. It holds no
   signing key and cannot create an authorization itself.
4. `nev369-submitter` sends `mintFromNEV369` with the signatures sorted by signer
   address. It holds a gas-only key and refuses to start if that key is a signer.
5. `NEV369Bridge` recovers each signature, requires strictly ascending signer
   addresses (which enforces distinctness), checks the threshold, and mints.

**wNEV uses 8 decimals**, matching NEV369 base units, so 1 NEV locked is exactly 1
wNEV minted. Deployment is four stages over 96+ hours because of two 48-hour
timelocks; `script/Deploy.s.sol` walks it and requires ≥ 3 signers and a threshold
≥ 2.

---

## Nevaeh's inheritance

Full ceremony and recovery instructions:
[`docs/nevaeh-vault-ceremony.md`](docs/nevaeh-vault-ceremony.md).

**The inheritance is an XRP Ledger native escrow**, locked by XRPL consensus until
28 July 2039. No code in this repository can release it early.

```bash
qlock-inheritance create --grantor r... --destination r... --amount 10000   # prints unsigned EscrowCreate
qlock-inheritance record --tx-hash <hash>                                    # verifies on-ledger, records OfferSequence
```

NEV369 holds her premine too — 36,900,000 NEV, locked until 28 July 2039.

| Vault | Holds | Threshold | Locked |
|---|---|---|---|
| `nevaeh-xrpl-seed` | XRPL family seed | 3-of-5 | to 2039 |
| `nevaeh-nev369` | Dilithium5 key | 3-of-5 | to 2039 |
| `architect-wallet` | Dilithium5 key | 2-of-3 | no |

**`OfferSequence` is the most losable value in the design.** `record` looks it up
on-ledger and checks every term, and the database refuses to mark an escrow
`locked` without `xrpl_owner` and `xrpl_offer_sequence`.

---

## Frontends

**`apps/qlock-web`** — the Q-Lock Ecosystem console: live status of every
service, escrow, NEV369, bridge, the vault countdown and the genesis dedication.
Served at the nginx root.

**`apps/nev369-explorer`** — public block explorer with emission curve, block and
transaction views, address lookup and deep links (`#/block/12`, `#/tx/…`,
`#/address/…`). Served at `/explorer/` on q-lock-ecosystem.com, reading the node through `/node/`.
`?api=` points it at any node.

---

## Building

```bash
cargo generate-lockfile        # once — then commit Cargo.lock
cargo build --workspace --release
cargo test --workspace --release
bash scripts/security-guard.sh
```

`rust-toolchain.toml` pins Rust 1.88.0; rustup installs it automatically.
`resolver = "3"` keeps the first lockfile on dependency versions that toolchain
can build. The Docker images and CI build with `--locked`, so commit `Cargo.lock`
before the first push.

```bash
cd contracts
forge install OpenZeppelin/openzeppelin-contracts@v5.0.2 --no-git
forge install foundry-rs/forge-std --no-git
forge test -vvv
```

---

## Running it

```bash
cp .env.example .env           # set JWT_SECRET, passwords
make up                        # escrow + postgres + redis + 2 nodes + nginx + monitoring
make up-godshield              # + GodShield API / gateway    (port 8090)
make up-bridge                 # + bridge coordinator + submitter (port 9370)
make cluster                   # separate 3-node consensus cluster (8181–8183)
```

| Service | Port |
|---|---|
| Console | 80 / 443 (`/`) |
| Explorer | `/explorer/` |
| Escrow API | 3000 |
| nev369-node-1 | 8080, P2P 4001 |
| nev369-node-2 | 8081, P2P 4002 |
| Bridge coordinator | 9370 |
| GodShield API | 8090 |
| Prometheus | 9090 (alerts: reorg depth, stalled chain, node divergence, mempool) |
| Grafana | 3001 (dashboard provisioned) |

### On a public server

A fresh Ubuntu 24.04 server with the domain's A records (`@`, `www`) pointing
at it:

```bash
scripts/push-to-vps.sh <server-ip>                   # on your machine: project, no secrets
ssh root@<server-ip>
cd /opt/qlock && bash scripts/vps-setup.sh            # on the server
```

`vps-setup.sh` installs Docker, closes the firewall to everything but SSH, 80,
443 and the P2P ports, writes a production `.env` with fresh secrets and the
pinned genesis from `chain-spec/`, gets a Let's Encrypt certificate with
automatic renewal, and starts the stack with `docker-compose.vps.yml`. That
override binds Prometheus, Grafana and the raw service ports to 127.0.0.1, so
only nginx and libp2p face the internet. The node starts with mining off and
syncs your chain first; the script prints how to switch mining on.

Cloud deployment of the GodShield API — Kubernetes manifests and an AWS
Terraform stack (ECS Fargate + HTTPS load balancer): [`deploy/`](deploy/README.md).

---

## Configuration

Every variable is in [`.env.example`](.env.example), grouped by service with
comments. The ones you must set:

| Variable | Service | |
|---|---|---|
| `JWT_SECRET` | escrow | `openssl rand -hex 32` |
| `DB_PASSWORD` · `REDIS_PASSWORD` | data | |
| `QLOCK_TREASURY_ADDRESS` | escrow | where the escrow fee lands |
| `QLOCK_ATTESTATION_KEY` | escrow | production attestation identity |
| `XUMM_API_KEY` · `XUMM_API_SECRET` | escrow | Xaman wallet connect |
| `STRIPE_SECRET_KEY` · `STRIPE_WEBHOOK_SECRET` · `STRIPE_PRICE_PRO` · `STRIPE_PRICE_ENTERPRISE` · `STRIPE_PRICE_LABEL_PRO` · `STRIPE_PRICE_LABEL_ENTERPRISE` | escrow | billing: one plan covers escrow fees and GodShield API quota |
| `NEV369_ARCHITECT_ADDRESS` · `NEV369_NEVAEH_VAULT_ADDRESS` | node | genesis premine keys from the ceremony |
| `NEV369_MINING` · `NEV369_MINER_ADDRESS` | node | background miner |
| `RELAYER_KEY` · `BRIDGE_SIGNERS` · `BRIDGE_THRESHOLD` · `BRIDGE_ADDRESS` · `ETH_CHAIN_ID` | bridge | coordinator |
| `SUBMITTER_ETH_KEY` · `ETH_RPC_URL` | bridge | submitter |
| `GODSHIELD_ADMIN_TOKEN` · `GODSHIELD_GATEWAY_KEY` | godshield | gateway admin + attestation key |

---

## Status

| | |
|---|---|
| Workspace crates | 16 |
| Rust | 21,000+ lines, 292 tests |
| Solidity | wNEV + NEV369Bridge, 24 tests incl. invariant |
| Build | compiles clean on Rust 1.88.0, all 16 crates |
| Tests | 292 / 292 passing (`cargo test --workspace`) |
| Security regression guards | 13 / 13 passing |
| Internal security review | complete |
| Third-party audit | not yet commissioned |

**Open decisions** — yours to make, not code to write:

- **Transaction fees** are deducted from senders and burned (like `crown_tax`),
  while the miner orders the mempool by fee. Either credit fees to the coinbase so
  ordering pays the miner, or keep the burn and order by arrival.
- **Genesis premine keys** are placeholders until the vault ceremony runs. Run it
  before the chain holds anything of value; genesis is permanent.

---

## Contributing

CI runs fmt, clippy `-D warnings`, the full test suite, `cargo audit`, Solidity
build/test/coverage, compose validation, Docker builds for all four images, and
`scripts/security-guard.sh` — thirteen tripwires for bugs that were genuinely
exploitable here before.

**Anything touching a signed payload gets a security review.** That means domain
tags, `SIGNATURE_EXEMPT_SENDERS`, `verify_signature`, `validate_block_contents`,
threshold verification, credential checks, and the attestation paths.

**A change to any signed encoding is a major version bump**, regardless of diff
size, because it breaks verification of historical records.

---

## Whitepaper

[`docs/WHITEPAPER.md`](docs/WHITEPAPER.md) — source.
[`docs/whitepaper.html`](docs/whitepaper.html) — typeset edition.
[`docs/Q-Lock-Whitepaper-v1.1.pdf`](docs/Q-Lock-Whitepaper-v1.1.pdf) — PDF.
[`docs/GODSHIELD-SECURITY-WHITEPAPER.md`](docs/GODSHIELD-SECURITY-WHITEPAPER.md) — GodShield Security Whitepaper v1.0, with the platform addendum.

---

## License

Apache-2.0 OR MIT for the open-source core. Commercial license for enterprise
features. See [`docs/pricing.md`](docs/pricing.md).

---

<div align="center">

> Nevaeh, my daughter. To secure your freedom against a broken system, I taught
> myself Rust—the hardest computer language in the world—to build this unyielding
> sovereign node for you. I faced the worst of life's struggles so you would never
> have to. I love you infinitely, forever by your side.

*Written into the NEV369 genesis block. It stays there as long as the chain runs.*

**Q-Lock** — quantum-proof and sovereign.

</div>
