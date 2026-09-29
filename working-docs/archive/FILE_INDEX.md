# Q-Lock — incoming file index

Working index for the ~60-file review. Kept on disk so the manifest
survives context pressure; re-read this rather than trusting recall.

**Nothing has been fixed or rewritten from these batches yet — indexing only.**

Legend: `CURRENT` = newest known version · `SUPERSEDED` = older, kept for
history only · `DUPLICATE` = byte-identical text to another upload ·
`CONFLICT` = disagrees with a current file and needs a decision.

---

## Batch 1 — 13 files

| File | Pages | What it is | Status |
|---|---|---|---|
| `backend_src_main.pdf` | 152 | `crates/qlock-escrow/src/main.rs` — Axum escrow backend | **DUPLICATE** of `backend_src_main__1_.pdf` (identical text) |
| `Auth__Billing__Rate_Limiting___Real_XRPL__Rust_.pdf` | 43 | auth.rs / billing.rs / ratelimit.rs + real XRPL calls | CURRENT — only copy of these modules seen so far |
| `backend_Cargo.pdf` / `backend_Cargo__1_.pdf` | 4 | `[package] qlock-backend v1.0.0`, flat `backend/` crate | **DUPLICATE** pair, and **SUPERSEDED** — workspace manifest names the crate `qlock-escrow` at `crates/qlock-escrow` |
| `Docker_Production_Stack.pdf` / `__1_.pdf` | 37 | docker-compose `version: '3.8'`, `backend/` + `frontend/` layout | **DUPLICATE** pair, **SUPERSEDED** — pre-workspace layout; `version:` key is obsolete in Compose v2 |
| `Project_Scaffold__package_json___gitignore__Cargo_toml__CI_.pdf` | 11 | `frontend/package.json`, .gitignore, Cargo.toml, CI | **SUPERSEDED** for Cargo/CI (flat layout); `package.json` may still be current for `apps/qlock-web` |
| `monitoring_prometheus_yml.pdf` | 4 | Prometheus scrape config | Re-send of earlier upload; text identical to what was already reviewed |
| `Q-Lock_Full_Stack_Manifest.pdf` | 7 | Maps artifacts → repo paths, `qlock/backend/src/...` | **SUPERSEDED** — describes the flat `backend/` layout, not `crates/` |
| `README__3_.pdf` | 13 | Escrow-only README. "Dilithium-3", "Unhackable" | **SUPERSEDED** + **CONFLICT** (see C1, C2) |
| `README__4_.pdf` | 19 | "Three ledgers · Zero venture capital". Dilithium5, NEV369 3-node cluster, ports 8081/9369 | CURRENT candidate — newest README seen |
| `Q-Lock___Ecosystem_README__3_.pdf` | 16 | "Three products · Two ledgers" | **DUPLICATE** of `Ecosystem_README__2_.pdf`; older than `README__4_` |
| `Q-Lock_Business_Plan.pdf` | 18 | Market, pricing, revenue projections | CURRENT (only copy) + **CONFLICT** (C1, C2) |

---

## Open conflicts needing a decision

**C1 — Dilithium-3 vs Dilithium5.**
`README__3_` and `Q-Lock_Business_Plan` both say Dilithium-3 (4 mentions
each). Every current source file — `godshield-core`, the whitepaper,
`README__4_` — is Dilithium5 / ML-DSA-87 at NIST Level 5. The scanner
flags `dilithium3` as a MEDIUM finding, so the business plan currently
advertises a primitive the codebase's own tooling reports as
insufficient. One of the two has to move.

**C2 — "Unhackable".**
Used in `README__3_` and twice in the business plan. Nothing here has
been audited, and `godshield-core` shipped a fix for a signature-forgery
bug where one captured signature validated arbitrary messages. That word
in a document shown to investors or customers is the highest-risk claim
in the set.

**C3 — Three ledgers vs two.**
`README__4_` says three, `Ecosystem_README` says two. The third is
presumably Ethereum via `NEV369Bridge`. Needs confirming — the bridge is
trusted and unaudited, so counting it as a proven ledger integration is
a stretch.

**C4 — Repo layout: flat vs workspace.**
`backend_Cargo`, `Docker_Production_Stack`, `Project_Scaffold` and
`Full_Stack_Manifest` all assume `qlock/backend/` + `qlock/frontend/`.
The v1.1.0 workspace manifest assumes `crates/*` + `apps/*`. Four files
on the old side, so this needs one explicit call, not per-file guessing.

**C5 — Ports.**
`README__4_` lists NEV369 on 8081 with P2P on 9369. Earlier compose used
8080/4001 and 8081/4002 for a two-node setup, and `README__4_` describes
a three-node cluster. Port map needs reconciling once.

---

## Still open from before these batches (unchanged)

- **NEV-001** — `validate_block_contents()` does not re-check balance or
  nonce. In-block double-spend mints from nothing. Confirmed still
  present in the latest `chain.rs` upload.
- **NEV-007** — `MAX_SUPPLY` 369,369,369 vs ~67.9M actual terminal
  emission; premine is ~69% of real supply, not ~12.7%.
- **godshield-scanner** is not a workspace member; scanner code lives in
  `godshield-adapters`.
- `bcrypt` and `argon2` both declared in the workspace.
- Fees are deducted from senders but credited to nobody — the mempool
  sorts by fee with no miner incentive attached.

---

*Batches received: 1. Awaiting the rest before any work starts.*

---

## Batch 2 — 14 files

**8 of 14 are duplicates or re-sends.** Genuinely new: 6.

| File | Size | What it is | Status |
|---|---|---|---|
| `nev369-relayer-main.rs` | 19 KB | Bridge relayer, Actix-web, JSON-file store, "hardened v0.1.2" | **NEW — and the most important file in the set. See F1.** |
| `All_9_crate_Cargo_toml_files.pdf` | 21 pp | Per-crate manifests | **NEW** + **CONFLICT** (C6) |
| `apps_qlock-control_index_html__1_.html` | 34 KB | Control panel UI (`__2_` is identical) | NEW |
| `nev369-bridge-prototype.html` | 14 KB | Bridge UI prototype | NEW |
| `Q-Lock___GodShield___Website_Frontend.tsx` | 15 KB | Marketing site frontend | NEW |
| `GodShield___Q-Lock___README.pdf` | 14 pp | Combined GodShield/Q-Lock README | NEW — 5th README variant |
| `README.pdf` | 13 pp | — | **DUPLICATE** of `README__3_` (the Dilithium-3 / "Unhackable" one) |
| `Q-Lock___Ecosystem_README.pdf`, `__1_` | 16 pp | — | **DUPLICATE** — now 4 identical copies (`__1_`, `__2_`, `__3_`) |
| `docs_nevaeh-vault-ceremony.pdf` | — | — | **DUPLICATE** of `__1_` |
| `nginx_proxy_params_qlock.pdf` | — | — | **DUPLICATE** of `__1_` |
| `backend_src_main.pdf` | 152 pp | — | **DUPLICATE** — third copy received |
| `NEV369Bridge-v2.sol` | 6 KB | — | Re-send, same content |

Running total: **48 files received, 37 unique.** 23% is duplication.

---

## F1 — The relayer does not verify anything on any chain

This changes the bridge's risk assessment, so recording it now rather
than at file 60.

`nev369-relayer-main.rs` has no chain connection at all. No `reqwest`, no
RPC client, no provider, no NEV369 node query, no Ethereum call. It is a
CRUD service over `data.json`:

- `POST /api/locks` creates a lock record from whatever JSON the caller
  sends. `lockId`, `amount` and `ethAddress` are all caller-supplied.
- `POST /api/locks/{id}/minted` sets a status flag.
- Auth is a single shared static `RELAYER_KEY` in a header.

So a lock record exists because somebody with the key asserted it, not
because a lock happened. `NEV369Bridge.mintFromNEV369` then mints wNEV
against that `nev369LockId`.

Stated plainly: **anyone holding `RELAYER_KEY` can mint wNEV with no
NEV369 lock ever occurring.** The contract's `processedLocks` mapping
prevents replaying the same id twice; it cannot tell whether the id ever
corresponded to anything.

The hardening in the file's header is real and worth keeping —
constant-time key comparison, no hardcoded default, atomic writes, fatal
error on corrupt store instead of silent reset, CORS allow-list, amount
kept as a string rather than round-tripped through `f64`. All correct.
None of it addresses the above, because the gap is architectural, not
implementation.

Two further consequences:
- Single instance only. Global `Mutex<Store>` over one JSON file means no
  horizontal scaling and no shared state between replicas.
- `amount` is a decimal string, and nothing reconciles NEV369's 8
  decimals against the contract's `uint256`. This is the same unit
  mismatch flagged on `wNEV` — it now spans three components.

## C6 — The nine crate manifests do not match the workspace

Manifests present: `godshield-core`, `godshield-adapters`,
`godshield-api`, `godshield-cli` (package name `godshield`),
`godshield-fairness`, `godshield-wasm`, `nevaeh-vault`, `qlock-escrow`,
`nev369-node`.

- **`godshield-scanner` has no manifest**, consistent with it not being a
  workspace member. The READMEs still list it.
- **`qlock-inheritance`** appears as a package name but is not a
  workspace member anywhere.
- `qlock_escrow` (underscore) appears alongside `qlock-escrow` (hyphen) —
  likely a lib-target name, worth confirming it is deliberate.
- `godshield-cli`'s package is `godshield` while the directory is
  `godshield-cli`; fine, but the workspace member path must match the
  directory, not the package name.

## C7 — Five README variants now in circulation

`README`/`README__3_` (escrow-only, Dilithium-3), `README__4_`
("Three ledgers"), `Ecosystem_README` (×4 identical, "Two ledgers"),
`GodShield___Q-Lock___README`, plus the v0.6.0 reconciled one already
written. Six documents describing the same project, disagreeing on
product count, crypto level, and status.

---

*Batches received: 2. Awaiting the rest before any work starts.*

---

# COVERAGE TICK LIST — against the Q-Lock ecosystem workspace

Legend
`[x]` have it and have read it · `[~]` have the file, **not yet read**
`[ ]` not received · `[w]` written by me in this thread (not from you)

## GodShield — the cryptographic core

- [x] `crates/godshield-core/src/lib.rs` — *partial read*: API surface,
      TripleHash, CanonicalMessage, GodKeyPair, errors, and the verify()
      forgery fix header. Bodies of sign()/verify() not fully read.
- [x] `crates/godshield-adapters/src/lib.rs` — full. BTC/ETH/SOL/NEV369
      adapters, Interoperability enum, AdapterRegistry, and the inline
      `MigrationHelper` scanner.
- [x] `crates/godshield-cli/src/main.rs` — full. keygen/sign/verify/scan/
      address/chains/vault.
- [ ] `crates/godshield-cli/src/vault.rs` — **MISSING.** main.rs declares
      `mod vault;` and the whole ceremony depends on it.
- [x] `crates/godshield-fairness/src/lib.rs` — full. Commit-reveal,
      rejection sampling, AbandonedRound.
- [ ] `crates/godshield-api/src/**` — **MISSING.** Only its Cargo.toml.
- [ ] `crates/godshield-wasm/src/**` — **MISSING.** Only its Cargo.toml.
- [w] `crates/godshield-scanner/` — did not exist upstream. Written here:
      `lib.rs`, `patterns.rs`, `Cargo.toml`.
- [x] `GodShield Security Whitepaper` — full.

## Q-Lock Escrow — XRPL

- [x] `crates/qlock-escrow/src/main.rs` — *partial read*: routes, state,
      env vars, pricing constants, metrics, startup guards. Handler
      bodies not fully read (152 pp).
- [x] `crates/qlock-escrow/src/lib.rs` — full (short).
- [~] `auth.rs` / `billing.rs` / `ratelimit.rs` / real XRPL calls —
      held in `Auth__Billing__Rate_Limiting___Real_XRPL__Rust_.pdf`
      (43 pp), **not yet read**.
- [ ] `attestation.rs` — **MISSING.** Declared in lib.rs. This holds the
      long-lived attestation identity that production fails closed on.
- [ ] `inheritance.rs` — **MISSING.** Declared in lib.rs.
- [ ] `xumm.rs` — **MISSING** as a distinct file.
- [ ] `db/schema.sql` — **MISSING.** Compose mounts it as initdb.
- [~] `Q-Lock___GodShield___Website_Frontend.tsx` — held, unread.
- [~] `apps/qlock-control/index.html` — held, unread.
- [ ] `apps/qlock-web/**` — **MISSING** (only a package.json in the
      old Project_Scaffold).

## NEV369 — the Layer-1

- [x] `crates/nev369-node/src/chain.rs` — full. **NEV-001 open.**
- [x] `crates/nev369-node/src/genesis.rs` — full.
- [ ] `crates/nev369-node/src/consensus.rs` — **MISSING, and this is the
      biggest gap.** chain.rs imports `BlockTree`, `AcceptOutcome`,
      `transactions_to_requeue` from it. Without this file the crate
      cannot compile and the NEV-001 fix cannot be verified against the
      real fork-choice types.
- [ ] `crates/nev369-node/src/main.rs` (current) — **MISSING.** Only the
      superseded version with f64 money and stub persistence.
- [x] NEV369 Full Stack — Cargo/Dockerfile/compose/nginx/CI/deploy.
- [~] `nev369-bridge-prototype.html` — held, unread.
- [ ] `apps/nev369-explorer/**` — **MISSING.**

## EVM bridge

- [x] `wNEV-v2.sol` — full.
- [x] `NEV369Bridge-v2.sol` — full.
- [x] `nev369-relayer-main.rs` — read enough to establish **F1**: no
      chain verification anywhere in it.
- [w] Fixed `wNEV.sol`, `NEV369Bridge.sol`, forge tests, `Deploy.s.sol`,
      `foundry.toml`.

## Inheritance vault

- [~] `crates/nevaeh-vault/src/lib.rs` — held (97 pp), **not yet read.**
      Largest unread file in the set.
- [x] `docs/nevaeh-vault-ceremony.md` — full.
- [ ] `qlock-inheritance` — package name appears in the manifests; no
      source, not a workspace member.

## Infrastructure

- [x] workspace `Cargo.toml` v1.1.0 — full.
- [x] `nginx/proxy_params_qlock` — full.
- [x] `monitoring/prometheus.yml` — full.
- [x] Their CI workflow + Docker production stack (flat layout).
- [w] Reconciled Cargo.toml, compose, two Dockerfiles, nginx.conf,
      Makefile, security-guard.sh, .env.example, deploy.sh, ignores.

## Docs

- [x] Whitepaper, vault ceremony, 5 README variants, business plan.
- [ ] `docs/api-reference.md` — **MISSING.**
- [ ] `docs/integration-guide.md` — **MISSING.**
- [ ] `docs/pricing.md` — **MISSING.** Referenced by the fee constants,
      which previously drifted from it.

---

## Blocks a build, in order

1. `consensus.rs` — nev369-node cannot compile without it
2. `nev369-node/src/main.rs` (current)
3. `godshield-cli/src/vault.rs` — ceremony is undeliverable without it
4. `attestation.rs` — escrow won't start in production without it
5. `db/schema.sql`
6. `godshield-api` + `godshield-wasm` sources

Held but unread, and worth reading before I build: `nevaeh-vault/lib.rs`
(97 pp), the Auth/Billing/XRPL bundle (43 pp), the three frontends.

---

## Batch 3 — 14 files  ·  ALL BATCHES IN: 60 received, 47 unique

New: 10. Duplicates: 4 (`Ecosystem_README__3_`, `NEV369_Full_Stack` ×2,
`GodShield_Security_Whitepaper`).

| File | Pages | Resolves |
|---|---|---|
| `GodShield_API_Server.pdf` | 37 | ✅ `godshield-api` source — gap closed |
| `GodShield_WASM_Bridge___Real_Client-Side_Signing.pdf` | 28 | ✅ `godshield-wasm` source — gap closed |
| `GodShield_Deployment_Scripts` (Docker/K8s/Terraform/CI) | 51 | ✅ new — deployment layer |
| `NEV369___Mempool_Reconciliation___Checkpointing.pdf` | 19 | ⚠️ **not** consensus.rs — see B1 |
| `NEV369_src_main_rs___Fixed___GodShield_Integrated.pdf` | 48 | ⚠️ **still f64** — see B2 |
| `NEV369_Production_Hardening` (rate limit/CORS/config/log) | 23 | ✅ new |
| `GodShield_CLI_Tool.pdf` | 31 | ⚠️ no vault subcommands — see B3 |
| `GodShield_Core_Library__Rust_.pdf` | 28 | earlier core variant — conflicts with the SECURITY_FIX version |
| `GodShield_Chain_Adapters.pdf` | 38 | earlier adapters variant — conflicts with the FIXED version |
| `Q-Lock__Ecosystem___README.pdf` | 55 | 6th README variant, and the longest |

---

# STILL MISSING — the tick list

## Blocks compilation

- [ ] **`crates/nev369-node/src/consensus.rs`** — `BlockTree`,
      `AcceptOutcome`, `transactions_to_requeue`, `locator`,
      `find_fork_point`, `blocks_after`, `take_connectable_orphans`,
      `cumulative_work`, `tip_hash`, `get_block`, `from_chain`.
      Searched all 60 files: these names appear **only** in chain.rs's
      own import line. The file has never been sent.

- [ ] **`crates/nev369-node/src/main.rs` — current version.**
      `NEV369_src_main_rs___Fixed___GodShield_Integrated.pdf` still has
      `f64` ×10 and `load_state_from_db` ×3, so it is a fuller copy of
      the *old* design, not the one matching chain.rs's `Amount = u64`
      and hash-keyed persistence. Two irreconcilable money types.

- [ ] **`crates/nev369-node/src/p2p.rs`** — newly revealed. The
      checkpointing file references `p2p.rs (handle_incoming_block)` as
      a call site it patches. Never sent.

- [ ] **`crates/godshield-cli/src/vault.rs`** — `main.rs` declares
      `mod vault;` and dispatches `Command::Vault(c) => vault::run(c)`.
      `GodShield_CLI_Tool.pdf` has no vault subcommands at all.
      **Partially recoverable:** `nevaeh-vault/src/lib.rs` (held,
      unread) contains 42 `recover` mentions, `sharks`, Shamir, and the
      vault accessors — so the vault *engine* exists; what is missing is
      the CLI wiring on top of it.

- [ ] **`crates/qlock-escrow/src/attestation.rs`** — `lib.rs` exports
      `attestation::{AttestationIdentity, QLockAttestor}`, `main.rs`
      panics at startup without it in production. Only the filename
      appears (in the Cargo.toml bundle). Source never sent.

- [ ] **`crates/qlock-escrow/src/inheritance.rs`** — declared `pub mod`
      in lib.rs. Never sent.

- [ ] **`crates/qlock-escrow/src/xumm.rs`** — declared `pub mod`. Never
      sent as a distinct file.

- [ ] **`crates/qlock-escrow/src/xrpl.rs`** — declared `pub mod`. May be
      inside the held-but-unread Auth/Billing/XRPL bundle.

## Needed to run

- [ ] **`db/schema.sql`** — no file by that name exists, **but the
      schema itself does**: `Docker_Production_Stack.pdf` carries an
      inline `db/init.sql` with `users`, `wallets`, `transactions`,
      `escrows`, `attestations`. So this is an extraction job, not a
      missing artefact. Note the path differs: compose mounts
      `./db/init.sql`, my compose mounts `./db/schema.sql`.

- [ ] **`.sqlx/`** — offline query metadata. Without it the escrow
      Docker build needs a live Postgres at image-build time.
      Generated, not authored: `cargo sqlx prepare --workspace`.

- [ ] **`apps/qlock-web/**`** — only an old `frontend/package.json`.
      Three frontends were sent (`qlock-control/index.html`,
      `nev369-bridge-prototype.html`, `Website_Frontend.tsx`) and none
      is `qlock-web`.

- [ ] **`apps/nev369-explorer/**`** — never sent. READMEs mark it
      "not started", so this may be correct rather than missing.

- [ ] **`crates/godshield-scanner/`** — does not exist upstream. Two
      different components share the name: the source-code scanner the
      CLI's `scan` command calls (currently `MigrationHelper` inside
      `godshield-adapters`) and `GodShieldScanner`, the wire-size
      validator. Naming decision needed before either moves.

- [ ] **`crates/qlock-inheritance/`** — package name appears in the
      Cargo bundle, is not a workspace member, and has no source.
      Likely superseded by `nevaeh-vault`; needs confirming or deleting.

## Docs referenced by code

- [ ] `docs/pricing.md` — the escrow fee constants are documented as
      having drifted from it once already.
- [ ] `docs/api-reference.md`
- [ ] `docs/integration-guide.md`

## Held, unread — I should read before building

- [~] `crates/nevaeh-vault/src/lib.rs` (97 pp) — largest unread file
- [~] `Auth__Billing__Rate_Limiting___Real_XRPL__Rust_.pdf` (43 pp)
- [~] `GodShield_Deployment_Scripts` (51 pp)
- [~] `Q-Lock__Ecosystem___README.pdf` (55 pp)
- [~] `NEV369_Production_Hardening` (23 pp)
- [~] The three frontends

---

## Version conflicts to settle before merging

| Component | Competing versions | Keep |
|---|---|---|
| godshield-core | `GodShield_Core_Library` vs `..._SECURITY_FIX` | SECURITY_FIX — it carries the verify() forgery fix |
| godshield-adapters | `GodShield_Chain_Adapters` vs `..._FIXED` | FIXED — bech32 impersonation + panic fix |
| godshield-cli | `GodShield_CLI_Tool` vs `crates_godshield-cli_src_main` | the crates_ one — it has the vault subcommands |
| nev369 main.rs | 2 copies, both f64 | **neither** — needs a u64 rewrite against chain.rs |
| README | 6 variants | one decision, not six |
| Repo layout | flat `backend/` (4 files) vs `crates/` | crates/ |

*All 60 files received. Nothing built yet.*
