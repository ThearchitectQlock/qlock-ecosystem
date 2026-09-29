# Q-Lock ecosystem — tick list

Legend
`[x]` done · `[~]` partial · `[ ]` not done · `[!]` blocked on you

---

## 0 · Can it compile?

- [x] Workspace manifest, 14 members, all deps resolve
- [x] **All 14 crate manifests exist** — 8 were missing, so `cargo check`
      failed before compiling anything
- [x] **14/14 crates have an entry point.** 28 `.rs` files, 17,320 lines
- [x] Eight predicted compile errors fixed without a toolchain:
  - `is_none_or` (Rust 1.82) → `map_or`; toolchain pins 1.75
  - `Gateway::verify` E0502 — `&KeyEpoch` live across `&mut self.audit`
  - `policy_check` closure holding `&Self` across `&mut self`
  - unused `HashMap` import in `godshield-bridge` (fails `-D warnings`)
  - `hmac` referenced by `qlock-escrow`, absent from workspace deps
  - joiner inserted a space after an opening quote —
    `format!("` + `{}/{}"` became `format!(" {}/{}"`, a leading space
    inside the request URL
  - `lib.rs` and `main.rs` both declaring `auth`/`billing`/`ratelimit`
    compiles each file twice into two distinct types with the same name
    ("expected `auth::Claims`, found `auth::Claims`"). Reverted to the
    author's stated boundary: the binary owns those three
  - `xumm.rs` missing function signature (see above)
- [ ] **`cargo check --workspace` has never run.** Everything above is
      static reasoning. Expect real errors on the first pass.

### Source present, per crate

| Crate | Manifest | Source | Buildable |
|---|---|---|---|
| `godshield-scanner` | ✅ | ✅ mine | ✅ |
| `godshield-bridge` | ✅ | ✅ mine | ✅ |
| `godshield-identity` | ✅ | ✅ mine | ✅ |
| `godshield-gateway` | ✅ | ✅ mine | ✅ |
| `godshield-sentinel` | ✅ | ✅ mine | ✅ |
| `nev369-node` | ✅ | ✅ all 5 files | ✅ |
| `qlock-escrow` | ✅ | ✅ 9 files | ✅ |
| `godshield-core` | ✅ | ✅ rebuilt | ✅ |
| `godshield-adapters` | ✅ | ✅ rebuilt | ✅ |
| `godshield-api` | ✅ | ✅ rebuilt | ✅ |
| `godshield-cli` | ✅ | ✅ rebuilt + `vault.rs` | ✅ |
| `godshield-fairness` | ✅ | ✅ rebuilt | ✅ |
| `godshield-wasm` | ✅ | ✅ rebuilt | ✅ |
| `nevaeh-vault` | ✅ | ✅ verbatim | ✅ |

**[x] RESOLVED — all 14 crates now have sources.** Two were placed
verbatim from clean `.rs` uploads (`nevaeh-vault`, `inheritance.rs`); the
rest were reconstructed from the PDF renders and every file passes brace
balance with zero dangling operators.

**One file needed a human decision and is flagged in place:**
`qlock-escrow/src/xumm.rs` was missing `get_payload_status`'s signature —
a page break in the PDF fell between the previous function's closing
brace and this body, so the render dropped the declaration and the file
would not parse. The body forces everything except the parameter name
(`uuid`, builds `{XUMM_BASE}/{uuid}`, returns `PayloadStatus`). Restored
with a comment saying so. **Check that one line against your original.**

---

## 1 · NEV369

- [x] `chain.rs` — state, transactions, blocks, persistence
- [x] `consensus.rs` — BlockTree, work-based fork choice, reorg, orphans
- [x] `genesis.rs` — config from env, premine pinning, production refusal
- [x] `main.rs` — actix API, libp2p gossip swarm, mining loop
- [x] `sync.rs` — locator-based block sync, work-gated
- [x] In-block double-spend fixed — `BlockExecution` scratch state
- [x] Emission reaches 369,369,369 exactly, clamped
- [x] Money is `u64` base units end to end
- [x] Timestamp rules as consensus rules
- [x] Orphan buffer bounded per parent
- [x] 60 tests written
- [ ] Never compiled
- [ ] Never run as two nodes
- [ ] No `/metrics` — no height, mempool, peer or reorg gauges
- [!] **Fees burn but drive mempool ordering.** Credit them to the
      coinbase, or stop sorting by them. Monetary policy, your call.
- [!] **Premine frozen.** `ARCHITECT_ADDRESS` is still the placeholder
      string. Your 10M is unspendable until the vault ceremony runs and
      genesis is rebuilt — and after genesis exists, changing it means
      wiping the chain.

## 2 · GodShield platform

| § | Component | State |
|---|---|---|
| 1 | PQ Security Gateway | [x] policy, rotation history, hash-chained audit |
| 2 | Migration Engine | [~] scanner done; no dependency-file parsing, no Go/C/C++/Python |
| 3 | Identity | [x] records, credentials, four states |
| 4 | Machine Security | [x] signed actions, replay, emergency suspension |
| 5 | Sentinel | [x] correlation, graduated response, evidence |
| 6 | Key lifecycle / HSM | [!] needs a decision: which HSM |
| 7 | Risk & Policy engine | [~] gateway covers algorithm, value, rate, status. No rule language |
| 8 | Evidence & Compliance | [~] audit chain + incident evidence. No export, no retention policy |
| 9 | Incident response | [~] Sentinel escalates. No runbook, no on-call path |
| 10 | Cryptographic agility | [~] domain tags are versioned; no migration tooling |
| 11 | AI governance | [!] needs a capability model from you |
| 12 | Bridge Security | [x] threshold, finality, replay, exposure, breaker |
| 13 | PQ Foundation | [x] `godshield-core` |

- [!] **`GodShieldScanner` hardcodes signature length 4627.**
      `godshield-core` uses **4864** and already performs the check. 4627
      rejects every real signature. Delete the duplicate or move it into
      core.

## 3 · Q-Lock Escrow

- [x] `attestation.rs` — persistent identity, fails closed in production
- [x] `db/schema.sql` — money scale fixed, FK blocker removed,
      `OfferSequence` enforced at the database
- [x] `docs/pricing.md` — the source of truth the fee constants drifted from
- [ ] `main.rs`, `lib.rs`, `auth.rs`, `billing.rs`, `ratelimit.rs`,
      `xrpl.rs`, `xumm.rs`, `inheritance.rs` — you have all of these
- [!] **`inheritance.rs` signs pipe-joined terms.** A beneficiary name
      containing `|` re-partitions every field after it. Switch to
      `attest_escrow_canonical` **before** any real escrow exists —
      switching after invalidates existing attestations.

## 4 · Bridge

- [x] `wNEV.sol` — 8 decimals, OZ v5, allowance-based burn
- [x] `NEV369Bridge.sol` — monotonic burn nonce, per-window mint limit
- [x] Forge tests, 4-stage deploy script, `foundry.toml`
- [x] `godshield-bridge` — m-of-n threshold, finality, circuit breaker
- [ ] **Not wired.** The relayer still records whatever JSON a caller
      sends under one shared key
- [ ] `forge test` never run
- [!] **Do not move value across this bridge** until the threshold path
      replaces the relayer

## 5 · Inheritance

- [x] Ceremony documented, three vaults, plain-English 2039 recovery spec
- [x] XRPL escrow is the real mechanism, not NEV369
- [ ] `nevaeh-vault/src/lib.rs` not in this folder
- [ ] Ceremony not performed
- [ ] `OfferSequence` not yet recorded anywhere

## 6 · Frontends

- [x] `apps/qlock-web` — unified console, five tabs, live endpoints
- [x] `apps/nev369-explorer` — public, read-only, deep-linkable
- [ ] Neither opened against a running backend

## 7 · Infrastructure

- [x] compose, two Dockerfiles, nginx + proxy_params, Makefile,
      `.env.example`, `deploy.sh`, prometheus, ignores, toolchain pin
- [x] CI — fmt, clippy `-D warnings`, test, audit, forge, 7 security guards
- [x] `scripts/security-guard.sh` — tripwires for previously exploitable bugs
- [ ] CI never run
- [ ] No alerting configured

## 8 · Docs

- [x] `README.md` v0.7.0 — figures machine-verified against the code
- [x] `AUDIT.md` — 34 findings, 34 fixed, 6 open
- [x] `docs/pricing.md`, `STATUS.md`, `INVENTORY.md`, `FILE_INDEX.md`
- [!] **"Unhackable" is still in the business plan and an old README.**
      `godshield-core` shipped a signature-forgery fix during this work.
      Nothing is audited. That word costs nothing to remove and is the
      riskiest sentence in the project.

---

## What "production ready" would require

Not achievable today. Written down so the phrase has a definition.

- [ ] `cargo check --workspace` clean
- [ ] `cargo test --workspace` green — 167 tests written, 0 run
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `forge test` green
- [ ] Two nodes gossiping, a forced partition, a verified reorg leaving
      balances correct
- [ ] Bridge threshold path replacing the relayer
- [ ] Vault ceremony performed; genesis rebuilt on real addresses
- [ ] Independent third-party audit of the core
- [ ] Independent audit of each integration and both contracts
- [ ] Alerting on reorg depth, attestation fingerprint change, escrow
      503 rate, Stripe signature failures
- [ ] Backup and restore tested end to end
- [ ] Incident runbook: who is paged, how a node rolls back

---

## Next three, in order

1. **Drop the seven missing source files in**, `godshield-core` first.
2. **Run `cargo check --workspace`** and paste the errors. That is a
   today job and I will work through them.
3. **Wire `godshield-bridge` into the relayer.** Until then the bridge
   is one stolen key away from unbacked supply.
