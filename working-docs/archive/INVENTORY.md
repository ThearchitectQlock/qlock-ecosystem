# Q-Lock ecosystem — complete inventory

82 files received · 61 unique · 21 duplicates.

`[you]` you supplied it · `[me]` I wrote it · `[ ]` missing

---

## NEV369 — `crates/nev369-node/`

- [you] `src/chain.rs` — superseded, see below
- [me]  `src/chain.rs` — **use this one.** Double-spend fix (NEV-001),
        scratch-state executor, height-correct coinbase, 22 tests
- [you] `src/consensus.rs` — **yours is the base.** BlockTree, work-based
        fork choice, reorg, orphans
- [me]  merged into it: timestamp validation + per-parent orphan cap
- [you] `src/genesis.rs` — GenesisConfig, env validation, premine pinning
- [you] `src/main.rs` — **u64 lineage**, actix API + libp2p gossip swarm
- [you] `src/sync.rs` — request/response block sync (locator → catch-up)
- [you] `apps/nev369-explorer/index.html`

Complete crate. Nothing missing.

## GodShield — `crates/godshield-*`

- [you] `godshield-core/src/lib.rs` — SECURITY_FIX version (verify()
        forgery fix). The canonical copy
- [you] `godshield-adapters/src/lib.rs` — FIXED version
- [you] `godshield-cli/src/main.rs`
- [you] `godshield-cli/src/vault.rs` — **just arrived.** `run()`,
        `VaultCommand`, Create/Recover/Verify, guardians, threshold,
        `--test-mode`
- [you] `godshield-fairness/src/lib.rs` — FIXED (rejection sampling)
- [you] `godshield-api/src/main.rs` — FIXED
- [you] `godshield-wasm/src/lib.rs`
- [me]  `godshield-scanner/` — `lib.rs` + `patterns.rs` + manifest.
        Did not exist; adapters re-exports from it

Complete. Note: your `GodShieldScanner` (wire-size validator) is a
different component and belongs in `godshield-core`, not here.

## Inheritance

- [you] `crates/nevaeh-vault/src/lib.rs` — Shamir, AES-GCM, TimeLock,
        VaultBuilder, recover_*, verify_integrity
- [you] `crates/qlock-escrow/src/inheritance.rs` — resolves the phantom
        `qlock-inheritance` crate; it is a MODULE, delete that member
- [you] `docs/nevaeh-vault-ceremony.md`

## Q-Lock Escrow — `crates/qlock-escrow/`

- [you] `src/main.rs` · `src/lib.rs` · `src/auth.rs` · `src/billing.rs`
        · `src/ratelimit.rs` · `src/xrpl.rs` · `src/inheritance.rs`
- [me]  `src/attestation.rs` — did not exist, blocked startup.
        `attest_escrow` added to match inheritance.rs
- [me]  `db/schema.sql` — extracted from inline init.sql
- [ ]   **`src/xumm.rs`** — declared `pub mod` in lib.rs. MISSING

## EVM bridge — `contracts/`

- [you] `wNEV-v2.sol` · `NEV369Bridge-v2.sol` — superseded
- [me]  `src/wNEV.sol` — decimals 18→8, OZ v5 imports
- [me]  `src/NEV369Bridge.sol` — monotonic burn nonce, 24h mint limit
- [me]  `test/NEV369Bridge.t.sol` · `script/Deploy.s.sol` ·
        `foundry.toml` · remappings · README
- [you] `nev369-relayer-main.rs` — works, verifies nothing on-chain

## Frontends — `apps/`

- [you] `qlock-control/index.html` · `nev369-bridge-prototype.html` ·
        `Website_Frontend.tsx` · `nev369-explorer/index.html`
- [ ]   **`qlock-web/`** — MISSING

## Infrastructure

- [me]  `Cargo.toml` (workspace) · `docker-compose.yml` ·
        `docker/Dockerfile.nev369` · `docker/Dockerfile.escrow` ·
        `.github/workflows/ci.yml` · `scripts/security-guard.sh` ·
        `Makefile` · `.env.example` · `deploy.sh` · `nginx/nginx.conf` ·
        `rust-toolchain.toml` · `.gitignore` · `.dockerignore`
- [you] `nginx/proxy_params_qlock` · `monitoring/prometheus.yml`
- [you] K8s/Terraform deployment scripts · production hardening

## Docs

- [you] Whitepaper · vault ceremony · business plan · 7 README variants
- [me]  `README.md` (v0.6.0) · `STATUS.md` · `FILE_INDEX.md` · this file
- [ ]   `docs/pricing.md` — fee constants reference it; drifted once before

---

# MISSING — 2 files

1. **`crates/qlock-escrow/src/xumm.rs`** — writable from the Xaman calls
   in qlock-escrow/main.rs if you don't have it
2. **`apps/qlock-web/`** — needs direction; a frontend isn't specified by
   its callers the way a module is

Optional: `docs/pricing.md`.

---

# NOT VERIFIED

Nothing compiled. No Rust toolchain, no forge, no Docker here.
No independent audit of any component.
