# Q-Lock ecosystem — status

Ten workspace crates, an EVM bridge, three frontends, infrastructure.
61 source files received (47 unique), 33 written.

---

## PART 1 — WRITTEN (33 files, ~9,600 lines)

### NEV369
| File | Lines | Note |
|---|---|---|
| `crates/nev369-node/src/chain.rs` | 1,713 | NEV-001 fixed + 7 other defects |
| `crates/nev369-node/src/consensus.rs` | 976 | **Did not exist.** BlockTree, fork choice, reorg, orphan buffer |

### Q-Lock Escrow
| File | Lines | Note |
|---|---|---|
| `crates/qlock-escrow/src/attestation.rs` | 559 | **Did not exist.** Startup blocker |
| `db/schema.sql` | 289 | Extracted from inline `init.sql`; money scale + FK fixes |

### GodShield
| File | Lines | Note |
|---|---|---|
| `crates/godshield-scanner/src/lib.rs` | 724 | **Did not exist as a crate** |
| `crates/godshield-scanner/src/patterns.rs` | 387 | Boundary matching; 20 primitive families |
| `crates/godshield-scanner/Cargo.toml` | 21 | |

### EVM bridge
`contracts/src/wNEV.sol` (242) · `contracts/src/NEV369Bridge.sol` (377) ·
`contracts/test/NEV369Bridge.t.sol` (228) · `contracts/script/Deploy.s.sol` (174) ·
`foundry.toml` (82) · README · remappings · gitignore

### Infrastructure
`Cargo.toml` (234) · `docker-compose.yml` (243) · `docker/Dockerfile.nev369` (83) ·
`docker/Dockerfile.escrow` (63) · `.github/workflows/ci.yml` (355) ·
`scripts/security-guard.sh` (215) · `Makefile` (249) · `.env.example` (150) ·
`deploy.sh` (238) · `nginx/nginx.conf` (214) · `nginx/proxy_params_qlock` (59) ·
`monitoring/prometheus.yml` (99) · `rust-toolchain.toml` · `.gitignore` · `.dockerignore`

### Docs
`README.md` (991) · `FILE_INDEX.md` · this file

---

## PART 2 — HELD FROM YOU

**Read in full:** `godshield-adapters/src/lib.rs` · `godshield-cli/src/main.rs` ·
`godshield-fairness/src/lib.rs` · `nev369-node/src/genesis.rs` ·
`qlock-escrow/src/lib.rs` · `wNEV-v2.sol` · `NEV369Bridge-v2.sol` ·
`nev369-relayer-main.rs` · whitepaper · vault ceremony ·
`nginx/proxy_params_qlock` · `prometheus.yml` · NEV369 full stack

**Read partially — have the API surface, not every body:**
`godshield-core/src/lib.rs` (~⅓ of 44pp) · `qlock-escrow/src/main.rs` (152pp) ·
`auth.rs` (header + hashing)

**Held, never read:**
`nevaeh-vault/src/lib.rs` (97pp) · `godshield-api` (37pp) ·
`godshield-wasm` (28pp) · Deployment Scripts K8s/Terraform (51pp) ·
Production Hardening (23pp) · `billing.rs` / `ratelimit.rs` / `xrpl.rs` ·
`Q-Lock__Ecosystem___README` (55pp) · three frontends · business plan

---

## PART 3 — STILL NEEDED

### Blocks `cargo build`

1. **`crates/nev369-node/src/main.rs`** — the u64 version.
   Both copies received are the f64 lineage (`MAX_SUPPLY: f64`,
   `balances: HashMap<String, f64>`, `load_state_from_db`). Needs to wire
   `chain.rs` + `consensus.rs` + `genesis.rs`, which use `Amount = u64`.
   Without it nothing in the crate has an entry point.

2. **`crates/nev369-node/src/p2p.rs`** — the version that talks to this
   `BlockchainApp`. The one in the Complete File Set belongs to the f64
   lineage and calls `handle_incoming_block` against a different type.
   Also `p2p_sync.rs` and `checkpoints.rs` from that set — worth porting,
   currently pointing at the wrong `BlockchainApp`.

3. **`crates/godshield-cli/src/vault.rs`** — `main.rs` declares
   `mod vault;` and dispatches `Command::Vault(c) => vault::run(c)`.
   The engine exists in `nevaeh-vault`; the CLI wiring does not. This is
   the file the whole inheritance ceremony runs through.

4. **`crates/qlock-escrow/src/inheritance.rs`** — declared `pub mod` in
   `lib.rs`, which says the ceremony binary needs it.

5. **`crates/qlock-escrow/src/xumm.rs`** — declared `pub mod`.

6. **The 9 per-crate `Cargo.toml` files, in full.** I have only the
   package names skimmed from the bundle, not dependency lists — so I
   cannot confirm the workspace `[workspace.dependencies]` actually
   satisfies each crate.

### Would change what I write

7. **`godshield-core/src/lib.rs` in full.** Everything depends on it and
   I have read about a third. I need the real `sign`/`verify` bodies,
   the exact `CanonicalMessage::encode` and `encode_strs` signatures, and
   the true Dilithium5 size constants — your `GodShieldScanner` hardcodes
   4627 (FIPS 204 ML-DSA-87) while `pqcrypto-dilithium 0.5` emits 4595.
   One of those is wrong and only the real code settles it.

8. **`docs/pricing.md`** — the escrow fee constants are documented as
   having drifted from it once already, charging every tier 0.3%. I
   cannot check code against a doc I do not have.

9. **`apps/qlock-web/`** — three frontends arrived and none is this one.

### Not needed
- `apps/nev369-explorer` — your READMEs say not started
- `.sqlx/` — generated: `cargo sqlx prepare --workspace`
- `qlock-inheritance` crate — in the manifest bundle, not a workspace
  member, no source. Probably superseded by `nevaeh-vault`; confirm or delete

---

## PART 4 — DECISIONS ONLY YOU CAN MAKE

| # | Question |
|---|---|
| 1 | **Fees**: credited to the miner, or burned? Currently deducted and credited to nobody, while `build_candidate` sorts by fee — so prioritisation has no incentive behind it |
| 2 | ~~`MAX_SUPPLY`~~ — **resolved.** 369 NEV / 437,000 blocks, clamped to reach 369,369,369 exactly. Nevaeh 9.99%, Architect 2.71%, mineable 87.30% |
| 3 | **Relayer**: it verifies nothing on any chain. Anyone with `RELAYER_KEY` can mint wNEV with no NEV369 lock. Light client, multi-signer threshold, or accept and document the trust? |
| 4 | **Scanner naming**: two components share the name — the source scanner (`MigrationHelper`) and your wire-size validator (`GodShieldScanner`). My read: wire sizes belong in `godshield-core`, source scanning in `godshield-scanner` |
| 5 | **READMEs**: six variants. Which is canonical? |
| 6 | **Dilithium-3 vs Dilithium5**: `README__3_` and the business plan say Dilithium-3; everything else says 5. Your own scanner flags `dilithium3` as MEDIUM |
| 7 | **"Unhackable"** in the business plan and a README. Nothing is audited, and core just fixed a signature-forgery bug |

---

## PART 5 — NOT VERIFIED

**Nothing here has been compiled.** No Rust toolchain, no `forge`, no
Docker in the environment this was written in. `consensus.rs`,
`attestation.rs` and `godshield-scanner` are new code that has never been
built — expect real errors on first `cargo check`.

No independent audit of any component.
