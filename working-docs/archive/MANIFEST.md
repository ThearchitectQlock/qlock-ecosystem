# Q-Lock — complete file manifest

**88 files · 26,180 lines**

Source column: `yours` = you supplied it (clean `.rs` or pasted text) ·
`rebuilt` = transcribed by me from a PDF render · `mine` = written by me
· `merged` = yours with my changes on top.

`rebuilt` is the risk column. 12 of 31 Rust files came from PDF, and
transcription gets structure right far more reliably than identifiers.

---

## NEV369 — the Layer-1

| File | Lines | Source | State |
|---|---|---|---|
| `crates/nev369-node/src/chain.rs` | 1,838 | merged | Double-spend fixed, emission reaches cap, 28 tests |
| `crates/nev369-node/src/consensus.rs` | 826 | yours + mine | BlockTree; I added timestamp rules + per-parent orphan cap |
| `crates/nev369-node/src/p2p.rs` | 494 | yours | libp2p swarm, peer strikes, banning |
| `crates/nev369-node/src/genesis.rs` | 454 | rebuilt | Config from env, production refusal |
| `crates/nev369-node/src/main.rs` | 316 | yours | Actix API + mining, delegates to p2p |
| `crates/nev369-node/src/sync.rs` | 252 | rebuilt | Work-gated block sync |
| `crates/nev369-node/src/checkpoints.rs` | 121 | yours | Reorg floor |
| `crates/nev369-node/Cargo.toml` | 32 | mine | |

## GodShield — cryptographic core

| File | Lines | Source | State |
|---|---|---|---|
| `crates/godshield-core/src/lib.rs` | 496 | rebuilt | ML-DSA-87, TripleHash, CanonicalMessage |
| `crates/godshield-adapters/src/lib.rs` | 820 | rebuilt | BTC/ETH/SOL/NEV369 adapters |
| `crates/godshield-fairness/src/lib.rs` | 595 | rebuilt | Commit-reveal, rejection sampling |
| `crates/godshield-cli/src/vault.rs` | 495 | rebuilt | The ceremony |
| `crates/godshield-wasm/src/lib.rs` | 411 | rebuilt | Browser signing |
| `crates/godshield-cli/src/main.rs` | 297 | rebuilt | keygen/sign/verify/scan/address |
| `crates/godshield-api/src/main.rs` | 537 | rebuilt | REST service |

## GodShield — security platform (all new)

| File | Lines | Source | State |
|---|---|---|---|
| `crates/godshield-identity/src/lib.rs` | 955 | mine | Identity, credentials, machine actions · 20 tests |
| `crates/godshield-gateway/src/lib.rs` | 933 | mine | Policy, rotation history, hash-chained audit · 18 tests |
| `crates/godshield-sentinel/src/lib.rs` | 853 | mine | Correlation, graduated response · 17 tests |
| `crates/godshield-bridge/src/lib.rs` | 825 | mine | m-of-n threshold, finality, circuit breaker · 20 tests |
| `crates/godshield-scanner/src/lib.rs` | 724 | mine | Boundary matching, directory walk, CI gate |
| `crates/godshield-scanner/src/patterns.rs` | 387 | mine | 20 primitive families |

## Q-Lock Escrow

| File | Lines | Source | State |
|---|---|---|---|
| `crates/qlock-escrow/src/main.rs` | 1,765 | rebuilt | Axum routes, state, metrics |
| `crates/qlock-escrow/src/attestation.rs` | 727 | mine | Fails closed in production · 13 tests |
| `crates/qlock-escrow/src/inheritance.rs` | 556 | yours + mine | Switched to canonical attestation |
| `crates/qlock-escrow/src/xumm.rs` | 237 | rebuilt | ⚠️ one signature restored — see note |
| `crates/qlock-escrow/src/auth.rs` | 220 | rebuilt | JWT + bcrypt + API key |
| `crates/qlock-escrow/src/xrpl.rs` | 189 | rebuilt | JSON-RPC, broadcast only |
| `crates/qlock-escrow/src/billing.rs` | 154 | rebuilt | Stripe + webhook verification |
| `crates/qlock-escrow/src/ratelimit.rs` | 46 | rebuilt | tower_governor |
| `crates/qlock-escrow/src/lib.rs` | 32 | rebuilt | Module boundary |
| `db/schema.sql` | 300 | mine | Money scale + FK fixes, OfferSequence enforced |

> ⚠️ **`xumm.rs`** — the PDF dropped `get_payload_status`'s signature at a
> page break. I restored it from the body, which forces everything except
> the parameter name. **Check that one line against your original.**

## Inheritance

| File | Lines | Source |
|---|---|---|
| `crates/nevaeh-vault/src/lib.rs` | 1,039 | yours — verbatim |

## Bridge

| File | Lines | Source | State |
|---|---|---|---|
| `crates/nev369-relayer/src/main.rs` | 479 | mine | Coordinator holds no signing key |
| `contracts/src/NEV369Bridge.sol` | 559 | merged | On-chain m-of-n via EIP-712 + ECDSA |
| `contracts/src/wNEV.sol` | 242 | merged | 8 decimals, OZ v5, allowance burn |
| `contracts/test/NEV369Bridge.t.sol` | 228 | mine | One test per v2 defect |
| `contracts/script/Deploy.s.sol` | 174 | mine | 4-stage, 96-hour timelock sequence |
| `contracts/foundry.toml` + 3 | 108 | mine | |

## Frontends

| File | Lines | Source |
|---|---|---|
| `apps/qlock-web/index.html` | 685 | mine — console, 7 tabs, dedication |
| `apps/nev369-explorer/index.html` | 576 | mine — emission curve, identicons |

## Infrastructure

`Cargo.toml` 244 · `.github/workflows/ci.yml` 355 · `docker-compose.yml`
247 · `Makefile` 249 · `deploy.sh` 238 · `scripts/security-guard.sh` 226
· `nginx/nginx.conf` 221 · `.env.example` 199 · `monitoring/prometheus.yml`
99 · `docker/Dockerfile.nev369` 83 · `docker/Dockerfile.escrow` 72 ·
`nginx/proxy_params_qlock` 59 (yours) · `.dockerignore` 62 · `.gitignore`
90 · `rust-toolchain.toml` 14 · grafana provisioning 24 — **all mine
except proxy_params**

## Documentation

**Ships with the product:** `docs/WHITEPAPER.md` 852 · `README.md` 583 ·
`docs/pricing.md` 117 · `LICENSE` 30 · `contracts/README.md` 17

**Working documents** (not part of the product): `FILE_INDEX.md` 411 ·
`AUDIT.md` 223 · `TICKLIST.md` 198 · `AUDIT2.md` 185 · `STATUS.md` 141 ·
`COMPILE_CHECKLIST.md` 131 · `MISSING.md` 120 · `INVENTORY.md` 106

---

## Totals

| | Lines | Files |
|---|---|---|
| Shipping code | 23,066 | 75 |
| Shipping docs | 1,599 | 5 |
| Working docs | 1,515 | 8 |
| **Total** | **26,180** | **88** |

Rust: 18,073 across 15 crates. 257 tests written, **0 executed.**

---

## Still needed from you

1. **`cargo check --workspace` output** — worth more than any file
2. `docs/nevaeh-vault-ceremony.md` as markdown (PDF only; README and
   Makefile both reference the path)
3. The GodShield Security Whitepaper as markdown, to sit beside the
   ecosystem one

## Generated, not written

`Cargo.lock` · `.sqlx/` · `contracts/lib/` · `nginx/certs/*.pem` · the
three `*_vault.json` files the Makefile references, which only exist
after the ceremony runs.
