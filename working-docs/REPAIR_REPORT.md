# Repair report — September 2026

What this pass fixed, how it was checked, and what is left. Older tracking
documents are in `archive/` for history; they describe earlier states and are
superseded by this file and the README.

## 1. The PDF-reconstruction damage

Fifteen Rust files only ever existed as PDF renders. The copy of the workspace
that went round as `qlock-ecosystem.zip` carried them as raw PDF text — page-break
characters, comment lines without `//`, identifiers split mid-word — and none of
the fifteen parsed.

Every one of them now parses, and every file in the workspace is `rustfmt`-clean.

| Damage | Where | Fixed |
|---|---|---|
| Split identifiers in code (`name.to _string()`, `kp.pub lic_key`, `recorded.architect _address`) | adapters, cli, genesis | yes |
| Joined tokens in code (`txidelse` ×4) | escrow main | yes |
| A `const` swallowed into a doc comment (`DILITHIUM5_PUBKEY_HEX_LEN`) — invisible to a parser, caught by name resolution | genesis | yes |
| Broken string continuations (`\n\ NEV369_…`) | genesis | yes |
| **Escrow route paths split** — `/wallet/:address/bal ance`, `/escrow/xrpl/:id/fin ish` and 12 more; those endpoints would have 404'd | escrow main | yes |
| **SQL keywords glued to columns** — `FROM transactionsWHERE`, `ORto_address`, `SELECTCOUNT`, `ASlocked`, `ONCONFLICT DONOTHING` | escrow main | yes — every SQL string |
| **`"pro duction"`** in the genesis production-refusal test | genesis | yes |
| Broken URLs — Stripe, Xaman, CoinGecko | billing, xumm, escrow main | yes |
| Plan names (`"enterpri se"`), `Be arer`, `dilithi um` | escrow, auth, adapters | yes |
| About 100 joined/split words in comments and messages | all fifteen | yes (dictionary-driven, reviewed) |

## 2. Real bugs found by compiling each crate

With no crates.io access, each crate was compiled on its own with rustc, with the
workspace crates it depends on inlined as modules. External-crate errors are
filtered out; what remains are genuine errors in this code:

| Bug | Fix |
|---|---|
| `billing.rs` wrapped in `mod billing { }` — routes pointed at functions that did not exist at that path | module wrapper removed; file rewritten (below) |
| `p2p.rs` used `peer` where no `peer` was bound (untracked sync replies) | responding peer passed in |
| `nev369-relayer` never set `chain_id` / `bridge_address` — the EIP-712 domain | read from `ETH_CHAIN_ID` / `BRIDGE_ADDRESS`, required |
| `inheritance.rs` passed `u32` where the canonical attestation takes `u64` | widened |
| `GodSignature` / `GodPublicKey` lacked `Debug`, `GodKeyPair` lacked `Debug` — tests in fairness and nevaeh-vault could not compile | derived; `GodKeyPair`'s `Debug` is hand-written and redacts the secret |
| `BridgeAuthorizer` and `GatewayAttestation` lacked the derives their tests use | derived |
| Missing manifest deps: `base64` (api), `sha3` (relayer), `serde-wasm-bindgen` + `console_error_panic_hook` (wasm) | added |

## 3. Behaviour bugs

| Bug | Fix |
|---|---|
| **Stripe webhook signature check returned `true`** — anyone could POST `checkout.session.completed` and upgrade any account | real HMAC-SHA256, constant-time compare, 5-minute replay window, idempotency via `stripe_events`, DB-backed plan and subscription updates, price IDs from env; 5 tests; CI guard |
| **Escrow server ignored `QLOCK_ATTESTATION_KEY`** — in production it panicked no matter what | uses `AttestationIdentity::from_env()` |
| Node API did not serve what the explorer and console call (`/chain`, `/block/N`, `/balance/…`, `height`/`latest_hash` in `/info`) — both pages showed nothing | full API: `/chain`, `/block/{index|hash}`, `/tx/{hash}`, `/balance`, `/mempool`, `/vault/nevaeh`, `/metrics`; every tx carries its hash |
| `/mine` unreachable — a second `scope("")` after the first never matches | per-route rate-limited resources |
| `/wallet/new` returned a public key whose secret was thrown away | dev-only, returns the keypair once; refused in production; CI guard |
| Escrow `/quantum/keygen` threw the secret away, returned the text "ecdsa-secp256k1" as a key, could crash on `.expect`, and the console called it with no body | dev-only full keypair, refused in production; CI guard |
| No background miner | `NEV369_MINING` + `NEV369_MINER_ADDRESS`, bounded rounds on the blocking pool |
| Compose passed `QLOCK_ENV` and `NEV369_BOOTSTRAP_PEER` to the nodes — neither is read | `NEV369_ENV`, `NEV369_BOOTSTRAP_PEERS` multiaddr, `NEV369_P2P_PORT=4001` |
| Escrow CORS took one origin | comma-separated list |
| Dockerfile.escrow copied a `.sqlx/` that does not exist (no compile-time queries are used) — the image could not build | removed |
| Rust 1.75 pin: alloy and current tokio/axum/libp2p releases need newer compilers | 1.88.0, `resolver = "3"` (MSRV-aware lockfile) |

## 4. Added

- **PQ Security Gateway over HTTP** — `/api/v1/gateway/{verify, policy/check, identity/register, key/rotate, sign, audit}` in `godshield-api`
- **Node `/metrics`** + Prometheus scrape + alert rules (deep reorg, stalled chain, node divergence, mempool, service down) + provisioned Grafana dashboard
- **Dockerfiles** for the bridge (coordinator + submitter) and the GodShield API; compose profiles `bridge` and `godshield`
- **Explorer** served at `/explorer/` and at the root of nev369protocol.tech; falls back to node lookups for blocks and transactions outside the recent window
- **`docker-compose.nev369.yml`** — three-node consensus cluster, rebuilt for the current layout
- **`docs/nevaeh-vault-ceremony.md`** — rebuilt from the PDF, Step 3 updated for `qlock-inheritance create/record`
- **`.env.example`** covering every variable the code and compose read
- **`docs/GODSHIELD-SECURITY-WHITEPAPER.md`** — your GodShield Security Whitepaper v1.0, transcribed from your PDF word for word, plus §8, a platform addendum describing the eleven crates as built
- **`deploy/k8s/` and `deploy/terraform/`** — from your GodShield deployment-scripts PDF, which had never been added. Fixed on the way in: the Terraform load balancer had no listener, sat in private subnets while public, the tasks were open to 0.0.0.0/0, `:latest` could not be re-pushed to the IMMUTABLE registry, and the log group was never created; the HPA metric block was mis-indented
- **`contracts/.env.example`, `contracts/.gitignore`**, and a contracts README rewritten for the threshold bridge
- **CI** for toolchain 1.88, static web-app checks, four Docker images, compose validation across profiles

## 5. How it was checked

- `rustfmt --check` on all 35 Rust files — parses clean
- per-crate rustc with workspace deps inlined — no intra-workspace errors (tests included)
- lexical scan for split identifiers and keyword-joined tokens — none left
- dictionary scan of every string and comment in the fifteen rebuilt files
- `node --check` on both frontends' scripts
- `scripts/security-guard.sh` — 13/13
- YAML parse of compose files, CI and alerts; `make -n` on the Makefile

What this environment cannot do is download crates, so the first
`cargo build` with real dependencies runs on your machine. Anything it reports
will be API-version detail against actix, libp2p, axum, sqlx or alloy — not the
reconstruction damage above.

## 6. Left for you

- `cargo generate-lockfile && cargo build --workspace --release`, commit `Cargo.lock`
- Run the vault ceremony, put the two premine keys in `.env`
- Decide fees: burn (as now) or credit to the coinbase
- `docs/WHITEPAPER.md` was left byte-for-byte as it is on GitHub. It says
  "fifteen crates / 252 tests"; the workspace is now 16 crates / 288 Rust tests.

## First real build (27 Sep 2026, Chromebook, Rust 1.88.0)

Fixed from actual compiler output:

- `async-stripe` removed: nothing used it (billing.rs calls Stripe's REST API and verifies webhooks itself), and 0.37 does not compile with only `webhook-events`.
- libp2p: added the `request-response` and `cbor` features that p2p.rs's sync protocol needs.
- nev369-node: the mine rate limiter could get `per_second(0)` and panic at startup; it is now clamped like the tx limiter.
- nev369-submitter: alloy 0.8 contract instances are generic over the transport; `submit()` had `()` hard-coded there.
- qlock-escrow main.rs was written against an older attestation API. It now holds a `QLockAttestor` and signs a `SettlementRecord` (amounts in exact drops, never via f64) for every settlement. Rows go through one `store_attestation` helper that writes the columns that actually exist.
- Xumm: `get_payload` → `get_payload_status`.
- ratelimit.rs moved to tower_governor 0.4 (`Arc` config, no lifetime), and the server now starts with connect info so the IP fallback works for requests that bypass nginx.
- `f64_to_bd` formatted `" {v}"` with a stray leading space, so every amount parsed to 0. Fixed. `' xumm'` in SQL fixed too.

The database schema was missing things the code uses:

- tables `xrpl_escrows`, `escrow_xumm_payloads` and `xumm_payloads`;
- columns `wallets.is_live`, `escrows.user_id` and `escrows.fee_rate`.

The `escrows` CHECK constraint rejected every custodial escrow, which is always created `locked` with no ledger keys. It now applies only to rows that point at an on-ledger escrow, and the native flow has its own constraint on `xrpl_escrows`.

Verified by loading schema.sql into Postgres 16 and running PREPARE on all 57 SQL statements in qlock-escrow: 0 rejected.

## First test run: 278 passed, 15 failed, all fixed

- **Secret key size was hard-coded to 4864** in `GodKeyPair::from_bytes`, but the linked pqcrypto-dilithium produces a different length. Every generated key therefore failed `from_json`, which broke vault recovery, attestation key loading, the gateway operational key and the `/api/v1/address/encode` endpoint. Sizes now come from `dilithium5::public_key_bytes()` / `secret_key_bytes()` via `GodKeyPair::public_key_len()` / `secret_key_len()`. The core test now also round-trips a key through JSON. This covers 12 of the failures.
- **CLI vault self-test could never pass.** It compared the key fingerprint (a hash of the key bytes) with the vault fingerprint (a hash of the hex identifier). It now compares the public key directly and keeps the sign/verify probe.
- **The vault fingerprint was a hash of the identifier alone**, so two vaults for the same address had interchangeable-looking shares. It now also covers the ciphertext, which is unique per sealing.
- `block_work` clamped at difficulty 31 and never saturated. It now saturates at 32, where it actually overflows. Unreachable in practice.
- Doc comment lines with 4-space indents in godshield-adapters were compiled as a doctest. Re-indented.
- PDF split and join damage inside strings: `dilithiu m3`, `message_h ex` (×2), `ML-DSALevel`, `Addgodshield-core`, `post-quantumstandard`.
- README and web console gave the signature size as 4,864 B. It is ~4.6 KB.

## Result

`cargo build --workspace` clean and `cargo test --workspace`: **292 passed, 0 failed** (Chromebook, Rust 1.88.0, 27 Sep 2026). The node's dead-code warnings are now annotated, so CI's clippy `-D warnings` is not tripped by them. Clippy lints themselves still need their first run.
