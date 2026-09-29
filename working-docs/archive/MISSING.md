# What is missing

Machine-checked against every path referenced by `docker-compose.yml`,
the Dockerfiles, `Makefile`, `deploy.sh` and `README.md`.

Fixed in this pass: `nginx/certs/`, `monitoring/grafana/` provisioning,
`LICENSE`. Compose now has zero dangling mounts.

---

## 1 · Generated — nobody writes these, a command does

| | Command | Blocks |
|---|---|---|
| `Cargo.lock` | `cargo check --workspace` | **Both Docker builds.** They pass `--locked`, which fails with "the lock file needs to be updated" until this exists. Dropping `--locked` would fix the build and break reproducibility — wrong trade for a consensus binary |
| `.sqlx/` | `cargo sqlx prepare --workspace` | The escrow image build. Without it, `sqlx`'s compile-time query macros need a live Postgres *during image build* |
| `contracts/lib/` | `forge install OpenZeppelin/openzeppelin-contracts@v5.0.2`<br>`forge install foundry-rs/forge-std` | `forge build` and `forge test` |
| `nginx/certs/*.pem` | certbot, or the self-signed one-liner in `nginx/certs/.gitkeep` | nginx starting |

All four are one command each, and three of them need a working
toolchain first. This is the real ordering constraint: **nothing else
proceeds until `cargo check` runs once.**

---

## 2 · Documents referenced but absent

| File | Referenced by | Status |
|---|---|---|
| `docs/nevaeh-vault-ceremony.md` | README, `Makefile` vault targets | **You have it.** It came through as a PDF and is the most important document in the project — it is what someone reads in 2039. Convert and commit it |
| `docs/WHITEPAPER.md` | README §GodShield | You have it (GodShield Security Whitepaper) |
| `docs/api-reference.md` | README | Never existed |
| `docs/integration-guide.md` | README | Never existed |

The first two exist as PDFs in this thread. The last two would need
writing, and neither blocks anything.

---

## 3 · Code that exists but is not wired

**The bridge relayer.** `godshield-bridge` implements m-of-n threshold
authorization, finality checks, replay protection, exposure limits and a
circuit breaker. `nev369-relayer-main.rs` still records whatever JSON a
caller sends under one shared static key. They do not talk to each other.

Until they do, anyone holding `RELAYER_KEY` mints wNEV with no NEV369
lock ever occurring. This is the single largest gap in the ecosystem and
it is integration work, not new code.

**`inheritance.rs` signs pipe-joined terms.**
`attest_escrow_canonical` exists in `attestation.rs` and takes the fields
individually. `inheritance.rs` still calls the pipe-joined version.
Switch **before** any real escrow exists — switching after invalidates
attestations already made.

**`GodShieldScanner`'s 4627.** `godshield-core` uses 4864 and already
performs the length check. Delete the duplicate or move it into core.

---

## 4 · Never executed

Not missing files. Missing evidence.

- [ ] `cargo check --workspace` — never run
- [ ] `cargo test --workspace` — 250 tests written, 0 run
- [ ] `cargo clippy -- -D warnings` — never run
- [ ] `forge build` / `forge test` — never run
- [ ] `docker compose up` — never run
- [ ] Two nodes gossiping — never run
- [ ] A forced partition and a verified reorg — never run
- [ ] Either frontend opened against a live backend — never run

**Twelve of the 28 Rust files were reconstructed from PDF renders.** They
pass brace balance and identifier checks, but reconstruction gets
structure right far more reliably than identifiers. Expect the first
compile to surface real errors in exactly those files.

---

## 5 · Blocked on a decision, not on work

| | |
|---|---|
| **Fees** | Deducted from senders, credited to nobody — they burn. But `build_candidate` sorts the mempool by fee descending, so prioritisation has no incentive behind it. Credit them to the coinbase, or stop sorting by them |
| **Premine** | `ARCHITECT_ADDRESS` is still the placeholder string, so your 10M is unspendable. Run the vault ceremony, put the hex public key in `.env`, then build genesis. After genesis exists, changing it means wiping the chain |
| **`OfferSequence`** | Not recorded anywhere yet, because the XRPL escrow has not been created. Without it the escrow is visible on-ledger and permanently unreleasable |
| **HSM** (§6) | Which one |
| **Policy language** (§7) | What rules look like beyond algorithm/value/rate |
| **AI capability model** (§11) | What an agent may hold |
| **"Unhackable"** | Still in the business plan and an old README. `godshield-core` shipped a signature-forgery fix during this work. Nothing is audited. Costs nothing to remove |

---

## 6 · Requires other people

- Independent third-party audit of `godshield-core`
- Independent audit of each integration and both Solidity contracts
- Five guardians identified, contactable, and holding shares
- A solicitor holding the fifth share alongside the will

Nothing on this list can be done by writing code, and the first two are
what stands between "written carefully" and "safe to hold value".

---

## The shortest path forward

1. `cargo check --workspace` — paste the errors
2. Fix them, commit `Cargo.lock`
3. `cargo test --workspace` — 250 tests get their first run
4. `forge install` && `forge test`
5. `docker compose up` — two nodes, watch them gossip
6. Wire `godshield-bridge` into the relayer
7. Vault ceremony, then rebuild genesis on real addresses
8. Paid review of `godshield-core`, then of each integration

Steps 1–5 are days. Steps 6–8 are the difference between a working
system and one that can hold money.
