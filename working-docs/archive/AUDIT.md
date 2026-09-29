# Q-Lock ecosystem — audit

Static review across 62 unique source files and 38 written files.

**What this is not:** an audit. Nothing here has been compiled, executed,
or reviewed by an independent party. This is one careful reading of
source text, and the class of bug it cannot find — race conditions,
integer behaviour under real load, anything that only appears when two
nodes disagree at speed — is exactly the class that costs money on a
blockchain. Treat it as a list of things worth checking, not a clearance.

Severity: **C** breaks the money · **H** breaks the product ·
**M** wrong but bounded · **L** worth knowing.

---

## Resolved in this pass

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | **C** | In-block double-spend / unbounded mint. `validate_block_contents` never re-checked balance or nonce, so two same-nonce transactions both passed and the second credited its recipient from a zero balance | `chain.rs` |
| 2 | **C** | wNEV used 18 decimals against NEV369's 8, with no scaling anywhere. Lock 1 NEV → receive 0.0000000001 wNEV | `wNEV.sol` |
| 3 | **C** | `GodShield::verify` trusted the caller-supplied `message_hash`, so one captured signature forged arbitrary messages | `godshield-core` (yours) |
| 4 | **C** | `ARCHITECT_ADDRESS` in the signature-exemption list — any inbound transaction claiming it auto-verified | `chain.rs` (yours) |
| 5 | **C** | Delimiter-free `format!` signing bytes: `sender="AB"/recipient="C"` signed identically to `"A"/"BC"` | `chain.rs` (yours) |
| 6 | **H** | The two contracts imported `Pausable` from OZ v4 and v5 paths respectively — could not compile together against any version | both `.sol` |
| 7 | **H** | `MAX_SUPPLY` 369,369,369 vs a schedule emitting 21,000,000. ~301M had no issuance path | `chain.rs` |
| 8 | **H** | `wNEV.burn` called `_burn` with no allowance check — BRIDGE_ROLE could destroy any holder's balance | `wNEV.sol` |
| 9 | **H** | Escrow FKs pointed counterparty addresses at `wallets` — every transfer to a non-customer violated the constraint | `schema.sql` |
| 10 | **H** | No `consensus.rs`. `chain.rs` imported 12 methods and 5 variants that existed nowhere | — |
| 11 | **H** | No `attestation.rs`. `lib.rs` exported it, `main.rs` panicked without it | — |
| 12 | **H** | Scanner matched `RSA` as a substring: `traversal`, `adversary`, `universal`, `reversal` all reported CRITICAL | `godshield-adapters` |
| 13 | **M** | Scanner skipped `#` as a comment, hiding every `#[cfg(feature = "secp256k1")]` gate | `godshield-adapters` |
| 14 | **M** | Scanner missed `p256`, `prime256v1`, `secp256r1`, `bls12_381`, `bn254`, `ml_dsa_44` | `godshield-adapters` |
| 15 | **M** | Fairness used `next_u64() % n` and claimed a CSPRNG avoids modulo bias. It does not | `godshield-fairness` (yours) |
| 16 | **M** | `burnId` hashed mutable block context — two identical burns in one block collided and the second reverted | `NEV369Bridge.sol` |
| 17 | **M** | Coinbase and supply validated at the *current tip* height, so side-branch rewards were measured against the wrong halving epoch | `chain.rs` |
| 18 | **M** | `consensus.rs` validated proof of work but not timestamps. Backdating drives difficulty *down* via the retarget window | `consensus.rs` |
| 19 | **M** | Orphan pool bounded globally only; the claimed parent hash is attacker-controlled, so one fabricated parent filled all 500 slots | `consensus.rs` |
| 20 | **M** | `NEVAEH_UNLOCK_TIMESTAMP` and `GENESIS_DEDICATION` defined in two modules — tests read one copy, production the other | `chain.rs` |
| 21 | **M** | Time-lock checked via `is_timelocked()` on one path and a direct address comparison on the other | `chain.rs` |
| 22 | **M** | Reorg persisted the accepted block's hash as tip, not the tree's tip — wrong when orphans connected past it | `chain.rs` |
| 23 | **M** | Dead index-keyed `persist_block` contradicting the hash-keyed scheme, one call from reintroducing fork-clobbering | `chain.rs` |
| 24 | **M** | Docker healthcheck ran `curl` in an image with no curl. Permanently unhealthy → restart loop | `Dockerfile` |
| 25 | **M** | Two compose files both bound `:8080` and both declared nginx on `:80/:443` — could not run together | compose |
| 26 | **M** | CI's auth-bypass guard grepped `main.rs` at the repo root, a file that does not exist. It passed unconditionally | `ci-cd.yml` |
| 27 | **M** | `DECIMAL(20,6)` truncated NEV369's 8 decimals at the database layer | `schema.sql` |
| 28 | **M** | `nginx.conf` set `Connection ""` right after `Upgrade`, silently breaking the Xaman WebSocket | mine, caught by your `proxy_params` |
| 29 | **M** | Test `genesis_does_not_rerun_on_restart` called `new()` with one argument — the persistence guard was not running | `chain.rs` |
| 30 | **L** | `attestations.device_id NOT NULL` with no server-side value. I then wrongly *removed* the column; `inheritance.rs` does use it | `schema.sql` |
| 31 | **L** | Explorer: a 128-hex search routed to `#/block/` and never tried `#/tx/`, despite a comment claiming it did | mine |
| 32 | **L** | Explorer: unguarded `localStorage` read at module scope — throws and kills the page when storage is disabled | mine |
| 33 | **L** | `attestation.rs`: `unwrap_or_default()` on key serialisation let a broken identity pass startup and fail at first signature | mine |
| 34 | **L** | Prometheus scraped a `backend` host that does not exist in this compose stack | `prometheus.yml` |

Fourteen of these were in code you wrote, sixteen I introduced or
inherited and then fixed, and four I got wrong the first time and
corrected on a second reading — #30 and #33 in particular were mine.

---

## Open, and it is not code that closes them

### C-1 · The bridge relayer verifies nothing

`nev369-relayer-main.rs` has no chain connection. No RPC client, no
node query, no Ethereum call. `POST /api/locks` records whatever JSON a
caller sends, authenticated by one shared static `RELAYER_KEY`.

So a lock record exists because someone with the key said so.
`mintFromNEV369` then mints wNEV against it. **Anyone holding
`RELAYER_KEY` can mint wNEV with no NEV369 lock ever occurring.**
`processedLocks` stops an id being replayed; it cannot tell whether an
id ever meant anything.

The hardening in that file is real and correct — constant-time key
compare, no default key, atomic writes, fatal error on corrupt store,
amounts kept as strings rather than through `f64`. None of it touches
this, because the gap is architectural.

Three ways out, in descending cost and descending trust:
1. A light client verifying NEV369 block headers on Ethereum
2. An *m*-of-*n* multi-signer threshold replacing the single key
3. Accept it, cap exposure with the per-window mint limit, and say so
   publicly

The per-window limit I added is (3) in code. It bounds a stolen key to
one window's worth instead of everything. It is mitigation, not a fix.

**Compounding factor:** a bridge inherits its source chain's soundness.
Before the fix, NEV369 could mint from nothing — so the bridge could
have imported unbacked supply through the front door regardless of the
relayer. That half is now closed.

### H-1 · `GodShieldScanner` rejects every real signature

Your wire-size validator hardcodes `ml_dsa_sig_size: 4627`.
`godshield-core` uses **4864**, and already has `len() != 2592` and
`len() != 4864` checks in `verify`.

Two consequences:
- 4627 would reject 100% of signatures the core produces. Fails closed,
  so nothing forges — but nothing verifies either.
- The capability already exists in core, with a different constant. Two
  files in one workspace disagreeing about a signature length is how you
  get a node that accepts what another rejects.

Delete the duplicate check, or move it into `godshield-core` beside the
sizes it belongs to and derive the constants from a generated keypair in
a test rather than typing them.

Also: the test never caught it. `audit_payload` checks the public key
first and returns early, so with `bad_pub` set the signature branch never
executes. The 4627 constant was untested.

### H-2 · Nothing has been compiled

`consensus.rs` (merged), `chain.rs`, `attestation.rs` and
`godshield-scanner` have never been through `cargo check`. I have no Rust
toolchain. Expect real errors on the first run — that is the expected
outcome, not a failure.

`main.rs` and `sync.rs` exist only as PDFs that hard-wrap at ~30
characters. 1,065 of 1,442 lines are mid-token fragments, and a wrapped
`//` comment turns its second line into code silently. I will not
reconstruct those; send them as `.rs`.

### M-1 · Fees are burned but drive prioritisation

`fee` is deducted from the sender and credited to nobody — it burns,
like `crown_tax`. But `build_candidate` sorts the mempool by fee
descending, so prioritisation has no incentive behind it. Either credit
`total_fees` to the coinbase (changes emission) or stop sorting by fee.
Monetary policy, not a bug to quietly pick.

### M-2 · `inheritance.rs` signs pipe-joined terms

```rust
format!("{}|{}|{}|{}|{}", beneficiary_name, destination_address,
        amount_drops, finish_after, beneficiary_dob)
```

No escaping. A beneficiary name containing `|` re-partitions every field
after it — the same ambiguity as finding #5, which is documented in
`chain.rs` as CRITICAL.

Worse here than there: this signs a thirteen-year inheritance escrow
whose whole purpose is proving in 2039 what was committed in 2026.
`attest_escrow_canonical` (domain `qlock.escrow.v2`) is in
`attestation.rs` and takes the fields individually. **Switch before
creating a real escrow** — switching after means existing attestations
stop verifying.

### M-3 · No node metrics

`nev369-node` exposes no `/metrics`, so the chain side is unobservable.
No height gauge, no mempool depth, no peer count, and no reorg counter —
that last one matters most, because a reorg deeper than a couple of
blocks is the signal that fork choice is misbehaving or someone is
attacking, and nothing would tell you. Three of the five alerts the
README calls for are blocked on this.

### L-1 · Single-instance relayer

Global `Mutex<Store>` over one JSON file. No horizontal scaling, no
shared state between replicas.

### L-2 · Escrow price cache is per-process

`Arc<RwLock<Option<(f64, f64, Instant)>>>`. With more than one replica
each holds its own and they disagree. Redis is already in the compose
stack.

### L-3 · Documented `expect` in `consensus.rs`

`self.index.get(&self.tip).expect("tip is always indexed")`. The
invariant holds by construction, and `panic = "unwind"` means one task
dies rather than the node. Acceptable; noted because a reachable panic
in a node is a denial-of-service.

---

## Where the ecosystem actually stands

**Sound, as far as reading can tell.** NEV369's transaction and block
validation, canonical signing throughout, fork choice by accumulated
work, reorg handling with mempool requeue, integer money end to end, the
emission schedule now reaching its own cap exactly, the vault's 3-of-5
split with a plain-English recovery spec for 2039, and the escrow's
non-custodial architecture — no server-side key can move user funds,
which is structural rather than promised.

**The honest documentation is an asset.** The ceremony doc saying the
software time-lock is a promise and the XRPL escrow is not; the
whitepaper listing what GodShield does not solve; the CLI printing that
nothing has been audited. That is unusual and it is worth keeping when
the pressure comes to soften it.

**Two things stand between this and safe.** The relayer has no
verification, and nothing has been compiled. The first is a design
decision you have to make. The second is a morning's work once
`main.rs` and `sync.rs` arrive as source.

**And one claim has to go.** "Unhackable" appears in the business plan
and a README. Finding #3 above was a signature-forgery bug in the
cryptographic core — found and fixed, but it existed. Nothing here has
been independently audited. That word in a document shown to a customer
or an investor is the highest-risk sentence in the repository, and it is
the one thing on this list that costs nothing to fix.

---

## Next, in order

1. `main.rs` and `sync.rs` as `.rs`
2. `cargo check --workspace` — send me the errors
3. `forge test` on the contracts
4. Delete `GodShieldScanner`'s 4627, or move the check into core
5. Switch `inheritance.rs` to `attest_escrow_canonical`
6. Decide the fee question
7. `./deploy.sh local` — two nodes, force a partition, confirm the reorg
   leaves balances correct
8. Paid review of `godshield-core`, then of each integration
