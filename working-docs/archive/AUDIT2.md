# Q-Lock ecosystem — audit, second pass

15 crates · 29 Rust files · ~18,000 lines · 252 tests written · 0 run.

Five crates and both frontends are new since the first audit. This pass
was done by scanning the code — cross-crate symbol resolution, struct
field matching, dependency reachability, string-literal integrity — not
from recall.

**Still true and still first:** nothing has been compiled. No `cargo
check` has run. Nothing has been independently audited.

---

## Fixed in this pass

### 1 · `GodKeyPair` pushed through serde — would not compile · **HIGH**

`godshield-core` derives only `Clone` on `GodKeyPair`. It keeps a
private `GodKeyPairSerde` shape behind explicit `to_json` / `from_json`
helpers, and the comment above it says why: so an accidental serialize
in a log line or an API response cannot leak the secret key.

My `attestation.rs` and `godshield-gateway` both called
`serde_json::to_vec(&kp)` and `from_slice`. Four call sites, none of
which compile — and had they compiled, they would have walked around a
deliberate safety measure.

Replaced with the core's own helpers.

**This is the clearest signal in the audit that reading a crate's API is
not the same as reading its intent.** The type had exactly the shape I
assumed; the derive it was missing was the whole point.

### 2 · Domain separation tag containing a space · **MEDIUM**

```rust
const DOMAIN_REVEAL: &str = "godshield.fairness.reveal.v 1";
```

Introduced when `godshield-fairness` was reconstructed from its PDF
render. It would still have separated domains — any consistent string
does — so nothing would have broken today.

The damage is slower. The tag no longer matched the documented registry,
and it reads like a typo somebody tidies up in six months, at which
point every Fairness reveal signature ever produced stops verifying.

Fixed now, while no signature exists under either spelling. That window
closes the first time a round is played.

### 3 · Three of ten security guards were firing on correct code · **MEDIUM**

`scripts/security-guard.sh` reported three regressions that were not
regressions:

| Guard | Why it fired |
|---|---|
| Exempt-sender list | Regex grabbed `&[&str]` — the *type* — instead of the value |
| Sender/key binding | Required one exact spelling; the local was inlined during a rewrite |
| Fairness modulo | Matched the *comment documenting the fix* |

This is the same failure as the scanner reporting `traversal` as
CRITICAL RSA. **A guard with false positives gets muted, and a muted
guard catches nothing.** All three now match the property rather than one
spelling of it, and the modulo check ignores comment lines.

10/10 passing.

### 4 · Five domain tags in code, absent from the README registry · **LOW**

`GODSHIELD-SENTINEL-SIGNAL-V1`, `GODSHIELD-SENTINEL-EVIDENCE-V1`,
`fairness.round.v1`, `nev369.empty`, `qlock.escrow.v1`. The registry is
the one place a tag collision would be caught, so a tag missing from it
is a gap in the only control. Added.

### 5 · Six user-facing strings missing a space · **LOW**

`GODSHIELDMIGRATION PLAN`, `VAULTCREATION CEREMONY`,
`DO THESE NOW — NOTLATER`, and three more. All from PDF reconstruction,
all in output a human reads. Cosmetic, but they appear in the vault
ceremony banner, which is the last thing someone reads before generating
a key that guards a child's inheritance.

---

## Checked and clean

| Check | Result |
|---|---|
| Every symbol imported from `godshield-core` is exported by it | ✅ |
| `GodPublicKey` / `GodSignature` field names match every construction site | ✅ |
| All 15 crate manifests parse; no unresolved workspace deps | ✅ |
| Every module on disk is declared exactly once | ✅ |
| No file compiled into both the lib and the bin | ✅ |
| Brace balance, all 29 files | ✅ |
| SQL literals with tight commas (`password_hash,api_key`) | ✅ valid — SQL is whitespace-tolerant |
| 10/10 security guards | ✅ |

---

## Open — code

### A · The bridge is not connected to the contracts · **HIGH**

`godshield-bridge` and `nev369-relayer` now implement m-of-n threshold
authorization, and the coordinator holds no signing key. But nothing
carries an `AuthorizationRecord` to `NEV369Bridge.mintFromNEV369`, and
the contract still accepts a call from any address holding
`RELAYER_ROLE`.

So the threshold exists in Rust and the contract does not know about it.
The remaining work is a submitter that presents the collected
attestations, and a contract change to verify them on-chain rather than
trusting the caller.

**Until that lands, the Solidity side is still single-role.**

### B · `inheritance.rs` signs pipe-joined terms · **MEDIUM**

```rust
format!("{}|{}|{}|{}|{}", beneficiary_name, destination_address,
        amount_drops, finish_after, beneficiary_dob)
```

No escaping. A beneficiary name containing `|` re-partitions every field
after it. `attest_escrow_canonical` (`qlock.escrow.v2`) exists and takes
the fields individually; `inheritance.rs` still calls the v1 path.

Both tags are now live in one file, which is the intended migration
shape — but **switch before a real escrow exists.** After that, switching
invalidates attestations already made.

### C · `GodShieldScanner` hardcodes signature length 4627 · **MEDIUM**

`godshield-core` uses **4864** and already performs the length check in
`verify`. 4627 rejects every real signature. Fails closed, so nothing
forges — but nothing verifies either. Delete the duplicate, or move the
check into core where the sizes live.

### D · Twelve declared dependencies are unreferenced · **LOW**

`zeroize` and `thiserror` in core, `sha2` in adapters, `hmac` / `subtle`
/ `dotenvy` in escrow, `argon2` in nevaeh-vault, and five more. Under
`cargo clippy -D warnings` these are warnings, not errors, but `cargo
udeps` would flag them and each is either a dependency to drop or a
feature never wired up.

`argon2` in `nevaeh-vault` is the interesting one — the ceremony
document describes key derivation, and the crate declares the KDF
without calling it. Worth confirming which is true.

---

## Open — not code

| | |
|---|---|
| **Never compiled** | 12 of 29 files were reconstructed from PDF renders. Reconstruction gets structure right far more reliably than identifiers — finding 2 is exactly that class, and there may be more the scans above cannot see |
| **252 tests, 0 run** | Written carefully and never executed |
| **No audit** | Not the core, not either integration, not the contracts |
| **Premine frozen** | `ARCHITECT_ADDRESS` is still the placeholder string. Vault ceremony, then rebuild genesis — and after genesis exists, changing it means wiping the chain |
| **`OfferSequence` unrecorded** | The XRPL escrow does not exist yet |
| **Fees** | Burned, but `build_candidate` sorts by them. Monetary policy |

---

## What is needed, in order

1. **`cargo check --workspace`.** Nothing below matters until this runs
   once. Expect errors concentrated in the reconstructed files.
2. **`cargo test --workspace`** — 252 tests get their first execution.
3. **`forge install` && `forge test`.**
4. **Switch `inheritance.rs` to `attest_escrow_canonical`** — before any
   real escrow, not after.
5. **Delete `GodShieldScanner`'s 4627**, or move the check into core.
6. **Connect the threshold path to the contract** (finding A). Until
   then the Solidity side is single-role whatever the Rust side does.
7. **`./deploy.sh local`** — two nodes, force a partition, confirm the
   reorg leaves balances correct.
8. **Vault ceremony**, then rebuild genesis on real addresses.
9. **Paid review of `godshield-core`**, then of each integration.

Steps 1–5 are days of work. Steps 6–9 are what separates a system that
runs from one that can hold money.
