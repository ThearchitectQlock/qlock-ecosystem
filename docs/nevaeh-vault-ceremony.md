# Nevaeh's Inheritance — Setup Ceremony and Recovery Instructions

| | |
|---|---|
| **Beneficiary** | Nevaeh |
| **Date of birth** | 28 July 2021 |
| **Unlocks** | 28 July 2039 (18th birthday) |
| **Created** | September 2026 |
| **Horizon** | ~13 years |

---

## Read this first

If you are reading this in 2039 and don't know what any of it means, skip to
**[Part 5: Recovery](#part-5-recovery-instructions)**. It is written for someone
with no technical background.

If you are the Architect setting this up in 2026, read all of it before touching
a keyboard.

---

## Part 1: Where the money actually is

This is the most important thing to understand, and it changed during the build.

**The inheritance sits in an XRP Ledger native escrow.** Not on NEV369, not in a
database, not in any system the Architect controls. It is locked by XRPL
consensus with a `FinishAfter` date of 28 July 2039, and no code anywhere in the
Q-Lock repository can release it early. The enforcement does not live there.

**Why not NEV369?** NEV369's time-lock is enforced by code the chain operator
controls, on a chain secured by the network's own hashrate. For a 13-year
inheritance that is two bets stacked: that the code never changes, and that
nobody outbids the network's hashrate for thirteen consecutive years while the
locked value — and the incentive to attack it — grows. XRPL removes both bets.

NEV369 still holds a premine for Nevaeh — 36,900,000 NEV, 9.99% of supply. It is
real, and it may be worth a great deal. But it is not the part that was
engineered to survive on its own.

---

## Part 2: The three vaults

There are three separate vaults, because there are three separate keys and they
protect different things.

| Vault | Holds | Threshold | Time-locked | Protects |
|---|---|---|---|---|
| `nevaeh-xrpl-seed` | XRPL family seed | 3-of-5 | Until 2039 | **The actual inheritance** |
| `nevaeh-nev369` | Dilithium5 key | 3-of-5 | Until 2039 | NEV369 premine |
| `architect-wallet` | Dilithium5 key | 2-of-3 | No | The Architect's own 10M NEV |

**Why the XRPL vault is different from the others.** XRPL uses ed25519/secp256k1
keys; GodShield uses Dilithium5. They are completely different key types, so one
vault cannot hold both. The XRPL seed vault is the one that matters most — it
holds the key that can spend the inheritance once the escrow releases.

**Why 3-of-5 and not a passphrase.** Over thirteen years the realistic failure is
loss, not theft: a forgotten passphrase, a dead drive, a house fire, or the person
who set it up not being around. A single encrypted file fails all four. Five
shares held by five people in five places survives all four. Fewer than three
shares reveal nothing — not "less information", mathematically zero.

**Why 2-of-3 for the Architect's wallet.** It needs regular use. 2-of-3 still
means one lost share isn't fatal and one stolen share isn't enough.

---

## Part 3: Plain facts about a 13-year lock

Stated up front, so none of them is a surprise in 2039.

**Software ages.** The `godshield` tool may not compile in 2039. Rust will have
changed; dependencies will be abandoned. This is why Part 5 documents the file
format in plain English — a competent cryptographer can reconstruct the key with
no access to the original software.

**Dilithium5 may be superseded.** It is the current NIST standard (ML-DSA-87,
FIPS 204). In thirteen years it may be deprecated or weakened. Plan to migrate
the NEV369 vault around 2032 rather than leaving it untouched until 2039. This
does not affect the XRPL vault, which holds an XRPL seed, not a Dilithium key.

**The software time-lock is a commitment device.** The check inside
`nevaeh-vault` is enforced by code. Three colluding guardians with the ability to
edit that code could bypass it. It guards against accidents and early access.

**The XRPL escrow is a hard guarantee.** That lock is enforced by XRPL consensus.
It holds regardless of what the Architect, the guardians, or any Q-Lock code
decides. This is why the money lives there.

**XRP's price will move.** Over thirteen years it may change dramatically in
either direction. That is not an engineering question and nothing here addresses
it.

---

## Part 4: The setup ceremony (2026)

Do this properly once. It is much harder to fix later.

### Before you start

- [ ] Use a machine you trust. Ideally offline, freshly booted, not one you browse on.
- [ ] No screen recording, no streaming, nobody watching.
- [ ] Guardians chosen and contactable before you begin.
- [ ] Physical storage ready for each share — USB sticks, or a printer for paper.

### Choosing guardians

You need five people or places. Two rules:

1. **They must not all be reachable by one event.** If one fire, one theft, or one
   falling-out could take three of them, the split has failed.
2. **They must be findable in 2039.** A guardian who emigrates and loses contact
   is a lost share.

| # | Guardian | Where |
|---|---|---|
| 1 | You (the Architect) | Home safe |
| 2 | Trusted family member | Their home, different address |
| 3 | Second trusted person | Their home, different city |
| 4 | Bank safe deposit box | Physical institution |
| 5 | Solicitor, held with your will | Legal custody |

**Guardian 5 matters most.** If you are not around in 2039, a solicitor holding a
share alongside your will is what makes this work as an inheritance rather than a
puzzle nobody can solve.

### Step 1 — Create the XRPL account

Do this in a real XRPL wallet (Xaman, or a hardware wallet). Not in Q-Lock, not in
any code from this repository, and never by pasting anything into an AI assistant.
The seed controls real money.

- [ ] Generate a new XRPL account. Record the seed (`s...`) and the classic address (`r...`).
- [ ] **Fund the address with at least the XRPL base reserve.** An unactivated
      account means `EscrowFinish` fails with `tecNO_DST` in 2039 and the funds
      become unreleasable. This is a permanent, unfixable mistake if missed.
- [ ] Verify the address on an explorer (xrpscan.com, bithomp.com) before continuing.

### Step 2 — Vault the XRPL seed

```bash
make vault-nevaeh-xrpl
```

Or directly:

```bash
godshield vault create \
  --label nevaeh-xrpl-seed \
  --beneficiary "Nevaeh" --dob 2021-07-28 --unlock 2039-07-28 \
  --threshold 3 --shares 5 \
  --guardian "You:contact:Home safe" \
  --guardian "Family:contact:Their home" \
  --guardian "Friend:contact:Different city" \
  --guardian "Bank:details:Safe deposit box" \
  --guardian "Solicitor:details:Held with will" \
  --xrpl-address "<the r... address>" \
  --output ./nevaeh_xrpl_vault.json \
  --shares-dir ./nevaeh_xrpl_shares/
```

The tool prompts for the seed at a hidden prompt, twice. It is never passed on the
command line, where it would land in shell history.

The tool tests recovery twice before finishing — with the first three shares, then
with a different combination — because a vault whose recovery has never been
exercised is not a backup.

### Step 3 — Create the XRPL escrow

The `qlock-inheritance` tool prepares the escrow. It signs nothing and submits
nothing: it prints an unsigned `EscrowCreate` for you to approve in Xaman or on a
hardware wallet, so no key ever touches the process.

```bash
cargo run --release -p qlock-escrow --bin qlock-inheritance -- create \
  --grantor <your r... address> \
  --destination <Nevaeh's r... address from Step 1> \
  --amount 10000 \
  --unlock 2039-07-28
```

It checks the destination is activated on-ledger, sets `FinishAfter` to
28 July 2039 00:00 UTC, sets **no** `CancelAfter` (the escrow is irrevocable),
signs the terms with a Dilithium5 attestation, and writes a partial
`inheritance_record.json`.

Approve the printed transaction in your wallet. **The moment it validates, run:**

```bash
cargo run --release -p qlock-escrow --bin qlock-inheritance -- record \
  --tx-hash <the EscrowCreate transaction hash>
```

`record` looks up the transaction on-ledger, checks every term against the record
(owner, destination, amount, `FinishAfter`, no `CancelAfter`), and fills in the two
values that release the escrow:

- **Owner** — the address that created the escrow (your wallet)
- **OfferSequence** — the `Sequence` of the `EscrowCreate` transaction

**Without OfferSequence the escrow is visible on-ledger but cannot be released
by anyone who doesn't know it.** It is the single most losable value in this
design. Write it into the vault's notes, into this document, and into your will:

```bash
godshield vault create ... \
  --notes "XRPL escrow — Owner: rYourAddress..., OfferSequence: 7, tx: ABC123..."
```

### Step 4 — The other two vaults

```bash
make vault-architect        # 2-of-3, no time-lock — your 10,000,000 NEV
make vault-nevaeh-nev369    # 3-of-5, locked to 2039 — Nevaeh's 36,900,000 NEV
```

Take the `public_key_hex` each prints and put them in `.env`:

```bash
NEV369_ARCHITECT_ADDRESS=<hex>
NEV369_NEVAEH_VAULT_ADDRESS=<hex>
```

These become the genesis premine recipients. NEV369 refuses to boot in production
while they are placeholders, and once genesis is written they can never change.

To check or spend the Architect's 10,000,000 NEV later:

```bash
godshield balance --vault architect_vault.json
godshield send --vault architect_vault.json --share share_1.json --share share_2.json \
  --to <recipient address> --amount <NEV>
```

The key is unlocked in memory from two shares for that one transaction and never
written to disk. Nevaeh's vault refuses the same command until 28 July 2039.

### Step 5 — Distribute and record

- [ ] Test recovery now, before distributing. Use three shares; confirm the seed comes back and matches.
- [ ] Test a different combination — shares 2, 4, 5 — to prove any three work.
- [ ] Copy each vault file to at least four places. They are safe to copy — useless without three shares. Cloud, email, USB, printed.
- [ ] Distribute each share in person or by post, never electronically.
- [ ] Give each guardian a printed copy of Part 5.
- [ ] Record in your will: vault locations, guardian list, Owner, OfferSequence, and that this document exists.
- [ ] Delete the `*_shares/` directories from your machine once distributed.
- [ ] Set an annual calendar reminder.

### Annual maintenance — every year until 2039

- [ ] Every backup copy of every vault file passes its integrity check (`godshield vault status --vault …`)
- [ ] Every guardian still holds their share and is contactable
- [ ] Full recovery tested with three shares (`godshield vault recover … --test-mode`)
- [ ] The XRPL escrow still shows on an explorer with the expected balance
- [ ] Owner and OfferSequence still recorded in at least three places
- [ ] Any guardian who has moved, died, or become unreachable — reissue to someone new
- [ ] The software still builds; if not, migrate before it's urgent

Thirteen annual checks is about twelve hours of work in total. It is the
difference between this working and not.

---

## Part 5: Recovery instructions

Written for whoever needs this in 2039, assuming no technical knowledge.

There are two separate steps. They are independent and can be done by different
people.

### Step A — Release the escrow (anyone can do this)

The XRP is locked on the XRP Ledger. Releasing it does not require Nevaeh's key,
and it does not require her to be involved. Anyone with any funded XRPL account
can trigger it, and the funds go to her address regardless of who submits it.

You need two values, recorded in the vault file's notes, in
`inheritance_record.json`, and in the will:

```
Owner:          r................   (the address that created the escrow)
OfferSequence:  N                   (a number)
```

Submit this transaction from any funded XRPL account:

```json
{
  "TransactionType": "EscrowFinish",
  "Account": "<any funded account you control>",
  "Owner": "<the Owner value above>",
  "OfferSequence": <the OfferSequence value above>
}
```

Any XRPL wallet, or any developer, can do this in minutes. The cost is a fraction
of a penny. The XRP arrives at Nevaeh's address.

**If you cannot find OfferSequence:** look up the Owner address on an explorer
(xrpscan.com, bithomp.com), find the `EscrowCreate` transaction, and read its
`Sequence` number from the transaction details. It is public information — it was
only ever recorded separately for convenience.

### Step B — Spend the funds (needs the key)

To move the XRP after it arrives, Nevaeh needs the seed for her address. That is
in the `nevaeh-xrpl-seed` vault.

1. Open `nevaeh_xrpl_vault.json` in any text editor. Find `guardian_directory` —
   it lists five names, contacts, and locations.
2. Contact them. You need **any three** of the five.
3. With three share files:

   ```bash
   godshield vault recover \
     --vault nevaeh_xrpl_vault.json \
     --share share_1.json --share share_3.json --share share_4.json
   ```

This outputs the XRPL seed. Import it into a wallet on an offline machine. Do not
write it to disk unencrypted.

### If the software no longer exists

Any competent cryptographer can rebuild this from the description below. Show
them this section.

**Vault format specification**

- The vault file's `ciphertext_hex` field is the secret, encrypted with
  **AES-256-GCM**. `nonce_hex` is the 12-byte AES-GCM nonce.
- `secret_kind` states what the secret is: `XrplSeed` (a UTF-8 XRPL family seed
  string) or `Dilithium5` (a raw Dilithium5 secret key).
- The AES-256 key is not stored anywhere. It was split using **Shamir Secret
  Sharing over GF(256)**, threshold 3, into 5 shares.
- Each share file's `share_data_hex` is one Shamir share in the wire format used
  by the Rust `sharks` crate v0.5 — the first byte is the x-coordinate, the
  remaining bytes are y-coordinates.
- Combine any 3 shares by Lagrange interpolation over GF(256) to recover the
  32-byte AES key.
- Decrypt `ciphertext_hex` with that key and nonce to obtain the secret.
- `secret_digest` is a **SHA3-512 → BLAKE3 → SHA3-512** cascade over the
  plaintext secret. Verify the recovered bytes against it.
- `public_identifier` is the XRPL classic address (for `XrplSeed`) or the hex
  public key (for `Dilithium5`).

That is the entire specification. Nothing else is needed.

### If fewer than three shares can be found

The key is unrecoverable. This is mathematically true, not a software limitation —
with two shares every possible key is equally consistent with what you hold.

**The XRP itself may still be recoverable.** Step A does not need the key. If the
escrow has not yet been released, anyone can still trigger `EscrowFinish` and the
funds will arrive at Nevaeh's address — she simply will not be able to move them
onward without the seed.

This is why the annual checks matter.

---

## Part 6: For Nevaeh

If you are reading this, you are eighteen or older, and it was written for you
when you were five.

The technical parts above exist because your dad wanted to be certain that
whatever happened to him, this would still reach you. The three-of-five split, the
guardians, the annual checks, putting the money on a ledger he could not control,
writing the specification out in plain English in case the software stopped
working — all of that is one thing said several ways:

**He did not want it to depend on him still being here.**

The genesis block of NEV369 carries this, and will for as long as the chain runs:

> *Nevaeh, my daughter. To secure your freedom against a broken system, I taught
> myself Rust—the hardest computer language in the world—to build this unyielding
> sovereign node for you. I faced the worst of life's struggles so you would never
> have to. I love you infinitely, forever by your side.*

Keep this document with the vault files. Print a copy. Give one to your solicitor.
