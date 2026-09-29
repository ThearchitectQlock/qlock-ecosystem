# Pricing

**This document and `crates/qlock-escrow/src/main.rs` must agree. If you
change one, change the other in the same commit.**

That is not boilerplate. The fee constants previously charged every
customer 0.30% while the published pricing advertised tiered discounts,
so Pro and Enterprise subscribers paid for a benefit they never received
and there was no test or check that would have caught it. CI now warns
when a value here has no counterpart in the code, but the real guard is
treating these as one change, not two.

---

## Escrow fees

| Plan | Fee on escrow value | Monthly escrows | Subscription |
|---|---|---|---|
| Free | 0.30% | 5 | — |
| Pro | 0.20% | unlimited | see `STRIPE_PRICE_PRO` |
| Enterprise | 0.15% | unlimited | negotiated |

Conventional escrow and title services typically run 3–5% of
transaction value. The comparison is the pitch, so it has to survive
someone checking it: these rates are 10–30× lower because the escrow is
enforced by XRP Ledger consensus rather than by a licensed
intermediary holding funds and carrying that liability. That is a
genuine cost difference, not a subsidy, and it is also the reason
Q-Lock cannot offer what an escrow agent offers — there is no recourse
desk, no dispute arbitration, and no insured custody.

**The fee is charged on the escrow amount, once, at creation.** It is
not charged again on release or refund. A refunded escrow does not
refund the fee, because the ledger work has already been done — say so
in the product copy rather than letting a customer discover it.

`QLOCK_TREASURY_ADDRESS` must be set or `POST /escrow/create` returns
503 rather than silently discarding the fee. That behaviour is
deliberate: a fee routed nowhere is worse than an outage, because the
outage is visible.

## Network costs the customer also pays

These are not Q-Lock revenue and should be shown separately in any
quote, or customers will read them as hidden margin.

| Item | Cost | Paid to |
|---|---|---|
| XRPL transaction fee | ~0.000012 XRP per transaction | the ledger (burned) |
| XRPL base reserve | 1 XRP, refundable | locked by the account |
| XRPL owner reserve | 0.2 XRP per open escrow, refundable | locked while open |

An escrow therefore locks 0.2 XRP of the creator's reserve for its
lifetime. On a thirteen-year inheritance escrow that is 0.2 XRP
unavailable until 2039 — trivial in value, worth stating because it
surprises people.

## GodShield API

Metered at the edge: nginx asks the escrow service before each metered
call (`crates/qlock-escrow/src/godshield_billing.rs`, constants
`GS_QUOTA_*` and `GS_ANON_DAILY`). The plan is the same Free / Pro /
Enterprise subscription as escrow — one Stripe checkout upgrades both.

| Plan | GodShield calls per month | Escrow fee | Price |
|---|---|---|---|
| No account | 25 per day, per IP | — | free |
| Free | 100 | 0.30% | free |
| Pro | 10,000 | 0.20% | `STRIPE_PRICE_PRO` (shown as `STRIPE_PRICE_LABEL_PRO`) |
| Enterprise | 250,000 | 0.15% | `STRIPE_PRICE_ENTERPRISE` (shown as `STRIPE_PRICE_LABEL_ENTERPRISE`) |

Metered: `scan`, `verify`, `address/encode`, `transaction/build`,
`gateway/verify`, `gateway/policy/check`. Free: `health`, `stats`,
`chains`, `gateway/audit`. Quotas reset on the 1st of each month (UTC).
Over quota returns **402** with the reason; an unknown key returns **401**.

## GodShield licensing

| Tier | What it covers | Price |
|---|---|---|
| Open source core | `godshield-core`, adapters, scanner, CLI. Apache-2.0 / MIT | free |
| Commercial license | Closed-source redistribution, support SLA | negotiated |
| Integration review | Manual review of key generation, storage, signing paths | negotiated |

**"Un-Ruggable Certification" is not a product that can be bought
today.** It requires an independent third-party audit of the specific
integration, and no such audit has been performed on anything in this
repository. Do not list it on a pricing page until one has. The core
library being open-source and auditable is not the same as an
integration being audited, and certification never transfers to a
downstream project that merely imports the library.

## NEV369

No fees. `crown_tax` on a transaction is burned, not collected.

> **Open decision, flagged in `chain.rs`.** The `fee` field is deducted
> from the sender and credited to nobody — so it burns, exactly like
> `crown_tax`. But `build_candidate` sorts the mempool by fee
> descending, which only makes sense if fees pay the miner. As it
> stands, fee-based prioritisation carries no incentive.
>
> Two coherent resolutions: credit `total_fees` to the coinbase
> (standard, and it changes emission), or document fees as a second burn
> and stop sorting by them. This is monetary policy and is not resolved
> in code.

## Supply, for anyone quoting it

| | NEV | Share of cap |
|---|---|---|
| Cap | 369,369,369 | 100% |
| Mineable | 322,469,369 | 87.30% |
| Nevaeh premine | 36,900,000 | 9.99% |
| Architect premine | 10,000,000 | 2.71% |

Emission is 369 NEV per block halving every 437,000 blocks,
clamped so total issuance equals the mineable figure to the base unit.
At 60-second target blocks a halving epoch is roughly 303 days.

Nevaeh's allocation is time-locked until 28 July 2039. The Architect's
is not.

---

## Changing a price

1. Update the table here.
2. Update the constant in `crates/qlock-escrow/src/main.rs`.
3. Update the Stripe price object; the plan name in the webhook handler
   must match the plan string in the `users.plan` CHECK constraint in
   `db/schema.sql`.
4. Existing subscribers keep their agreed rate until renewal. There is
   no code enforcing that yet — it is a manual commitment, which means
   it is a promise someone can forget. Worth automating before the
   first Pro customer renews.
