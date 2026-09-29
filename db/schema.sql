-- ═══════════════════════════════════════════════════════════════════════
-- Q-Lock Escrow — PostgreSQL schema
--
-- EXTRACTED from the inline `db/init.sql` in Docker_Production_Stack, which
-- was the only place this schema existed. It was never a file, so
-- docker-compose mounted a path that did not exist and Postgres
-- initialised empty — every sqlx query would fail at runtime against a
-- database with no tables.
--
-- Named schema.sql to match the compose mount. The old compose used
-- init.sql; pick one and keep it.
--
-- ── FIXES vs. THE INLINE VERSION ──────────────────────────────────────
--
-- 1. MONEY COLUMNS. `DECIMAL(20, 6)` for XRP amounts is wrong twice over:
--
--      - XRP has 6 decimal places, so drops are exact at scale 6. But
--        `balance`, `amount` and `fee` are also used for NEV369 values,
--        and NEV369 has 8 decimals. Storing an 8-decimal amount in a
--        6-decimal column silently truncates the last two digits —
--        rounding at the database layer, after the Rust side went to the
--        trouble of using u64 base units to avoid exactly that.
--
--      - sqlx maps DECIMAL to BigDecimal, which main.rs already uses. So
--        the type is right; only the scale is wrong.
--
--    Widened to DECIMAL(30, 8). Wide enough for NEV369's full supply in
--    base units and XRP's total supply, at a scale that truncates
--    neither.
--
-- 2. FOREIGN KEYS ON WALLETS BROKE EVERY EXTERNAL TRANSFER.
--    `transactions` and `escrows` had FKs from `from_address`/`to_address`
--    to `wallets(address)`. Q-Lock is non-custodial and settles on the
--    public XRP Ledger, so counterparty addresses belong to people who
--    have never had a Q-Lock account. Inserting a transaction to any
--    address not already in `wallets` would violate the constraint and
--    the insert would fail.
--
--    That makes the FK not a data-integrity measure but a functional
--    block on the product's main path. Dropped, with indexes kept so
--    lookups stay fast.
--
-- 3. `attestations.device_id NOT NULL` with no default. The NOT NULL was
--    wrong — server-side attestations have no device — but removing the
--    column was also wrong, which I only found on reading
--    qlock_inheritance.rs. It passes device_id into
--    QLockAttestor::attest_escrow, so it is real on the client signing
--    path. Column kept, made nullable, and `signer_fingerprint` added
--    alongside it rather than instead of it.
--
-- 4. Added `UNIQUE(api_key)` was present; added an index on `users.email`
--    for the login path, which is the hottest query in auth.rs.
--
-- 5. Added `subscriptions` — billing.rs handles Stripe checkout and
--    webhooks, and `users.plan` alone cannot record a Stripe customer or
--    subscription id, so a webhook has nothing to reconcile against.
--
-- ── STILL OPEN ────────────────────────────────────────────────────────
--
-- No migration tooling. This file is mounted as docker-entrypoint-initdb.d
-- and therefore runs ONCE, on an empty volume only. Any change after the
-- first deploy needs a real migration (sqlx migrate), not an edit here —
-- editing this file after launch changes nothing on an existing database
-- and silently diverges dev from production.
-- ═══════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────────
-- Users and auth
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         VARCHAR(255) UNIQUE NOT NULL,

    -- bcrypt hash. auth.rs uses bcrypt::{hash, verify, DEFAULT_COST}.
    --
    -- NOTE: the workspace also declares argon2, which nevaeh-vault uses
    -- for vault key derivation. Two hashers is correct here — they do
    -- different jobs. What must never happen is argon2 being used for a
    -- password while bcrypt verifies it, or vice versa: a user
    -- registered under one and checked against the other is a permanent
    -- lockout that presents as a wrong password. If passwords ever move
    -- to argon2, that is a migration with a hash-prefix check, not a
    -- swap.
    password_hash VARCHAR(255) NOT NULL,

    api_key       VARCHAR(255) UNIQUE NOT NULL,
    plan          VARCHAR(50)  NOT NULL DEFAULT 'free',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT users_plan_known CHECK (plan IN ('free', 'pro', 'enterprise'))
);

-- Login is the hottest query in auth.rs and every request costs a bcrypt
-- verification, so the lookup itself must not also be a scan.
CREATE INDEX idx_users_email ON users (email);

-- ─────────────────────────────────────────────────────────────────────
-- Billing
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE subscriptions (
    id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id                UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    stripe_customer_id     VARCHAR(255),
    stripe_subscription_id VARCHAR(255) UNIQUE,
    plan                   VARCHAR(50)  NOT NULL,
    status                 VARCHAR(50)  NOT NULL DEFAULT 'incomplete',
    current_period_end     TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_subscriptions_user ON subscriptions (user_id);
CREATE INDEX idx_subscriptions_customer ON subscriptions (stripe_customer_id);

-- Stripe retries webhooks, and a retry must not be applied twice.
-- Recording the event id and rejecting duplicates is what makes the
-- handler idempotent; without it a retried `checkout.session.completed`
-- can upgrade a plan twice or double-credit.
CREATE TABLE stripe_events (
    id            VARCHAR(255) PRIMARY KEY,
    event_type    VARCHAR(100) NOT NULL,
    processed_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ─────────────────────────────────────────────────────────────────────
-- Wallets
--
-- Only wallets Q-Lock has been told about. It does NOT contain every
-- address the system transacts with — see fix 2 above.
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE wallets (
    address    VARCHAR(100) PRIMARY KEY,
    user_id    UUID REFERENCES users (id) ON DELETE SET NULL,

    -- Cached, not authoritative. The XRP Ledger is the source of truth
    -- for balances; this is a display convenience and will be stale.
    balance    DECIMAL(30, 8) NOT NULL DEFAULT 0,

    -- True once the address is connected through Xumm: its balance is
    -- then read from the ledger and the cached value is never trusted.
    -- False rows are internal demo balances.
    is_live    BOOLEAN      NOT NULL DEFAULT false,

    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_wallets_user ON wallets (user_id);

-- ─────────────────────────────────────────────────────────────────────
-- Transactions
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE transactions (
    hash          VARCHAR(100) PRIMARY KEY,
    from_address  VARCHAR(100) NOT NULL,
    to_address    VARCHAR(100) NOT NULL,
    amount        DECIMAL(30, 8) NOT NULL,
    fee           DECIMAL(30, 8) NOT NULL,
    status        VARCHAR(50)  NOT NULL DEFAULT 'pending',
    crypto_method VARCHAR(50)  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    confirmed_at  TIMESTAMPTZ,

    -- main.rs returns `status: "demo"` or `"submitted"` from POST /send
    -- specifically so nothing downstream mistakes an internal movement
    -- for a real payment. Constrained here too, so the database cannot
    -- hold a state the API never produces.
    CONSTRAINT transactions_status_known
        CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed', 'demo')),

    CONSTRAINT transactions_amount_positive CHECK (amount > 0),
    CONSTRAINT transactions_fee_non_negative CHECK (fee >= 0)

    -- No FK to wallets. Counterparties are arbitrary XRPL addresses.
);

CREATE INDEX idx_transactions_from ON transactions (from_address);
CREATE INDEX idx_transactions_to ON transactions (to_address);
CREATE INDEX idx_transactions_status ON transactions (status);
CREATE INDEX idx_transactions_created ON transactions (created_at DESC);

-- ─────────────────────────────────────────────────────────────────────
-- Escrows
-- ─────────────────────────────────────────────────────────────────────

-- Custodial escrows: amounts held on Q-Lock's internal ledger. Native
-- on-ledger XRPL escrows live in `xrpl_escrows` below.
CREATE TABLE escrows (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Creator; drives the monthly plan quota. Nullable so deleting a user
    -- does not delete the financial record.
    user_id      UUID REFERENCES users (id) ON DELETE SET NULL,
    from_address VARCHAR(100) NOT NULL,
    to_address   VARCHAR(100) NOT NULL,
    amount       DECIMAL(30, 8) NOT NULL,
    fee_paid     DECIMAL(30, 8) NOT NULL,
    -- Plan fee rate at creation (0.005 = 0.5%), kept because plans change.
    fee_rate     DECIMAL(10, 6),
    status       VARCHAR(50)  NOT NULL DEFAULT 'pending',

    -- The two values that make a native XRPL escrow releasable.
    --
    -- OfferSequence is the single most losable piece of the whole
    -- design: without it an escrow is visible on-ledger and permanently
    -- unreleasable. The ceremony document says to record it in three
    -- places. This is one of them, and it is the only one a machine
    -- reads, so it is NOT optional for any escrow that reaches 'locked'.
    xrpl_owner          VARCHAR(100),
    xrpl_offer_sequence BIGINT,
    xrpl_create_tx      VARCHAR(100),

    finish_after TIMESTAMPTZ,
    cancel_after TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    released_at  TIMESTAMPTZ,

    -- GodShield attestation over the escrow record.
    quantum_proof TEXT,
    conditions    JSONB NOT NULL DEFAULT '[]',

    CONSTRAINT escrows_status_known
        CHECK (status IN ('pending', 'locked', 'released', 'refunded', 'cancelled', 'expired')),
    CONSTRAINT escrows_amount_positive CHECK (amount > 0),

    -- If a row does record an on-ledger escrow, it must carry both
    -- release keys. Custodial rows (no xrpl_create_tx) are 'locked' from
    -- creation with no ledger escrow at all, so the rule applies only to
    -- rows that point at one. The native flow's equivalent is on
    -- xrpl_escrows.
    CONSTRAINT escrows_ledger_rows_carry_release_keys CHECK (
        xrpl_create_tx IS NULL
        OR (xrpl_owner IS NOT NULL AND xrpl_offer_sequence IS NOT NULL)
    )
);

CREATE INDEX idx_escrows_from ON escrows (from_address);
CREATE INDEX idx_escrows_to ON escrows (to_address);
CREATE INDEX idx_escrows_status ON escrows (status);
CREATE INDEX idx_escrows_expires ON escrows (expires_at)
    WHERE status = 'locked';
CREATE INDEX idx_escrows_user_month ON escrows (user_id, created_at);

-- ─────────────────────────────────────────────────────────────────────
-- Native XRPL escrows (non-custodial, signed in Xumm)
-- ─────────────────────────────────────────────────────────────────────
-- Lifecycle, driven by main.rs:
--   pending_fee  → user signs the platform fee payment
--   pending_lock → fee confirmed; user signs EscrowCreate
--   locked       → EscrowCreate validated, OfferSequence recorded
--   released     → EscrowFinish validated
--   refunded     → EscrowCancel validated (after cancel_after)

CREATE TABLE xrpl_escrows (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID REFERENCES users (id) ON DELETE SET NULL,
    owner_address       VARCHAR(100) NOT NULL,
    destination_address VARCHAR(100) NOT NULL,
    amount              DECIMAL(30, 8) NOT NULL,
    fee_amount          DECIMAL(30, 8) NOT NULL,
    fee_rate            DECIMAL(10, 6) NOT NULL,

    -- XRPL "Ripple epoch" seconds (since 2000-01-01), exactly as they go
    -- into EscrowCreate — not Unix time.
    finish_after        BIGINT NOT NULL,
    cancel_after        BIGINT NOT NULL,

    status              VARCHAR(50) NOT NULL DEFAULT 'pending_fee',
    fee_tx_hash         VARCHAR(100),
    create_tx_hash      VARCHAR(100),
    -- OfferSequence: without it the escrow can never be finished or
    -- cancelled. See the constraint below.
    create_sequence     BIGINT,
    finish_tx_hash      VARCHAR(100),
    cancel_tx_hash      VARCHAR(100),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT xrpl_escrows_status_known CHECK (
        status IN ('pending_fee', 'pending_lock', 'locked', 'released', 'refunded')
    ),
    CONSTRAINT xrpl_escrows_amount_positive CHECK (amount > 0),
    CONSTRAINT xrpl_escrows_window CHECK (cancel_after > finish_after),

    -- An escrow that reaches 'locked' without its OfferSequence is funds
    -- on-ledger that nobody can release, so the database refuses it.
    CONSTRAINT xrpl_escrows_locked_requires_sequence CHECK (
        status NOT IN ('locked', 'released', 'refunded')
        OR (create_tx_hash IS NOT NULL AND create_sequence IS NOT NULL)
    )
);

CREATE INDEX idx_xrpl_escrows_owner ON xrpl_escrows (owner_address);
CREATE INDEX idx_xrpl_escrows_destination ON xrpl_escrows (destination_address);
CREATE INDEX idx_xrpl_escrows_user_month ON xrpl_escrows (user_id, created_at);

-- Which Xumm sign request belongs to which escrow step.
CREATE TABLE escrow_xumm_payloads (
    uuid       VARCHAR(64) PRIMARY KEY,
    escrow_id  UUID NOT NULL REFERENCES xrpl_escrows (id) ON DELETE CASCADE,
    kind       VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT escrow_xumm_payloads_kind CHECK (kind IN ('fee', 'lock', 'finish', 'cancel'))
);

CREATE INDEX idx_escrow_xumm_payloads_escrow ON escrow_xumm_payloads (escrow_id);

-- Plain Xumm payments (POST /wallet/xumm/pay): the terms are recorded at
-- request time so the confirmation step cannot be fed different ones.
CREATE TABLE xumm_payloads (
    uuid         VARCHAR(64) PRIMARY KEY,
    from_address VARCHAR(100) NOT NULL,
    to_address   VARCHAR(100) NOT NULL,
    amount       DECIMAL(30, 8) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─────────────────────────────────────────────────────────────────────
-- Post-quantum attestations
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE attestations (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tx_hash             VARCHAR(100) NOT NULL UNIQUE,

    -- Dilithium5 signature and public key, hex. ~4.6 KB and ~2.6 KB
    -- respectively, so TEXT rather than VARCHAR.
    dilithium_signature TEXT   NOT NULL,
    public_key          TEXT   NOT NULL,

    -- TripleHash of the public key. This is the field that binds an
    -- attestation to an identity.
    --
    -- Was `device_id VARCHAR(255) NOT NULL`, which server-side
    -- attestations cannot populate — there is no device. Nullable and
    -- renamed to what the attestation actually carries.
    signer_fingerprint  VARCHAR(255),

    -- RESTORED. I removed this earlier believing nothing populated it.
    -- Wrong: qlock_inheritance.rs passes a device_id straight through to
    -- QLockAttestor::attest_escrow, so it is a real field on the client
    -- signing path. Nullable rather than NOT NULL, because server-side
    -- attestations genuinely have no device — that part of the original
    -- schema was the bug, not the column itself.
    device_id           VARCHAR(255),

    timestamp           BIGINT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_attestations_fingerprint ON attestations (signer_fingerprint);

-- A fingerprint appearing that is not the configured production identity
-- means either a key rotation nobody recorded or forged rows, and the
-- README lists it as an alert that does not exist yet. This view is what
-- that alert would query.
CREATE VIEW attestation_signers AS
SELECT signer_fingerprint,
       count(*)      AS attestation_count,
       min(created_at) AS first_seen,
       max(created_at) AS last_seen
FROM attestations
GROUP BY signer_fingerprint;

-- ─────────────────────────────────────────────────────────────────────
-- updated_at maintenance
-- ─────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER subscriptions_touch_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER xrpl_escrows_touch_updated_at
    BEFORE UPDATE ON xrpl_escrows
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
