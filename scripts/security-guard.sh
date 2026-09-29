#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Regression guards for previously-exploitable bugs.
#
# REPLACES the single grep in the old ci-cd.yml:
#
#   if grep -n "== ARCHITECT_ADDRESS" main.rs | grep -q "return true"
#
# That had three problems:
#
#   1. It targeted `main.rs` at the repo root, which no longer exists —
#      the node is at crates/nev369-node/src/. A guard that greps a
#      missing file passes unconditionally. It was already dead.
#
#   2. It matched one exact source shape. Reintroducing the bypass with
#      `if [GENESIS, NETWORK_REWARD, ARCHITECT_ADDRESS].contains(...)`
#      sails straight through it.
#
#   3. It guarded one bug. Four separate previously-exploitable classes
#      exist in this codebase's history and all four need a tripwire.
#
# These are still greps, and greps are a tripwire on a known-bad shape,
# not a security control. The real controls are the unit tests in
# chain.rs and review. This catches the specific regressions that have
# actually happened here before.
# ═══════════════════════════════════════════════════════════════════════

set -uo pipefail

FAIL=0
NODE_SRC="crates/nev369-node/src"
CORE_SRC="crates/godshield-core/src"
FAIRNESS_SRC="crates/godshield-fairness/src"

red()  { printf '\033[31m%s\033[0m\n' "$1"; }
grn()  { printf '\033[32m%s\033[0m\n' "$1"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$1"; }

fail() { red "  ✗ $1"; shift; for l in "$@"; do echo "      $l"; done; FAIL=1; }
pass() { grn "  ✓ $1"; }
skip() { ylw "  ○ $1 (path not present — guard inactive)"; }

echo ""
echo "  Security regression guards"
echo "  ─────────────────────────────────────────────────────────────"

# ── GUARD 1: signature bypass list ─────────────────────────────────────
# History: ARCHITECT_ADDRESS sat in SIGNATURE_EXEMPT_SENDERS alongside
# GENESIS and NETWORK_REWARD. Any inbound transaction claiming that
# sender auto-verified. Complete drain path for the 10M premine, no
# signature required.

if [ -d "$NODE_SRC" ]; then
  # Take the value after '=', not the type annotation before it.
  # An earlier version matched the first '&[...]' on the line, which is
  # `&[&str]` — the declared type — so the guard reported the contents
  # as unexpected on a perfectly correct list.
  EXEMPT_LINE=$(grep -rh 'SIGNATURE_EXEMPT_SENDERS' "$NODE_SRC" \
                | grep -oE '=\s*&\[[^]]*\]' | head -1 || true)

  if [ -z "$EXEMPT_LINE" ]; then
    fail "SIGNATURE_EXEMPT_SENDERS not found" \
         "The exemption list is the single most security-critical constant" \
         "in the node. If it was renamed, update this guard in the same PR."
  elif [ "$(echo "$EXEMPT_LINE" | tr -cd ',' | wc -c)" -gt 1 ]; then
    fail "SIGNATURE_EXEMPT_SENDERS has more than two entries" \
         "Found: $EXEMPT_LINE" \
         "Only GENESIS and NETWORK_REWARD may be exempt. Both are" \
         "protocol-internal and never arrive over the wire. Any spendable" \
         "address on this list is an unauthenticated drain path."
  elif ! echo "$EXEMPT_LINE" | grep -q 'GENESIS' \
    || ! echo "$EXEMPT_LINE" | grep -q 'NETWORK_REWARD'; then
    fail "SIGNATURE_EXEMPT_SENDERS contents unexpected" "Found: $EXEMPT_LINE"
  else
    pass "signature exemption list is exactly GENESIS + NETWORK_REWARD"
  fi

  # Any early `return true` in verification, however written.
  if grep -rn 'ARCHITECT' "$NODE_SRC" | grep -qE 'return true|=> true'; then
    fail "an ARCHITECT branch returns true in a verification path" \
         "This is the original bypass. Anyone could spend the premine."
  else
    pass "no ARCHITECT short-circuit in verification"
  fi

  # Sender-to-key binding must survive.
  # Match the CHECK, not one spelling of it. This previously required a
  # `derived` local; inlining it to `hex::encode(...) != self.sender`
  # tripped the guard on code that was still correct. A guard that fires
  # on a refactor is a guard people start ignoring.
  if grep -rqE '(derived|hex::encode\(&public_key_bytes\)) *!= *self\.sender' "$NODE_SRC"; then
    pass "sender address is bound to the supplied public key"
  else
    fail "sender/public-key binding check is missing" \
         "Without it, anyone signs with their own key and writes someone" \
         "else's address into the sender field."
  fi
else
  skip "NEV369 node guards"
fi

# ── GUARD 2: integer money ─────────────────────────────────────────────
# History: balances were f64. Floating point silently loses and creates
# value under repeated arithmetic.

if [ -d "$NODE_SRC" ]; then
  if grep -rnE 'type Amount *= *f(32|64)' "$NODE_SRC"; then
    fail "Amount is a float" "Money must be u64 base units. 1 NEV = 100_000_000."
  elif grep -rnE '(balances|amount|fee|crown_tax|total_burned)\s*:\s*f(32|64)' "$NODE_SRC"; then
    fail "a float appears in a balance-carrying field" \
         "$(grep -rnE '(balances|amount|fee|crown_tax|total_burned)\s*:\s*f(32|64)' "$NODE_SRC" | head -3)"
  else
    pass "no floats in money paths"
  fi
else
  skip "integer money guard"
fi

# ── GUARD 3: canonical encoding ────────────────────────────────────────
# History: signing bytes were format!("{}{}{}...") with no delimiters, so
# sender="AB"/recipient="C" produced identical bytes to
# sender="A"/recipient="BC". One signature validated two transactions.
# The same bug independently existed in block hashing and in Fairness
# reveal payloads.

for d in "$NODE_SRC" "$FAIRNESS_SRC"; do
  [ -d "$d" ] || continue
  if grep -rnB2 -E 'fn (signing_bytes|calculate_hash|reveal_payload|derive_outcome)' "$d" \
     | grep -qE 'format!\("\{\}\{\}'; then
    fail "delimiter-free format! inside a signing/hashing function in $d" \
         "Ambiguous concatenation. Use CanonicalMessage::encode with a" \
         "domain tag — length-prefixed and domain-separated."
  else
    pass "no ambiguous concatenation in signing paths ($d)"
  fi
done

# ── GUARD 4: modulo bias ───────────────────────────────────────────────
# History: derive_outcome did rng.next_u64() % outcome_space with a
# comment claiming a CSPRNG avoids modulo bias. It does not. RNG
# certification suites test for exactly that construction.

if [ -d "$FAIRNESS_SRC" ]; then
  # Ignore comment lines. The fairness crate documents the modulo bug it
  # fixed, and the guard was matching that description — reporting a
  # regression against the very comment explaining there isn't one.
  if grep -rn 'next_u64() % ' "$FAIRNESS_SRC" | grep -vE '^[^:]*:[0-9]+: *(//|\*)'; then
    fail "raw modulo on RNG output in Fairness" \
         "Biased whenever outcome_space does not divide 2^64 evenly." \
         "Use rejection sampling — see derive_outcome."
  elif grep -rq 'u64::MAX % outcome_space' "$FAIRNESS_SRC"; then
    pass "Fairness uses rejection sampling"
  else
    fail "rejection-sampling limit computation not found in Fairness" \
         "Expected the 'u64::MAX - (u64::MAX % outcome_space)' bound."
  fi
else
  skip "Fairness RNG guard"
fi

# ── GUARD 5: domain tags are versioned and unique ───────────────────────
# Editing a tag's encoding in place invalidates every signature ever
# produced under it, including records already on the chain.

if [ -d crates ]; then
  TAGS=$(grep -rhoE '"[a-z0-9]+\.[a-z0-9.]+\.v[0-9]+"' crates --include='*.rs' | sort -u || true)
  DUPES=$(grep -rhoE '"[a-z0-9]+\.[a-z0-9.]+\.v[0-9]+"' crates --include='*.rs' \
          | sort | uniq -d || true)
  if [ -n "$TAGS" ]; then
    pass "domain tags found: $(echo "$TAGS" | tr '\n' ' ')"
    [ -n "$DUPES" ] && ylw "      note: reused across files (fine if intentional): $DUPES"
  else
    ylw "  ○ no versioned domain tags found"
  fi
fi

# ── GUARD 6: regression tests still exist ──────────────────────────────
# A test deleted is a guard deleted. These four encode bugs that were
# genuinely exploitable in this codebase.

if [ -d "$NODE_SRC" ]; then
  MISSING=()
  for t in canonical_encoding_prevents_field_boundary_collision \
           architect_address_is_not_signature_exempt \
           sender_must_match_public_key \
           money_is_integer_not_float; do
    grep -rq "fn $t" "$NODE_SRC" || MISSING+=("$t")
  done
  if [ ${#MISSING[@]} -gt 0 ]; then
    fail "regression tests removed: ${MISSING[*]}" \
         "Each encodes a previously-exploitable bug. Deleting one removes" \
         "the only automated evidence the fix is still in place."
  else
    pass "all four exploit regression tests present"
  fi
fi

# ── GUARD 7: NEV-001 reminder (informational) ──────────────────────────
# Not a failure — the bug is known and tracked. This is here so nobody
# ships a release believing the gate is clear.

if [ -d "$NODE_SRC" ]; then
  if grep -rq 'fn in_block_double_spend_is_rejected\|fn block_double_spend' "$NODE_SRC"; then
    pass "NEV-001 double-spend rejection test present"
  else
    echo ""
    ylw "  ! NEV-001 STILL OPEN"
    echo "      validate_block_contents() does not re-check balance or nonce."
    echo "      An in-block double-spend mints from nothing. Not a CI failure"
    echo "      because it is tracked in README.md — but this workspace is"
    echo "      NOT cleared to hold real value until it is fixed and a"
    echo "      rejection test exists."
  fi
fi

# ── GUARD 8: Stripe webhooks are really verified ──────────────────────
# The billing webhook once returned `true` from its signature check, so
# anyone could POST checkout.session.completed and upgrade any account.
BILLING=crates/qlock-escrow/src/billing.rs
if [ -f "$BILLING" ]; then
  if grep -q 'Hmac::<Sha256>' "$BILLING" && grep -q 'ct_eq' "$BILLING" \
     && ! grep -qE '^\s*true\s*(//.*)?$' "$BILLING"; then
    pass "Stripe webhook signature is HMAC-verified in constant time"
  else
    fail "Stripe webhook verification missing or short-circuited" \
         "billing.rs must HMAC-SHA256 the signed payload and compare with ct_eq."
  fi
fi

# ── GUARD 9: no server-side key generation in production ──────────────
NODE_MAIN=crates/nev369-node/src/main.rs
if [ -f "$NODE_MAIN" ]; then
  if grep -A4 'async fn new_wallet' "$NODE_MAIN" | grep -q 'production()'; then
    pass "node /wallet/new is refused in production"
    if grep -A8 'async fn generate_quantum_key' crates/qlock-escrow/src/main.rs | grep -q '"production"'; then
      pass "escrow /quantum/keygen is refused in production"
    else
      fail "escrow /quantum/keygen is not gated on production"
    fi
  else
    fail "node /wallet/new is not gated on production" \
         "A key generated on a server is a key the operator could have kept."
  fi
fi

echo "  ─────────────────────────────────────────────────────────────"
if [ "$FAIL" -ne 0 ]; then
  echo ""
  red "  GUARDS FAILED — a previously-exploitable bug may have returned."
  echo "  Anything touching a signed payload needs a security review, not a"
  echo "  normal review. See Contributing in README.md."
  echo ""
  exit 1
fi
grn "  All guards passed."
echo ""
