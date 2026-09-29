#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Connect Stripe: paid plans for GodShield + escrow.
#
# Run ON THE SERVER as root (or from your machine with
#   ssh -t ubuntu@<server> "sudo bash /opt/qlock/scripts/stripe-setup.sh"):
#
# Asks for your Stripe keys privately (nothing is echoed or saved in shell
# history), checks each looks right, writes them to .env and restarts the
# escrow service. Blank answers keep the current value. Safe to re-run —
# e.g. to switch from test keys to live keys.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }
[ -f .env ] || { echo "No .env — run scripts/vps-setup.sh first."; exit 1; }

current() { { grep -E "^$1=" .env || true; } | head -1 | cut -d= -f2- ; }
ask() {  # ask VAR "prompt" prefix secret
    local var="$1" prompt="$2" prefix="$3" secret="${4:-}" val cur
    cur="$(current "$var")"
    while true; do
        if [ -n "$secret" ]; then
            read -r -s -p "  $prompt${cur:+ [keep current]}: " val; echo
        else
            read -r -p "  $prompt${cur:+ [$cur]}: " val
        fi
        [ -z "$val" ] && { val="$cur"; break; }
        if [ -z "$prefix" ] || [[ "$val" == $prefix* ]]; then break; fi
        echo "    That doesn't start with '$prefix' — check you copied the right value."
    done
    printf -v "$var" '%s' "$val"
}

echo
echo "Stripe setup. Test keys (sk_test_…) first is a good idea; re-run with live keys after."
echo
ask STRIPE_SECRET_KEY            "Secret key (sk_test_… or sk_live_…)"        "sk_"     secret
ask STRIPE_WEBHOOK_SECRET        "Webhook signing secret (whsec_…)"           "whsec_"  secret
ask STRIPE_PRICE_PRO             "Pro price ID (price_…)"                     "price_"
ask STRIPE_PRICE_LABEL_PRO       "Pro price as shown on the site, e.g. £29/month" ""
ask STRIPE_PRICE_ENTERPRISE      "Enterprise price ID (price_…, blank = 'Contact us')" "price_"
ask STRIPE_PRICE_LABEL_ENTERPRISE "Enterprise price as shown, e.g. £299/month" ""

python3 - <<PY
import re
env = open('.env').read()
vals = {
  'STRIPE_SECRET_KEY': '''$STRIPE_SECRET_KEY''',
  'STRIPE_WEBHOOK_SECRET': '''$STRIPE_WEBHOOK_SECRET''',
  'STRIPE_PRICE_PRO': '''$STRIPE_PRICE_PRO''',
  'STRIPE_PRICE_LABEL_PRO': '''$STRIPE_PRICE_LABEL_PRO''',
  'STRIPE_PRICE_ENTERPRISE': '''$STRIPE_PRICE_ENTERPRISE''',
  'STRIPE_PRICE_LABEL_ENTERPRISE': '''$STRIPE_PRICE_LABEL_ENTERPRISE''',
}
for k, v in vals.items():
    line = f'{k}={v}'
    if re.search(rf'^{k}=.*$', env, re.M):
        env = re.sub(rf'^{k}=.*$', lambda _: line, env, count=1, flags=re.M)
    else:
        env = env.rstrip('\n') + '\n' + line + '\n'
open('.env', 'w').write(env)
PY
chmod 600 .env

docker compose --profile godshield -f docker-compose.yml -f docker-compose.vps.yml up -d escrow >/dev/null
sleep 6
echo
MODE=test; [[ "$STRIPE_SECRET_KEY" == sk_live_* ]] && MODE=LIVE
echo "  ✓ Stripe connected ($MODE mode). Escrow restarted."
curl -fsS https://q-lock-ecosystem.com/api/billing/plans 2>/dev/null \
  | python3 -c 'import json,sys
for p in json.load(sys.stdin)["plans"]:
    print("    %-10s %-14s checkout: %s" % (p["name"], p["price"] or "-", "on" if p["checkout"] else "off"))' 2>/dev/null || true
echo
echo "  Webhook endpoint in Stripe must be:  https://q-lock-ecosystem.com/billing/webhook"
