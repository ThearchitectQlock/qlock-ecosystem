#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Q-Lock — first-time setup of a fresh Ubuntu 24.04 server
#
# Run ON THE SERVER, as root, from the project folder that
# scripts/push-to-vps.sh copied there:
#
#   sudo -i            (skip if you logged in as root)
#   cd /opt/qlock && bash scripts/vps-setup.sh
#
# Before running it, the domain's DNS A records (@ and www) must point
# at this server, or the certificate step fails.
#
# What it does, in order. Each step is safe to re-run:
#   1. Updates the system; installs Docker, certbot, ufw, fail2ban and
#      automatic security updates.
#   2. Firewall: allows only SSH, 80, 443 and the NEV369 P2P ports.
#   3. Writes .env the first time, with fresh random secrets, production
#      mode for the node, and the pinned genesis from chain-spec/.
#   4. Gets a Let's Encrypt certificate for the domain and www, and sets
#      up automatic renewal.
#   5. Builds and starts the stack with docker-compose.vps.yml, so only
#      nginx and P2P face the internet.
#   6. Checks that the site, explorer and node answer.
#
# The node starts with mining OFF. It syncs the existing chain from your
# own node first; the script prints how to turn mining on after that.
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

DOMAIN="q-lock-ecosystem.com"
TREASURY="rdyZMSbKDPwsa75JiWbNnjYyNBr7BhaE2"
COMPOSE=(docker compose --profile godshield -f docker-compose.yml -f docker-compose.vps.yml)

cd "$(dirname "$0")/.."
PROJECT="$(pwd)"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31m✗ %s\033[0m\n' "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (you are $(whoami))."
[ -f docker-compose.yml ] && [ -f docker-compose.vps.yml ] || die "Run from the project folder."
grep -qE 'VERSION_ID="(24|26)\.04"' /etc/os-release || warn "Written for Ubuntu 24.04 / 26.04 — carrying on."

# ── Preflight: things only you can provide ────────────────────────────

SPEC=chain-spec/nev369-mainnet.env
if [ ! -f .env ]; then
    [ -f "$SPEC" ] || die "$SPEC is missing. On your own machine, with your node running:
    scripts/export-chain-spec.sh
then push the project again (scripts/push-to-vps.sh)."
    for k in NEV369_GENESIS_TIMESTAMP NEV369_GENESIS_HASH NEV369_ARCHITECT_ADDRESS NEV369_NEVAEH_VAULT_ADDRESS; do
        grep -qE "^$k=.+" "$SPEC" || die "$SPEC has no value for $k. Re-run scripts/export-chain-spec.sh."
    done
fi

SERVER_IP="$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)"
DNS_IP="$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)"
if [ -n "$SERVER_IP" ] && [ "$DNS_IP" != "$SERVER_IP" ]; then
    die "$DOMAIN points at '${DNS_IP:-nothing}', but this server is $SERVER_IP.
In Cloudflare DNS, set A records for @ and www to $SERVER_IP, proxy status
'DNS only' (grey cloud). Wait a minute, then run this again."
fi
ok "$DOMAIN points at this server ($SERVER_IP)"

EMAIL="${LETSENCRYPT_EMAIL:-}"
if [ -z "$EMAIL" ] && [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    read -r -p "  Email for Let's Encrypt expiry notices: " EMAIL
    [ -n "$EMAIL" ] || die "An email is needed for the certificate."
fi

# ── 1. System packages ────────────────────────────────────────────────

bold "1/6  System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq ca-certificates curl git ufw fail2ban unattended-upgrades certbot python3 >/dev/null
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
systemctl enable --now fail2ban >/dev/null 2>&1 || true
ok "updated; ufw, fail2ban, certbot, automatic security updates"

if ! command -v docker >/dev/null 2>&1; then
    # Docker's own packages first; Ubuntu's if Docker has none for this
    # release yet (a brand-new Ubuntu can be ahead of Docker's repo).
    if ! curl -fsSL https://get.docker.com | sh >/dev/null 2>&1; then
        warn "get.docker.com had no packages for this release — using Ubuntu's"
        apt-get install -y -qq docker.io docker-compose-v2 docker-buildx >/dev/null \
            || apt-get install -y -qq docker.io docker-compose-v2 >/dev/null
    fi
fi
systemctl enable --now docker >/dev/null
docker compose version >/dev/null || die "docker compose is not available."
# docker-compose.vps.yml uses `!override`, added in Compose 2.24.4.
CV="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
if [ "$(printf '%s\n' 2.24.4 "$CV" | sort -V | head -1)" != 2.24.4 ]; then
    die "Docker Compose $CV is too old (need 2.24.4+). Remove it and re-run: apt-get remove -y docker-compose-v2"
fi
ok "$(docker --version | cut -d, -f1); $(docker compose version --short 2>/dev/null | sed 's/^/compose /')"

# ── 2. Firewall ───────────────────────────────────────────────────────

bold "2/6  Firewall"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 4001/tcp comment 'NEV369 P2P node-1' >/dev/null
ufw allow 4002/tcp comment 'NEV369 P2P node-2' >/dev/null
ufw --force enable >/dev/null
ok "open: SSH, 80, 443, 4001, 4002 — everything else closed"
ok "Docker-published ports are limited by docker-compose.vps.yml"

# ── 3. .env ───────────────────────────────────────────────────────────

bold "3/6  Configuration (.env)"
if [ -f .env ]; then
    ok ".env already exists — left unchanged"
else
    cp .env.example .env
    chmod 600 .env
    GRAFANA_PW="$(openssl rand -hex 12)"
    python3 - "$SPEC" "$DOMAIN" "$TREASURY" "$GRAFANA_PW" <<'PY'
import re, secrets, sys
spec_path, domain, treasury, grafana_pw = sys.argv[1:5]
env = open('.env').read()

def put(key, value):
    global env
    line = f'{key}={value}'
    if re.search(rf'^{key}=.*$', env, re.M):
        env = re.sub(rf'^{key}=.*$', lambda _: line, env, count=1, flags=re.M)
    else:
        env = env.rstrip('\n') + '\n' + line + '\n'

db_pw, redis_pw = secrets.token_hex(24), secrets.token_hex(24)
put('DB_PASSWORD', db_pw)
put('REDIS_PASSWORD', redis_pw)
put('DATABASE_URL', f'postgresql://qlock:{db_pw}@postgres:5432/qlock')
put('JWT_SECRET', secrets.token_hex(32))
put('GRAFANA_PASSWORD', grafana_pw)
put('GODSHIELD_ADMIN_TOKEN', secrets.token_hex(32))
put('QLOCK_TREASURY_ADDRESS', treasury)
put('FRONTEND_ORIGIN', f'https://{domain}')
put('RELAYER_ALLOWED_ORIGINS', f'https://{domain}')
put('GODSHIELD_ALLOWED_ORIGIN', f'https://{domain}')

# The node: production mode, pinned genesis, mining off until synced.
put('NEV369_ENV', 'production')
put('NEV369_ALLOWED_ORIGINS', f'https://{domain}')
put('NEV369_MINING', '0')
put('NEV369_HTTP_MINING', '0')
for line in open(spec_path):
    m = re.match(r'^(NEV369_[A-Z_]+)=(.+)$', line.strip())
    if m:
        put(m.group(1), m.group(2))

open('.env', 'w').write(env)
PY
    ok ".env written with fresh secrets (readable by root only)"
    ok "node: production, pinned genesis, mining off"
    ok "treasury: $TREASURY"
    echo "  Grafana login (keep it in your password manager): admin / $GRAFANA_PW"
fi

# Escrow attestation identity. With it, the escrow runs in production
# mode; without it, it runs with a temporary identity and says so.
if [ -f qlock_attestation.json ]; then
    python3 - <<'PY'
import json, re
key = json.dumps(json.load(open('qlock_attestation.json')), separators=(',', ':'))
env = open('.env').read()
for k, v in (('QLOCK_ATTESTATION_KEY', key), ('QLOCK_ENV', 'production')):
    line = f'{k}={v}'
    if re.search(rf'^{k}=.*$', env, re.M):
        env = re.sub(rf'^{k}=.*$', lambda _: line, env, count=1, flags=re.M)
    else:
        env = env.rstrip('\n') + '\n' + line + '\n'
open('.env', 'w').write(env)
PY
    shred -u qlock_attestation.json 2>/dev/null || rm -f qlock_attestation.json
    ok "attestation key moved into .env and the file destroyed; escrow in production mode"
elif grep -qE '^QLOCK_ATTESTATION_KEY=.+' .env; then
    ok "attestation key already in .env"
else
    warn "no attestation key yet — escrow runs in development mode (temporary identity)"
fi

# GodShield gateway operational key: enables the gateway's attestation
# endpoint (/api/v1/gateway/sign). Same one-way handling as above.
if [ -f godshield_gateway.json ]; then
    python3 - <<'PY'
import json, re
key = json.dumps(json.load(open('godshield_gateway.json')), separators=(',', ':'))
env = open('.env').read()
line = f'GODSHIELD_GATEWAY_KEY={key}'
if re.search(r'^GODSHIELD_GATEWAY_KEY=.*$', env, re.M):
    env = re.sub(r'^GODSHIELD_GATEWAY_KEY=.*$', lambda _: line, env, count=1, flags=re.M)
else:
    env = env.rstrip('\n') + '\n' + line + '\n'
open('.env', 'w').write(env)
PY
    shred -u godshield_gateway.json 2>/dev/null || rm -f godshield_gateway.json
    ok "GodShield gateway key moved into .env and the file destroyed"
elif grep -qE '^GODSHIELD_GATEWAY_KEY=.+' .env; then
    ok "GodShield gateway key already in .env"
else
    warn "no GodShield gateway key — the gateway runs without its signing endpoint"
fi

# ── 4. TLS certificate ────────────────────────────────────────────────

bold "4/6  HTTPS certificate"
mkdir -p nginx/certs nginx/certbot
if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    # Standalone needs port 80 free: stop nginx if a previous run started it.
    docker stop qlock-nginx >/dev/null 2>&1 || true
    certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" \
        -d "$DOMAIN" -d "www.$DOMAIN"
fi

# Every renewal copies the new certificate to nginx and reloads it.
HOOK=/etc/letsencrypt/renewal-hooks/deploy/qlock-nginx.sh
cat > "$HOOK" <<HOOK
#!/bin/sh
cp -L /etc/letsencrypt/live/$DOMAIN/fullchain.pem $PROJECT/nginx/certs/fullchain.pem
cp -L /etc/letsencrypt/live/$DOMAIN/privkey.pem   $PROJECT/nginx/certs/privkey.pem
chmod 600 $PROJECT/nginx/certs/privkey.pem
docker exec qlock-nginx nginx -s reload >/dev/null 2>&1 || true
HOOK
chmod 755 "$HOOK"
sh "$HOOK"
ok "certificate for $DOMAIN and www.$DOMAIN installed"

# ── 5. Build and start ────────────────────────────────────────────────

bold "5/6  Building and starting (the first build takes 10–20 minutes)"
"${COMPOSE[@]}" up -d --build
# nginx.conf is bind-mounted as a single file. rsync replaces files by
# rename, so a running nginx keeps reading the old copy: recreate it so
# a pushed config always takes effect. (A second or two of downtime.)
"${COMPOSE[@]}" up -d --force-recreate --no-deps nginx >/dev/null
# One public node (see docker-compose.vps.yml): retire the test node-2.
docker rm -f nev369-node-2 >/dev/null 2>&1 || true
ok "stack started"

# Renewals from now on go through nginx (webroot), with no downtime.
if certbot reconfigure --cert-name "$DOMAIN" --webroot -w "$PROJECT/nginx/certbot" \
       --non-interactive >/dev/null 2>&1; then
    ok "automatic renewal: webroot through nginx (tested)"
else
    certbot reconfigure --cert-name "$DOMAIN" --non-interactive \
        --pre-hook "docker stop qlock-nginx" --post-hook "docker start qlock-nginx" >/dev/null 2>&1 || true
    warn "automatic renewal: standalone, with nginx paused for a few seconds each time"
fi

# Public miner download (node + wallet), served at /downloads/.
if bash scripts/build-downloads.sh; then
    ok "miner download built — https://$DOMAIN/downloads/install.sh"
else
    warn "miner download failed to build (the site still works) — see output above"
fi

# ── 6. Checks ─────────────────────────────────────────────────────────

bold "6/6  Checks"
check() {
    local name="$1" url="$2"
    for _ in $(seq 1 30); do
        if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then ok "$name  $url"; return 0; fi
        sleep 5
    done
    warn "$name did not answer: $url   (logs: ${COMPOSE[*]} logs --tail 50)"
}
check "website " "https://$DOMAIN/"
check "explorer" "https://$DOMAIN/explorer/"
check "node    " "https://$DOMAIN/node/info"
check "godshield" "https://$DOMAIN/godshield/health"
check "download " "https://$DOMAIN/downloads/install.sh"

HEIGHT="$(curl -fsS --max-time 5 "https://$DOMAIN/node/info" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("height","?"))' 2>/dev/null || echo '?')"

bold "Live."
cat <<EOF
  Website   https://$DOMAIN
  Explorer  https://$DOMAIN/explorer/
  Node API  https://$DOMAIN/node/info      (height now: $HEIGHT)
  GodShield https://$DOMAIN/godshield/health

  Next, on YOUR machine: add this line to .env and restart your node, so
  this server syncs the chain from it:
      NEV369_BOOTSTRAP_PEERS=/dns4/$DOMAIN/tcp/4001

  When the explorer's height matches your node, turn mining on here.
  The reward address comes from a wallet's .address.txt file (public;
  push-to-vps.sh sends it, the wallet file itself stays with you):
      A=\$(cat nev369_wallet.address.txt)
      sed -i "s|^NEV369_MINING=.*|NEV369_MINING=1|; s|^NEV369_MINER_ADDRESS=.*|NEV369_MINER_ADDRESS=\$A|" .env
      ${COMPOSE[*]} up -d nev369-node-1

  Useful:
      ${COMPOSE[*]} ps
      ${COMPOSE[*]} logs -f nev369-node-1
      ssh -L 3001:127.0.0.1:3001 <login>@${SERVER_IP:-<server>}   then open http://localhost:3001 (Grafana)
EOF
