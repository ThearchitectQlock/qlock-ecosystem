#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Q-Lock deployment
#
# Extends the earlier script (local | single) with `nodes` and
# `production`. The production path has a hard gate in front of it,
# because the repo is not cleared to hold real value: NEV-001 is open
# and there has been no third-party audit. A deploy script that will
# happily push this to mainnet is a liability, so this one asks.
#
#   ./deploy.sh local        full stack: escrow + 2 nodes + edge + metrics
#   ./deploy.sh nodes        just the two NEV369 nodes (P2P testing)
#   ./deploy.sh single       one node, quick smoke test
#   ./deploy.sh escrow       escrow backend + postgres + redis only
#   ./deploy.sh production   gated — reads the readiness gate at you
#   ./deploy.sh status       health of everything running
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

MODE="${1:-}"
COMPOSE="docker compose"

c_red()  { printf '\033[31m%s\033[0m\n' "$*"; }
c_grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
c_bld()  { printf '\033[1m%s\033[0m\n'  "$*"; }

require_env() {
    if [ ! -f .env ]; then
        c_red "No .env found."
        echo "  cp .env.example .env    then fill in DATABASE_URL and JWT_SECRET"
        exit 1
    fi
    if grep -qE '^JWT_SECRET=\s*$' .env; then
        c_red "JWT_SECRET is empty in .env."
        echo "  Generate one:  openssl rand -hex 32"
        exit 1
    fi
    if grep -q '^QLOCK_ATTESTATION_VAULT=..*' .env; then
        c_red "QLOCK_ATTESTATION_VAULT is set."
        echo "  The escrow backend panics on purpose when it sees this."
        echo "  A vault that unlocks itself unattended is not a vault."
        echo "  Recover with 'godshield vault recover' and inject the key"
        echo "  through your secrets manager instead."
        exit 1
    fi
}

wait_healthy() {
    local svc="$1" tries="${2:-30}"
    printf '  waiting for %s' "$svc"
    for _ in $(seq 1 "$tries"); do
        local st
        st=$($COMPOSE ps --format json "$svc" 2>/dev/null \
             | grep -oE '"Health":"[a-z]*"' | head -1 | cut -d'"' -f4 || true)
        case "$st" in
            healthy) printf ' ✓\n'; return 0 ;;
            unhealthy) printf ' ✗\n'; c_red "  $svc is unhealthy"; \
                       $COMPOSE logs --tail=30 "$svc"; return 1 ;;
        esac
        printf '.'; sleep 2
    done
    printf ' timeout\n'
    $COMPOSE logs --tail=30 "$svc"
    return 1
}

case "$MODE" in

  local)
    echo ""
    c_bld "  ⛓  NEV369 + Q-Lock — full local stack"
    echo ""
    require_env
    $COMPOSE build
    $COMPOSE up -d
    echo ""
    wait_healthy postgres || true
    wait_healthy escrow || true
    wait_healthy nev369-node-1 || true
    echo ""
    c_grn "  Stack up."
    echo ""
    echo "    escrow API      http://localhost:3000/health"
    echo "    nev369 node-1   http://localhost:8080/health"
    echo "    nev369 node-2   http://localhost:8081/health"
    echo "    prometheus      http://localhost:9090"
    echo "    grafana         http://localhost:3001"
    echo ""
    echo "    Watch the nodes gossip:"
    echo "      docker compose logs -f nev369-node-1 nev369-node-2"
    echo ""
    c_ylw "    Two nodes is the point. A single node exercises none of the"
    c_ylw "    fork resolution, reorg or orphan-buffer code."
    echo ""
    ;;

  nodes)
    echo ""
    c_bld "  ⛓  NEV369 — two-node network only"
    echo ""
    require_env
    $COMPOSE build nev369-node-1
    $COMPOSE up -d nev369-node-1 nev369-node-2
    wait_healthy nev369-node-1 || true
    echo ""
    c_grn "  node-1 :8080   node-2 :8081"
    echo ""
    echo "  To force a reorg and watch it heal, mine on both nodes while"
    echo "  they are partitioned, then reconnect:"
    echo "    docker network disconnect qlock_qlock-net nev369-node-2"
    echo "    # mine on both"
    echo "    docker network connect qlock_qlock-net nev369-node-2"
    echo ""
    c_ylw "  Check balances on both nodes afterwards. A reorg that leaves"
    c_ylw "  balances subtly wrong is the failure mode to look for, and it"
    c_ylw "  does not announce itself."
    echo ""
    ;;

  single)
    echo ""
    c_bld "  ⛓  NEV369 — single node smoke test"
    echo ""
    require_env
    docker build -f docker/Dockerfile.nev369 -t nev369-node:local .
    docker run -d \
      --name nev369-node \
      --env-file .env \
      -p 8080:8080 -p 4001:4001 \
      -v nev369_data_single:/home/nev369/data \
      nev369-node:local
    c_grn "  Node running on :8080"
    c_ylw "  Smoke test only. Proves the binary starts and genesis builds."
    c_ylw "  Proves nothing about consensus."
    echo ""
    ;;

  escrow)
    echo ""
    c_bld "  ⛓  Q-Lock Escrow — backend only"
    echo ""
    require_env
    $COMPOSE build escrow
    $COMPOSE up -d postgres redis escrow
    wait_healthy postgres || true
    wait_healthy escrow || true
    c_grn "  Escrow API on :3000"
    echo ""
    ;;

  production)
    echo ""
    c_red "  ┌──────────────────────────────────────────────────────────┐"
    c_red "  │  PRODUCTION DEPLOY — READINESS GATE                      │"
    c_red "  └──────────────────────────────────────────────────────────┘"
    echo ""
    echo "  This repository is not cleared to hold real value."
    echo ""
    c_bld "  Open blockers:"
    echo ""
    echo "    NEV-001  validate_block_contents() does not re-check balance"
    echo "             or nonce. Two transactions from the same sender at"
    echo "             the same nonce both pass, the second subtracts from"
    echo "             an already-zero balance via saturating_sub, and the"
    echo "             recipient is still credited in full."
    echo "             Net effect: unbounded minting from nothing."
    echo ""
    echo "    NEV-003  The workspace has never been compiled."
    echo ""
    echo "    NEV-007  MAX_SUPPLY says 369,369,369 NEV. The emission"
    echo "             schedule terminates near 67.9M, which makes the"
    echo "             premine 69% of real supply rather than the ~12.7%"
    echo "             it appears to be. Disclosure problem before a sale."
    echo ""
    echo "    AUDIT    No independent third-party review of the core or"
    echo "             either integration."
    echo ""
    echo "  Full list: README.md → Production readiness gate"
    echo ""
    c_bld "  If every box on that gate is genuinely ticked, this script is"
    c_bld "  not the right tool anyway. Production deploys should go"
    c_bld "  through the GHCR images CI publishes, pinned by SHA, applied"
    c_bld "  by your orchestrator — not by a bash script on a laptop."
    echo ""
    read -r -p "  Type the exact phrase 'the gate is clear' to continue: " CONFIRM
    if [ "$CONFIRM" != "the gate is clear" ]; then
        echo ""
        c_grn "  Stopping. Correct call."
        echo ""
        exit 0
    fi
    echo ""
    c_ylw "  Proceeding is on you. Deploy the SHA-pinned GHCR images:"
    echo ""
    echo "    ghcr.io/<owner>/qlock-escrow:<sha>"
    echo "    ghcr.io/<owner>/nev369-node:<sha>"
    echo ""
    echo "  with QLOCK_ENV=production, a persistent attestation identity"
    echo "  injected from your secrets manager, and real vault-ceremony"
    echo "  premine addresses. The node refuses to boot on placeholders,"
    echo "  and the escrow backend panics without an attestation identity."
    echo "  Both of those are working as intended."
    echo ""
    ;;

  status)
    echo ""
    $COMPOSE ps
    echo ""
    for ep in "escrow  http://localhost:3000/health" \
              "node-1  http://localhost:8080/health" \
              "node-2  http://localhost:8081/health"; do
        name="${ep%% *}"; url="${ep##* }"
        if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
            c_grn "  ✓ $name"
        else
            c_red "  ✗ $name  ($url)"
        fi
    done
    echo ""
    ;;

  *)
    echo ""
    c_bld "  Q-Lock deployment"
    echo ""
    echo "    ./deploy.sh local        full stack — escrow, 2 nodes, edge, metrics"
    echo "    ./deploy.sh nodes        two NEV369 nodes only — P2P and reorg testing"
    echo "    ./deploy.sh single       one node — smoke test"
    echo "    ./deploy.sh escrow       escrow + postgres + redis"
    echo "    ./deploy.sh production   gated, and it will argue with you"
    echo "    ./deploy.sh status       health of what is running"
    echo ""
    exit 1
    ;;
esac
