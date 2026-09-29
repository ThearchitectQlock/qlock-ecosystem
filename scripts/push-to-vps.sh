#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Copy the project to the server, without any secrets.
#
# Run on YOUR machine, from anywhere inside the project:
#
#   scripts/push-to-vps.sh <server-ip>              logs in as root
#   scripts/push-to-vps.sh ubuntu@<server-ip>       OVH and others: a sudo user
#
# Then on the server:  cd /opt/qlock && sudo bash scripts/vps-setup.sh
#
# Safe to run again after every update: it sends only what changed.
#
# Never sent: vault and share files, wallet files, .env, keys and
# certificates, chain data, build output, patch backups. The server gets
# its own .env from vps-setup.sh. Excluded files already on the server
# (its .env, certificates, chain data) are left alone.
#
# The one secret that IS sent, if you created it: qlock_attestation.json,
# the escrow's signing identity. vps-setup.sh moves it into the server's
# .env and destroys the file there.
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

TARGET="${1:-}"
[ -n "$TARGET" ] || { echo "usage: scripts/push-to-vps.sh [user@]<server-ip>"; exit 1; }
case "$TARGET" in
    *@*) LOGIN="$TARGET" ;;
    *)   LOGIN="root@$TARGET" ;;
esac
# A non-root login (OVH's `ubuntu`) gets /opt/qlock handed to it once,
# through sudo, and then copies files as itself.
USER_PART="${LOGIN%%@*}"
if [ "$USER_PART" = root ]; then SUDO=""; else SUDO="sudo"; fi
DEST=/opt/qlock

cd "$(dirname "$0")/.."

if ! command -v rsync >/dev/null 2>&1; then
    echo "Installing rsync..."
    sudo apt-get install -y -qq rsync
fi

if [ ! -f chain-spec/nev369-mainnet.env ]; then
    echo "chain-spec/nev369-mainnet.env is missing — the server needs it to join YOUR chain."
    echo "With your node running:  scripts/export-chain-spec.sh"
    exit 1
fi

if [ ! -f Cargo.lock ]; then
    echo "Cargo.lock is missing. Run  cargo build  once first; the server's build needs it."
    exit 1
fi

echo "Preparing $LOGIN (it may ask for the password, and once more for sudo)..."
ssh -t -o StrictHostKeyChecking=accept-new "$LOGIN" \
    "command -v rsync >/dev/null || ($SUDO apt-get update -qq && $SUDO apt-get install -y -qq rsync >/dev/null); \
     $SUDO mkdir -p $DEST && $SUDO chown $USER_PART: $DEST"

echo "Sending the project..."
rsync -az --delete --human-readable --info=stats1 \
    --include='.env.example' \
    --exclude='.env' --exclude='.env.*' \
    --exclude='.git/' \
    --exclude='target/' --exclude='**/target/' \
    --exclude='node_modules/' --exclude='**/node_modules/' \
    --exclude='data/' --exclude='*.db' \
    --exclude='.backup-*/' \
    --exclude='*_shares/' --exclude='*share_*.json' --exclude='share_*.json' \
    --exclude='*_vault.json' \
    --exclude='nev369_wallet*.json' --exclude='*wallet*.json' \
    --exclude='keys.json' --exclude='*.key' --exclude='*.seed' --exclude='secrets/' \
    --exclude='*.pem' --exclude='nginx/certs/*.pem' --exclude='nginx/certbot/' \
    --exclude='apps/downloads/' \
    --exclude='*.log' --exclude='*.zip' --exclude='*_patch.sh' \
    ./ "$LOGIN:$DEST/"

echo
echo "Done. Now on the server:"
echo "  ssh $LOGIN"
echo "  cd $DEST && sudo bash scripts/vps-setup.sh"
for k in qlock_attestation.json godshield_gateway.json; do
    if [ -f "$k" ]; then
        echo
        echo "$k was sent. Once vps-setup.sh has run, delete your copy here:"
        echo "  shred -u $k"
    fi
done
