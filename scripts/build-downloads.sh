#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Builds the public NEV369 download that the website points miners at:
#
#   curl -fsSL https://q-lock-ecosystem.com/downloads/install.sh | bash
#   nev369-mine
#
# Run on the server from the project folder (vps-setup.sh does it):
#   bash scripts/build-downloads.sh
#
# Writes apps/downloads/, which nginx serves at /downloads/:
#   nev369-linux-x86_64.tar.gz   node + godshield CLI + helper scripts + chain spec
#   install.sh                   installs into ~/.local, checks the checksum
#   SHA256SUMS
#
# The chain spec (pinned genesis) comes from chain-spec/nev369-mainnet.env,
# so every downloaded node joins THIS chain and refuses any other.
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail
cd "$(dirname "$0")/.."

DOMAIN="${QLOCK_DOMAIN:-q-lock-ecosystem.com}"
SPEC=chain-spec/nev369-mainnet.env
OUT=apps/downloads
PKG=nev369-linux-x86_64

[ -f "$SPEC" ] || { echo "$SPEC missing — cannot build downloads"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Building nev369-node and godshield (cached after the first time)..."
docker build -q -f docker/Dockerfile.downloads --target export \
    --output "type=local,dest=$WORK/bin" . >/dev/null

STAGE="$WORK/$PKG"
mkdir -p "$STAGE/bin" "$STAGE/share"
cp "$WORK/bin/nev369-node" "$WORK/bin/godshield" "$STAGE/bin/"
cp "$SPEC" "$STAGE/share/nev369-mainnet.env"

# ── nev369-mine: wallet on first run, then a mining node ────────────────
cat > "$STAGE/bin/nev369-mine" <<MINE
#!/usr/bin/env bash
# Mine NEV369 to your own wallet. First run creates the wallet.
set -euo pipefail
BIN="\$(dirname "\$(readlink -f "\$0")")"
SHARE="\$BIN/../share"
HOME_DIR="\${NEV369_HOME:-\$HOME/.nev369}"
mkdir -p "\$HOME_DIR/data"
WALLET="\$HOME_DIR/wallet.json"

if [ ! -f "\$WALLET" ]; then
    echo "No wallet yet — creating one. This is where your mining rewards go."
    "\$BIN/godshield" wallet new --output "\$WALLET" --label "NEV369 mining wallet"
fi
ADDR="\$(cat "\$HOME_DIR/wallet.address.txt")"

set -a; . "\$SHARE/nev369-mainnet.env"; set +a
export NEV369_ENV=production
export NEV369_DB_PATH="\$HOME_DIR/data/chain.db"
export NEV369_BIND_ADDR=127.0.0.1
export NEV369_BIND_PORT="\${NEV369_BIND_PORT:-8369}"
export NEV369_P2P_PORT="\${NEV369_P2P_PORT:-4001}"
export NEV369_BOOTSTRAP_PEERS="\${NEV369_BOOTSTRAP_PEERS:-/dns4/$DOMAIN/tcp/4001}"
export NEV369_ALLOWED_ORIGINS="http://127.0.0.1:\$NEV369_BIND_PORT"
export NEV369_MINING=1
export NEV369_MINER_ADDRESS="\$ADDR"
export RUST_LOG="\${RUST_LOG:-info}"

echo
echo "  Mining NEV369 to \${ADDR:0:16}…\${ADDR: -8}"
echo "  It syncs the chain first, then mines. Leave this open. Ctrl+C stops it."
echo "  Your wallet:  nev369-wallet      Explorer: https://$DOMAIN/explorer/"
echo
exec "\$BIN/nev369-node"
MINE

# ── nev369-wallet: the browser wallet on this machine ───────────────────
cat > "$STAGE/bin/nev369-wallet" <<WALLET
#!/usr/bin/env bash
# Open your NEV369 wallet in the browser. Uses your own node if it is
# running (nev369-mine), otherwise the public node.
set -euo pipefail
BIN="\$(dirname "\$(readlink -f "\$0")")"
HOME_DIR="\${NEV369_HOME:-\$HOME/.nev369}"
WALLET="\${1:-\$HOME_DIR/wallet.json}"
[ -f "\$WALLET" ] || { echo "No wallet at \$WALLET — run nev369-mine or: godshield wallet new --output \$WALLET"; exit 1; }
NODE="https://$DOMAIN/node"
curl -fsS -m 2 "http://127.0.0.1:\${NEV369_BIND_PORT:-8369}/health" >/dev/null 2>&1 \\
    && NODE="http://127.0.0.1:\${NEV369_BIND_PORT:-8369}"
shift || true
exec "\$BIN/godshield" wallet open --wallet "\$WALLET" --node "\$NODE" "\$@"
WALLET

cat > "$STAGE/README.txt" <<README
NEV369 — node, miner and wallet

  nev369-mine      create a wallet (first run) and mine to it
  nev369-wallet    open your wallet in the browser: balance, send, receive
  godshield        the full GodShield CLI (wallet new, send, balance, vault, scan ...)

Your wallet and chain data live in ~/.nev369/. Back up ~/.nev369/wallet.json
and remember its password — there is no recovery.

Explorer: https://$DOMAIN/explorer/
README

chmod 755 "$STAGE/bin/"*
mkdir -p "$OUT"
tar -C "$WORK" -czf "$WORK/$PKG.tar.gz" "$PKG"
mv "$WORK/$PKG.tar.gz" "$OUT/$PKG.tar.gz"

# ── install.sh ──────────────────────────────────────────────────────────
cat > "$OUT/install.sh" <<INSTALL
#!/usr/bin/env bash
# NEV369 installer — puts nev369-mine, nev369-wallet and godshield in
# ~/.local/bin. No sudo needed. Re-run to update.
set -euo pipefail
URL="https://$DOMAIN/downloads"
PKG="$PKG"

# Linux comes from this server; macOS from the GitHub release (built by CI).
RELEASES="https://github.com/ThearchitectQlock/qlock-ecosystem/releases/latest/download"
SUMS="\$URL/SHA256SUMS"
case "\$(uname -s)/\$(uname -m)" in
    Linux/x86_64)  ;;
    Darwin/arm64)  PKG=nev369-macos-arm64;  URL="\$RELEASES"; SUMS="\$RELEASES/SHA256SUMS" ;;
    Darwin/x86_64) PKG=nev369-macos-x86_64; URL="\$RELEASES"; SUMS="\$RELEASES/SHA256SUMS" ;;
    *)
        echo "No download for \$(uname -s) \$(uname -m) yet."
        echo "Windows: get nev369-windows-x86_64.zip from"
        echo "  https://github.com/ThearchitectQlock/qlock-ecosystem/releases/latest"
        exit 1 ;;
esac
command -v curl >/dev/null || { echo "Needs curl"; exit 1; }
if command -v sha256sum >/dev/null; then SHA="sha256sum -c --quiet -"; else SHA="shasum -a 256 -c --quiet -"; fi

TMP="\$(mktemp -d)"; trap 'rm -rf "\$TMP"' EXIT
echo "Downloading NEV369..."
curl -fsSL "\$URL/\$PKG.tar.gz" -o "\$TMP/\$PKG.tar.gz"
curl -fsSL "\$SUMS" -o "\$TMP/SHA256SUMS"
( cd "\$TMP" && grep " \$PKG.tar.gz\\\$" SHA256SUMS | \$SHA ) \\
    || { echo "Checksum mismatch — download corrupted. Nothing was installed."; exit 1; }

DEST="\$HOME/.local/share/nev369"
rm -rf "\$DEST"; mkdir -p "\$DEST" "\$HOME/.local/bin"
tar -xzf "\$TMP/\$PKG.tar.gz" -C "\$DEST" --strip-components=1
for b in nev369-mine nev369-wallet godshield nev369-node; do
    ln -sf "\$DEST/bin/\$b" "\$HOME/.local/bin/\$b"
done

if command -v ldd >/dev/null && ldd "\$DEST/bin/godshield" 2>/dev/null | grep -q "not found"; then
    echo "Missing system libraries. Run:  sudo apt install -y libssl3 ca-certificates"
fi

echo
echo "  ✓ Installed: nev369-mine, nev369-wallet, godshield"
case ":\$PATH:" in
    *":\$HOME/.local/bin:"*) echo "  Start mining:  nev369-mine" ;;
    *) echo "  Open a new terminal (or run: export PATH=\"\\\$HOME/.local/bin:\\\$PATH\"), then:  nev369-mine" ;;
esac
INSTALL
chmod 644 "$OUT/install.sh"

( cd "$OUT" && sha256sum "$PKG.tar.gz" install.sh > SHA256SUMS )
echo "Downloads ready in $OUT/: $(du -h "$OUT/$PKG.tar.gz" | cut -f1) package"
