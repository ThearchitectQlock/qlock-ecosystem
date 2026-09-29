#!/usr/bin/env bash
# Package a built miner for one platform into dist/.
#   scripts/package-release.sh <rust-target> <package-name>
# Called by .github/workflows/release.yml after `cargo build --release`.
set -euo pipefail
TARGET="$1"; NAME="$2"
cd "$(dirname "$0")/.."
DOMAIN="${QLOCK_DOMAIN:-q-lock-ecosystem.com}"
SRC="target/$TARGET/release"
STAGE="dist-stage/$NAME"
rm -rf dist-stage dist; mkdir -p "$STAGE/bin" "$STAGE/share" dist
cp chain-spec/nev369-mainnet.env "$STAGE/share/"

crlf() { sed 's/$/\r/' ; }   # Windows scripts get CRLF line endings

case "$TARGET" in
*windows*)
    cp "$SRC/nev369-node.exe" "$SRC/godshield.exe" "$STAGE/bin/"

    crlf > "$STAGE/nev369-mine.ps1" <<PS1
# Mine NEV369 to your own wallet. The first run creates the wallet.
\$ErrorActionPreference = 'Stop'
\$Here = Split-Path -Parent \$MyInvocation.MyCommand.Path
\$Bin = Join-Path \$Here 'bin'
\$HomeDir = if (\$env:NEV369_HOME) { \$env:NEV369_HOME } else { Join-Path \$env:USERPROFILE '.nev369' }
New-Item -ItemType Directory -Force -Path (Join-Path \$HomeDir 'data') | Out-Null
\$Wallet = Join-Path \$HomeDir 'wallet.json'
if (-not (Test-Path \$Wallet)) {
    Write-Host 'No wallet yet - creating one. This is where your mining rewards go.'
    & (Join-Path \$Bin 'godshield.exe') wallet new --output \$Wallet --label 'NEV369 mining wallet'
    if (\$LASTEXITCODE -ne 0) { exit 1 }
}
\$Addr = (Get-Content (Join-Path \$HomeDir 'wallet.address.txt') -Raw).Trim()
foreach (\$line in Get-Content (Join-Path \$Here 'share\nev369-mainnet.env')) {
    if (\$line -match '^(NEV369_[A-Z_]+)=(.+)\$') { Set-Item -Path ("Env:" + \$Matches[1]) -Value \$Matches[2] }
}
\$env:NEV369_ENV = 'production'
\$env:NEV369_DB_PATH = Join-Path \$HomeDir 'data\chain.db'
\$env:NEV369_BIND_ADDR = '127.0.0.1'
if (-not \$env:NEV369_BIND_PORT) { \$env:NEV369_BIND_PORT = '8369' }
if (-not \$env:NEV369_P2P_PORT) { \$env:NEV369_P2P_PORT = '4001' }
if (-not \$env:NEV369_BOOTSTRAP_PEERS) { \$env:NEV369_BOOTSTRAP_PEERS = '/dns4/$DOMAIN/tcp/4001' }
\$env:NEV369_ALLOWED_ORIGINS = "http://127.0.0.1:\$(\$env:NEV369_BIND_PORT)"
\$env:NEV369_MINING = '1'
\$env:NEV369_MINER_ADDRESS = \$Addr
if (-not \$env:RUST_LOG) { \$env:RUST_LOG = 'info' }
Write-Host ''
Write-Host ("  Mining NEV369 to " + \$Addr.Substring(0,16) + '...' + \$Addr.Substring(\$Addr.Length-8))
Write-Host '  It syncs the chain first, then mines. Leave this window open; close it to stop.'
Write-Host '  Your wallet: double-click OPEN-WALLET.cmd    Explorer: https://$DOMAIN/explorer/'
Write-Host ''
& (Join-Path \$Bin 'nev369-node.exe')
PS1

    crlf > "$STAGE/nev369-wallet.ps1" <<PS1
# Open your NEV369 wallet in the browser: balance, send, receive.
\$ErrorActionPreference = 'Stop'
\$Here = Split-Path -Parent \$MyInvocation.MyCommand.Path
\$HomeDir = if (\$env:NEV369_HOME) { \$env:NEV369_HOME } else { Join-Path \$env:USERPROFILE '.nev369' }
\$Wallet = Join-Path \$HomeDir 'wallet.json'
if (-not (Test-Path \$Wallet)) { Write-Host 'No wallet yet - run START-MINING.cmd first.'; exit 1 }
\$Node = 'https://$DOMAIN/node'
try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8369/health' | Out-Null; \$Node = 'http://127.0.0.1:8369' } catch {}
& (Join-Path \$Here 'bin\godshield.exe') wallet open --wallet \$Wallet --node \$Node
PS1

    printf '@echo off\r\ntitle NEV369 miner\r\npowershell -NoProfile -ExecutionPolicy Bypass -File "%%~dp0nev369-mine.ps1"\r\necho.\r\npause\r\n' > "$STAGE/START-MINING.cmd"
    printf '@echo off\r\ntitle NEV369 wallet\r\npowershell -NoProfile -ExecutionPolicy Bypass -File "%%~dp0nev369-wallet.ps1"\r\necho.\r\npause\r\n' > "$STAGE/OPEN-WALLET.cmd"

    crlf > "$STAGE/README.txt" <<TXT
NEV369 miner for Windows

  START-MINING.cmd   creates your wallet (first run) and mines to it
  OPEN-WALLET.cmd    your wallet in the browser: balance, send, receive

First run: Windows may say "Windows protected your PC" because these files
aren't code-signed yet. Click "More info", then "Run anyway". When the
firewall asks, allow access: miners talk to each other on port 4001.

Your wallet and chain data live in %USERPROFILE%\.nev369\
Back up wallet.json and remember the password. There is no recovery.

Explorer: https://$DOMAIN/explorer/
TXT
    ( cd dist-stage && 7z a -tzip -bso0 "../dist/$NAME.zip" "$NAME" )
    ;;
*)
    cp "$SRC/nev369-node" "$SRC/godshield" "$STAGE/bin/"
    # Portable across Linux and macOS: no `readlink -f` (older macOS lacks it).
    cat > "$STAGE/bin/nev369-mine" <<SH
#!/usr/bin/env bash
# Mine NEV369 to your own wallet. The first run creates the wallet.
set -euo pipefail
SELF="\$0"
while [ -L "\$SELF" ]; do L="\$(readlink "\$SELF")"; case "\$L" in /*) SELF="\$L";; *) SELF="\$(dirname "\$SELF")/\$L";; esac; done
BIN="\$(cd "\$(dirname "\$SELF")" && pwd)"; SHARE="\$BIN/../share"
HOME_DIR="\${NEV369_HOME:-\$HOME/.nev369}"
mkdir -p "\$HOME_DIR/data"
WALLET="\$HOME_DIR/wallet.json"
if [ ! -f "\$WALLET" ]; then
    echo "No wallet yet — creating one. This is where your mining rewards go."
    "\$BIN/godshield" wallet new --output "\$WALLET" --label "NEV369 mining wallet"
fi
ADDR="\$(tr -d ' \r\n' < "\$HOME_DIR/wallet.address.txt")"
set -a; . "\$SHARE/nev369-mainnet.env"; set +a
export NEV369_ENV=production NEV369_DB_PATH="\$HOME_DIR/data/chain.db" NEV369_BIND_ADDR=127.0.0.1
export NEV369_BIND_PORT="\${NEV369_BIND_PORT:-8369}" NEV369_P2P_PORT="\${NEV369_P2P_PORT:-4001}"
export NEV369_BOOTSTRAP_PEERS="\${NEV369_BOOTSTRAP_PEERS:-/dns4/$DOMAIN/tcp/4001}"
export NEV369_ALLOWED_ORIGINS="http://127.0.0.1:\$NEV369_BIND_PORT" NEV369_MINING=1 NEV369_MINER_ADDRESS="\$ADDR"
export RUST_LOG="\${RUST_LOG:-info}"
echo
echo "  Mining NEV369 to \${ADDR:0:16}…\${ADDR: -8}"
echo "  It syncs the chain first, then mines. Leave this open. Ctrl+C stops it."
echo "  Your wallet:  nev369-wallet      Explorer: https://$DOMAIN/explorer/"
echo
exec "\$BIN/nev369-node"
SH
    cat > "$STAGE/bin/nev369-wallet" <<SH
#!/usr/bin/env bash
# Open your NEV369 wallet in the browser. Uses your own node if running.
set -euo pipefail
SELF="\$0"
while [ -L "\$SELF" ]; do L="\$(readlink "\$SELF")"; case "\$L" in /*) SELF="\$L";; *) SELF="\$(dirname "\$SELF")/\$L";; esac; done
BIN="\$(cd "\$(dirname "\$SELF")" && pwd)"
HOME_DIR="\${NEV369_HOME:-\$HOME/.nev369}"
WALLET="\${1:-\$HOME_DIR/wallet.json}"
[ -f "\$WALLET" ] || { echo "No wallet at \$WALLET — run nev369-mine first."; exit 1; }
NODE="https://$DOMAIN/node"
curl -fsS -m 2 "http://127.0.0.1:\${NEV369_BIND_PORT:-8369}/health" >/dev/null 2>&1 && NODE="http://127.0.0.1:\${NEV369_BIND_PORT:-8369}"
shift || true
exec "\$BIN/godshield" wallet open --wallet "\$WALLET" --node "\$NODE" "\$@"
SH
    chmod 755 "$STAGE/bin/"*
    cat > "$STAGE/README.txt" <<TXT
NEV369: node, miner and wallet

  nev369-mine      create a wallet (first run) and mine to it
  nev369-wallet    your wallet in the browser: balance, send, receive
  godshield        the full GodShield CLI

Easiest install:  curl -fsSL https://$DOMAIN/downloads/install.sh | bash
Your wallet and chain data live in ~/.nev369/. Back up ~/.nev369/wallet.json
and remember its password. There is no recovery.

Explorer: https://$DOMAIN/explorer/
TXT
    tar -C dist-stage -czf "dist/$NAME.tar.gz" "$NAME"
    ;;
esac
rm -rf dist-stage
ls -la dist
