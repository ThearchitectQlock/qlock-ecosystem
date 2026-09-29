# Mining NEV369 and using a wallet

Everything here runs on your own machine: Linux, macOS, WSL on Windows, or the
Linux container on a Chromebook. You need about 4 GB of free disk space for the
build and a few hundred MB for the chain.

Each block pays **369 NEV** to whoever mines it. The reward halves every 437,000
blocks. Your node mines to one address, which is your wallet.

---

## Quick start: two commands

On 64-bit Linux (a Linux PC, a Chromebook's Linux terminal, or Windows through
WSL: run `wsl --install` in PowerShell first), open a terminal and paste:

```bash
curl -fsSL https://q-lock-ecosystem.com/downloads/install.sh | bash
nev369-mine
```

The first run creates your wallet (choose a password of at least 10
characters), syncs the chain from the network, and starts mining to your
wallet. Open your wallet any time with `nev369-wallet`.

Your wallet and chain data live in `~/.nev369/`. **Back up
`~/.nev369/wallet.json` and remember the password. There is no recovery.**

### Windows

Download `nev369-windows-x86_64.zip` from the
[latest release](https://github.com/ThearchitectQlock/qlock-ecosystem/releases/latest),
unzip it anywhere, and double-click **START-MINING.cmd**. The first run creates
your wallet. Open it any time with **OPEN-WALLET.cmd**. Your wallet and chain
live in `%USERPROFILE%\.nev369\`.

The files aren't code-signed yet, so Windows may show *"Windows protected your
PC"*: click **More info → Run anyway**. Allow network access when the firewall
asks; miners connect to each other on port 4001.

### macOS

The same two commands as Linux work on Apple Silicon and Intel Macs:

```bash
curl -fsSL https://q-lock-ecosystem.com/downloads/install.sh | bash
nev369-mine
```

If `nev369-mine` isn't found afterwards, run `export PATH="$HOME/.local/bin:$PATH"`
(add that line to `~/.zshrc` to keep it).

Every download is listed in the release with its SHA-256 checksum.

The rest of this guide covers building from source, which gives you more control.

---

## 1. Install from source

```bash
# Rust (skip if `cargo --version` already works)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build tools (Debian / Ubuntu / Chromebook Linux)
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git

# The code
git clone https://github.com/ThearchitectQlock/qlock-ecosystem.git
cd qlock-ecosystem

# The wallet tool and the node
cargo install --path crates/godshield-cli
cargo build --release -p nev369-node
```

`rust-toolchain.toml` pins the Rust version, so rustup fetches the right
compiler on the first build. The first build takes a while.

---

## 2. Create your wallet

```bash
godshield wallet new
```

You choose a password (at least 10 characters) and get two files:

| File | What it is |
|---|---|
| `nev369_wallet.json` | Your key, encrypted with your password. **Back this up.** |
| `nev369_wallet.address.txt` | Your address. It's public, so share it to receive NEV. |

The key is encrypted with Argon2id and AES-256-GCM. Nobody can open the file
without the password, including you if you forget it. **There is no recovery.**
Keep a copy of the wallet file on a USB stick or in a second place, and keep the
password somewhere you won't lose it.

A NEV369 address is a Dilithium5 public key written as hex: 5,184 characters.
It's long because post-quantum keys are long. Always copy and paste it, and
never retype it.

---

## 3. Join the network

Every node on the network has to start from the same genesis block. The values
that pin it are published in [`chain-spec/nev369-mainnet.env`](../chain-spec/).

```bash
cp .env.example .env
cat chain-spec/nev369-mainnet.env >> .env
```

Then edit `.env` and set:

```bash
NEV369_MINING=1
NEV369_MINER_ADDRESS=<paste the contents of nev369_wallet.address.txt>
NEV369_BOOTSTRAP_PEERS=/dns4/q-lock-ecosystem.com/tcp/4001
```

`NEV369_BOOTSTRAP_PEERS` points at the public node, which you connect to first to
download the chain. After that, your node finds other peers itself.

If your node reports **GENESIS MISMATCH**, the chain-spec lines in `.env` don't
match the network's. Copy them again exactly as published. Your node refuses to
start rather than quietly founding a separate chain.

---

## 4. Start mining

```bash
set -a; source .env; set +a
./target/release/nev369-node
```

After syncing, the log shows `mining` lines with your hash rate every 30
seconds, and a line for each block you win. To stop, press Ctrl+C. The chain is
saved in `./data/` and picks up where it left off next time.

To keep it running after you close the terminal:

```bash
nohup ./target/release/nev369-node > node.log 2>&1 &
tail -f node.log
```

---

## 5. Check, send and receive

**In your browser (easiest):**

```bash
godshield wallet open --wallet nev369_wallet.json
```

This prints a link and opens it in your browser. The page shows your balance and
has three tabs:

- **Send:** paste the recipient's address, enter the amount, review, then enter
  your password to sign.
- **Receive:** your address, with Copy and Download buttons.
- **History:** every transaction in and out, with confirmations.

The page is served by `godshield` on your own machine (127.0.0.1). Your key never
leaves your computer. It's decrypted only for the moment it signs a transaction,
then wiped from memory. Keep the terminal open while you use the page, and press
Ctrl+C to close the wallet.

On a **Chromebook**, if the link doesn't open, start the wallet with
`--bind 0.0.0.0` and open the `penguin.linux.test` link it prints instead.

If your node isn't running, point the wallet at the public one:

```bash
godshield wallet open --wallet nev369_wallet.json --node https://q-lock-ecosystem.com/node
```

**From the terminal:**

```bash
godshield balance --wallet nev369_wallet.json
godshield send --wallet nev369_wallet.json --to <address> --amount 25
```

**On the explorer:** paste any address, block number or transaction hash into
[q-lock-ecosystem.com/explorer](https://q-lock-ecosystem.com/explorer/) to see its
balance and full transaction history.

### How sending works

- Amounts have 8 decimal places. The fee is optional, and miners include
  higher-fee transactions first.
- Each address can have **one transaction waiting** at a time. Once it's in a
  block (about a minute), you can send the next. The wallet tells you if one is
  still pending.
- A transaction is final once it's in a block. Check it on the explorer: the
  wallet links straight to it.
- Memos are public. Don't put anything private in them.

### Mining rewards

- The mining reward pays to `NEV369_MINER_ADDRESS`. Open that wallet to see it
  arrive.
- Blocks come roughly every 60 seconds across the whole network. The more miners
  there are, the smaller your share of those blocks, which is how the reward
  stays fair.
