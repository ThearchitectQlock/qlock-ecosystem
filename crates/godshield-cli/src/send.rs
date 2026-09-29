// crates/godshield-cli/src/send.rs
//
// ═══════════════════════════════════════════════════════════════════════
// godshield send / balance — spend and inspect NEV369
//
//   godshield send --wallet nev369_wallet.json --to <address> --amount 25
//   godshield send --vault architect_vault.json \
//       --share share_1.json --share share_2.json --to <address> --amount 250000
//
// The key is unlocked IN MEMORY — from a password-sealed wallet file, or
// from vault shares — used to sign one transaction, and dropped. It is
// never written to disk. `--key` accepts a plaintext keypair file, for
// development keys only.
//
// The transaction is shown in full and must be confirmed by typing the
// amount before it is signed. The bytes signed are exactly nev369-node's
// Transaction::signing_bytes(): CanonicalMessage under `nev369.tx.v1` over
// sender, recipient, amount, fee, crown_tax, nonce, memo. A test pins it.
//
// Offline signing: `--offline --nonce N` signs without contacting a node
// and prints the transaction JSON, to POST to /tx/submit elsewhere.
//
// The building blocks below (account lookup, signing, submission, amount
// parsing) are shared with the browser wallet in webwallet.rs, so the two
// cannot drift apart.
// ═══════════════════════════════════════════════════════════════════════

use crate::keyfile::WalletFile;
use anyhow::{anyhow, bail, Context};
use colored::Colorize;
use godshield_core::{CanonicalMessage, GodKeyPair, GodShield, TripleHash};
use nevaeh_vault::{SecretKind, TimeLockedVault, VaultShare};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

pub const UNITS_PER_NEV: u64 = 100_000_000;
pub const ADDRESS_HEX_LEN: usize = 5184;
pub const MAX_MEMO_LEN: usize = 256;

#[derive(clap::Args)]
pub struct SendArgs {
    /// Password-sealed wallet file (from `godshield wallet new`).
    #[arg(long, conflicts_with_all = ["vault", "key"])]
    wallet: Option<PathBuf>,

    /// Vault file holding the sending key (e.g. architect_vault.json).
    #[arg(long, conflicts_with = "key")]
    vault: Option<PathBuf>,

    /// Share files — at least the vault's threshold (2 for the Architect).
    #[arg(long = "share")]
    shares: Vec<PathBuf>,

    /// Plaintext keypair JSON instead (development keys only).
    #[arg(long)]
    key: Option<PathBuf>,

    /// Recipient NEV369 address (a hex Dilithium5 public key).
    #[arg(long)]
    to: String,

    /// Amount in NEV, as a decimal: 250000 or 1.5 (up to 8 places).
    #[arg(long)]
    amount: String,

    /// Fee in NEV. Miners take the highest-fee transactions first.
    #[arg(long, default_value = "0")]
    fee: String,

    /// Optional memo, signed with the transaction.
    #[arg(long, default_value = "")]
    memo: String,

    /// Node HTTP API.
    #[arg(long, default_value = "http://localhost:8080")]
    node: String,

    /// Sign without contacting a node; prints the transaction JSON.
    #[arg(long, requires = "nonce")]
    offline: bool,

    /// Nonce to use (required with --offline; otherwise read from the node).
    #[arg(long)]
    nonce: Option<u64>,

    /// Skip the confirmation prompt.
    #[arg(long)]
    yes: bool,
}

// ── Shared building blocks ───────────────────────────────────────────────

/// What the node reports for one address.
pub struct Account {
    pub balance: u64,
    pub pending_outgoing: u64,
    pub nonce: u64,
    pub timelocked: bool,
}

pub fn fetch_account(node: &str, address: &str) -> anyhow::Result<Account> {
    let base = node.trim_end_matches('/');
    let info = get_json(&format!("{base}/balance/{address}"))
        .with_context(|| format!("could not reach the node at {base}"))?;
    Ok(Account {
        balance: info["balance_units"].as_u64().unwrap_or(0),
        pending_outgoing: info["pending_outgoing_units"].as_u64().unwrap_or(0),
        nonce: info["nonce"].as_u64().unwrap_or(0),
        timelocked: info["timelocked"].as_bool() == Some(true),
    })
}

/// A transfer before signing. Amounts are base units.
pub struct Transfer {
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub memo: String,
}

impl Transfer {
    pub fn validate(&self, sender: &str) -> anyhow::Result<()> {
        if !is_hex_address(&self.to) {
            bail!(
                "the recipient must be a NEV369 address: the {ADDRESS_HEX_LEN}-character hex \
                 public key shown by `godshield wallet address` or the wallet's Receive tab"
            );
        }
        if self.to == sender {
            bail!("the recipient is the sending address");
        }
        if self.amount == 0 {
            bail!("amount must be greater than zero");
        }
        if self.memo.chars().count() > MAX_MEMO_LEN {
            bail!("memo is longer than {MAX_MEMO_LEN} characters");
        }
        Ok(())
    }

    /// Check against the node's view of the sender before signing.
    pub fn check_against(&self, account: &Account) -> anyhow::Result<()> {
        if account.timelocked {
            bail!("this address is time-locked — the node refuses to spend from it");
        }
        if account.pending_outgoing > 0 {
            bail!(
                "you already have a transaction waiting for the next block — \
                 send this one once it confirms"
            );
        }
        let need = self
            .amount
            .checked_add(self.fee)
            .ok_or_else(|| anyhow!("amount + fee overflows"))?;
        if account.balance < need {
            bail!(
                "insufficient balance: have {} NEV, need {} NEV",
                fmt_nev(account.balance),
                fmt_nev(need)
            );
        }
        Ok(())
    }
}

/// Sign `transfer` at `nonce`. Returns the transaction JSON the node's
/// /tx/submit expects, and its hash.
pub fn sign_transfer(
    kp: &GodKeyPair,
    transfer: &Transfer,
    nonce: u64,
) -> anyhow::Result<(serde_json::Value, String)> {
    let sender = hex::encode(&kp.public_key);
    let crown_tax = 0u64;
    let message = signing_bytes(
        &sender,
        &transfer.to,
        transfer.amount,
        transfer.fee,
        crown_tax,
        nonce,
        &transfer.memo,
    );
    let sig = GodShield::sign(kp, &message)?;
    let tx = serde_json::json!({
        "sender": sender,
        "recipient": transfer.to,
        "amount": transfer.amount,
        "fee": transfer.fee,
        "crown_tax": crown_tax,
        "nonce": nonce,
        "timestamp": chrono::Utc::now().timestamp().max(0) as u64,
        "public_key_hex": sender,
        "signature_hex": hex::encode(&sig.signature),
        "payload_memo": transfer.memo,
    });
    Ok((tx, TripleHash::hash_hex(&message)))
}

/// POST a signed transaction. Returns the node's transaction hash.
pub fn submit(node: &str, tx: &serde_json::Value) -> anyhow::Result<String> {
    let base = node.trim_end_matches('/');
    let resp = post_json(&format!("{base}/tx/submit"), tx)
        .with_context(|| format!("could not reach the node at {base}"))?;
    if resp["accepted"].as_bool() == Some(true) {
        Ok(resp["tx_hash"].as_str().unwrap_or_default().to_string())
    } else {
        let why = resp["error"].as_str().unwrap_or("unknown error");
        if why.to_ascii_lowercase().contains("pending") {
            bail!(
                "the node refused it: {why} — you already have a transaction waiting; \
                 send this one after the next block"
            );
        }
        bail!("the node refused it: {why}")
    }
}

/// Unlock a Dilithium5 key from a vault and its shares. Respects the
/// vault's time-lock: Nevaeh's vault refuses until 2039.
pub fn unlock_vault(vault: &TimeLockedVault, shares: &[VaultShare]) -> anyhow::Result<GodKeyPair> {
    if vault.secret_kind != SecretKind::Dilithium5 {
        bail!(
            "this vault holds {}, not a NEV369 key",
            vault.secret_kind.describe()
        );
    }
    if shares.len() < vault.shares_required as usize {
        bail!(
            "this vault needs {} shares; {} given",
            vault.shares_required,
            shares.len()
        );
    }
    Ok(vault.recover_godkeypair(shares)?)
}

// ── godshield send ───────────────────────────────────────────────────────

pub fn run(args: SendArgs) -> anyhow::Result<()> {
    let transfer = Transfer {
        to: args.to.trim().to_string(),
        amount: parse_nev(&args.amount).context("--amount")?,
        fee: parse_nev_allow_zero(&args.fee).context("--fee")?,
        memo: args.memo.clone(),
    };

    let kp = load_key(&args)?;
    let sender = hex::encode(&kp.public_key);
    transfer.validate(&sender)?;

    let base = args.node.trim_end_matches('/').to_string();
    let (nonce, balance) = if args.offline {
        (
            args.nonce.expect("clap enforces --nonce with --offline"),
            None,
        )
    } else {
        let account = fetch_account(&base, &sender)?;
        transfer.check_against(&account)?;
        (args.nonce.unwrap_or(account.nonce), Some(account.balance))
    };

    // ── Show exactly what will be signed ──
    println!();
    println!("    {}", "NEV369 TRANSACTION".bold());
    println!("    From:     {}", short(&sender));
    println!("    To:       {}", short(&transfer.to));
    println!("    Amount:   {} NEV", fmt_nev(transfer.amount).bold());
    println!("    Fee:      {} NEV", fmt_nev(transfer.fee));
    println!("    Nonce:    {nonce}");
    if !transfer.memo.is_empty() {
        println!("    Memo:     {}", transfer.memo);
    }
    if let Some(bal) = balance {
        println!(
            "    Balance:  {} NEV → {} NEV",
            fmt_nev(bal),
            fmt_nev(bal - transfer.amount - transfer.fee)
        );
    }
    println!();

    if !args.yes {
        print!(
            "    Type the amount ({}) to sign and send: ",
            args.amount.trim()
        );
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim() != args.amount.trim() {
            bail!("not confirmed — nothing was signed");
        }
    }

    let (tx, tx_hash) = sign_transfer(&kp, &transfer, nonce)?;
    drop(kp);

    if args.offline {
        println!(
            "    {} Signed offline. Transaction hash:",
            "✓".green().bold()
        );
        println!("    {tx_hash}");
        println!();
        println!("{}", serde_json::to_string_pretty(&tx)?);
        println!();
        println!("    Submit it from a connected machine:");
        println!(
            "      curl -X POST {base}/tx/submit -H 'Content-Type: application/json' -d @tx.json"
        );
        return Ok(());
    }

    let accepted = submit(&base, &tx)?;
    let shown = if accepted.is_empty() {
        tx_hash
    } else {
        accepted
    };
    println!(
        "    {} Accepted by the node and broadcast to peers.",
        "✓".green().bold()
    );
    println!("    Transaction: {shown}");
    println!("    It confirms when the next block is mined — check {base}/tx/<hash>");
    Ok(())
}

// ── godshield balance ────────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct BalanceArgs {
    /// Wallet file — reads its public address; no password needed.
    #[arg(long, conflicts_with_all = ["vault", "address"])]
    wallet: Option<PathBuf>,
    /// Vault file — reads its public address; no shares needed.
    #[arg(long, conflicts_with = "address")]
    vault: Option<PathBuf>,
    /// Or a NEV369 address directly.
    #[arg(long)]
    address: Option<String>,
    #[arg(long, default_value = "http://localhost:8080")]
    node: String,
}

pub fn balance(args: BalanceArgs) -> anyhow::Result<()> {
    let (address, label) = match (&args.wallet, &args.vault, &args.address) {
        (Some(p), _, _) => {
            let w = WalletFile::load(p)?;
            (w.address.clone(), w.label.clone())
        }
        (None, Some(p), _) => {
            let v = TimeLockedVault::from_json(&fs::read_to_string(p)?)?;
            if v.secret_kind != SecretKind::Dilithium5 {
                bail!(
                    "this vault holds {}, not a NEV369 key",
                    v.secret_kind.describe()
                );
            }
            (v.public_identifier.clone(), v.label.clone())
        }
        (None, None, Some(a)) => (a.trim().to_string(), String::from("address")),
        (None, None, None) => bail!("give --wallet, --vault or --address"),
    };
    let account = fetch_account(&args.node, &address)?;
    println!();
    println!("    {}", label.bold());
    println!("    Address:  {}", short(&address));
    println!("    Balance:  {} NEV", fmt_nev(account.balance).bold());
    if account.pending_outgoing > 0 {
        println!(
            "    Pending:  {} NEV outgoing",
            fmt_nev(account.pending_outgoing)
        );
    }
    println!("    Nonce:    {}", account.nonce);
    if account.timelocked {
        println!("    Status:   {}", "time-locked".purple());
    } else {
        println!("    Status:   {}", "spendable".green());
    }
    println!();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════

fn load_key(args: &SendArgs) -> anyhow::Result<GodKeyPair> {
    if let Some(path) = &args.wallet {
        let w = WalletFile::load(path)?;
        let pw = zeroize::Zeroizing::new(rpassword::prompt_password(format!(
            "    Password for \"{}\": ",
            w.label
        ))?);
        let kp = w.open(&pw)?;
        println!(
            "    {} Wallet unlocked in memory — the key is not written anywhere.",
            "✓".green()
        );
        return Ok(kp);
    }
    if let Some(path) = &args.key {
        return GodKeyPair::from_json(&fs::read_to_string(path)?)
            .map_err(|e| anyhow!("{}: {e}", path.display()));
    }
    let vault_path = args
        .vault
        .as_ref()
        .ok_or_else(|| anyhow!("give --wallet, or --vault with --share files, or --key"))?;
    let vault = TimeLockedVault::from_json(&fs::read_to_string(vault_path)?)?;
    let mut shares = Vec::new();
    for p in &args.shares {
        shares.push(VaultShare::from_json(&fs::read_to_string(p)?)?);
    }
    let kp = unlock_vault(&vault, &shares)?;
    println!(
        "    {} Key unlocked in memory from {} shares — not written to disk.",
        "✓".green(),
        shares.len()
    );
    Ok(kp)
}

/// Must match nev369-node's Transaction::signing_bytes() byte for byte.
pub fn signing_bytes(
    sender: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    crown_tax: u64,
    nonce: u64,
    memo: &str,
) -> Vec<u8> {
    CanonicalMessage::encode(
        "nev369.tx.v1",
        &[
            sender.as_bytes(),
            recipient.as_bytes(),
            &amount.to_le_bytes(),
            &fee.to_le_bytes(),
            &crown_tax.to_le_bytes(),
            &nonce.to_le_bytes(),
            memo.as_bytes(),
        ],
    )
}

pub fn parse_nev_allow_zero(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() {
        bail!("empty amount");
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        bail!("'{s}' is not a plain decimal number of NEV");
    }
    if frac.len() > 8 {
        bail!("NEV has 8 decimal places; '{s}' has {}", frac.len());
    }
    let w: u64 = if whole.is_empty() { 0 } else { whole.parse()? };
    let f: u64 = format!("{frac:0<8}").parse()?;
    w.checked_mul(UNITS_PER_NEV)
        .and_then(|w| w.checked_add(f))
        .ok_or_else(|| anyhow!("'{s}' is too large"))
}

pub fn parse_nev(s: &str) -> anyhow::Result<u64> {
    let v = parse_nev_allow_zero(s)?;
    if v == 0 {
        bail!("amount must be greater than zero");
    }
    Ok(v)
}

pub fn fmt_nev(units: u64) -> String {
    let frac = format!("{:08}", units % UNITS_PER_NEV);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{}", units / UNITS_PER_NEV)
    } else {
        format!("{}.{frac}", units / UNITS_PER_NEV)
    }
}

pub fn is_hex_address(s: &str) -> bool {
    s.len() == ADDRESS_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// First 16 and last 8 characters of a long address.
pub fn short(address: &str) -> String {
    if address.len() <= 28 {
        return address.to_string();
    }
    format!("{}…{}", &address[..16], &address[address.len() - 8..])
}

pub fn get_json(url: &str) -> anyhow::Result<serde_json::Value> {
    let r = reqwest::blocking::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(15))
        .send()?;
    Ok(r.json()?)
}

fn post_json(url: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let r = reqwest::blocking::Client::new()
        .post(url)
        .timeout(std::time::Duration::from_secs(30))
        .json(body)
        .send()?;
    Ok(r.json()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nev_amounts_are_exact() {
        assert_eq!(parse_nev("10000000").unwrap(), 1_000_000_000_000_000);
        assert_eq!(parse_nev("1.5").unwrap(), 150_000_000);
        assert_eq!(parse_nev("0.00000001").unwrap(), 1);
        assert!(parse_nev("0").is_err());
        assert!(parse_nev("1.000000001").is_err());
        assert!(parse_nev("-1").is_err());
        assert_eq!(fmt_nev(150_000_000), "1.5");
        assert_eq!(fmt_nev(1_000_000_000_000_000), "10000000");
    }

    #[test]
    fn signed_bytes_match_the_node_layout() {
        // Same construction as nev369-node Transaction::signing_bytes().
        let ours = signing_bytes("aa", "bb", 5, 1, 0, 7, "m");
        let node = CanonicalMessage::encode(
            "nev369.tx.v1",
            &[
                b"aa".as_slice(),
                b"bb",
                &5u64.to_le_bytes(),
                &1u64.to_le_bytes(),
                &0u64.to_le_bytes(),
                &7u64.to_le_bytes(),
                b"m",
            ],
        );
        assert_eq!(ours, node);
    }

    #[test]
    fn a_signed_transfer_verifies_and_hashes_like_the_node() {
        let kp = GodKeyPair::generate().unwrap();
        let t = Transfer {
            to: "b".repeat(ADDRESS_HEX_LEN),
            amount: 5,
            fee: 0,
            memo: String::new(),
        };
        let (tx, hash) = sign_transfer(&kp, &t, 3).unwrap();
        let sender = hex::encode(&kp.public_key);
        let msg = signing_bytes(&sender, &t.to, 5, 0, 0, 3, "");
        assert_eq!(hash, TripleHash::hash_hex(&msg));
        let sig = godshield_core::GodSignature {
            signature: hex::decode(tx["signature_hex"].as_str().unwrap()).unwrap(),
            ..GodShield::sign(&kp, &msg).unwrap()
        };
        assert!(GodShield::verify(&kp.export_public(), &sig, &msg).unwrap());
    }

    #[test]
    fn transfers_are_checked_before_signing() {
        let me = "a".repeat(ADDRESS_HEX_LEN);
        let ok = Transfer {
            to: "b".repeat(ADDRESS_HEX_LEN),
            amount: 10,
            fee: 1,
            memo: String::new(),
        };
        assert!(ok.validate(&me).is_ok());
        let to_self = Transfer {
            to: me.clone(),
            amount: 10,
            fee: 0,
            memo: String::new(),
        };
        assert!(to_self.validate(&me).is_err());
        let rich = Account {
            balance: 100,
            pending_outgoing: 0,
            nonce: 0,
            timelocked: false,
        };
        assert!(ok.check_against(&rich).is_ok());
        let poor = Account { balance: 5, ..rich };
        assert!(ok.check_against(&poor).is_err());
        let locked = Account {
            timelocked: true,
            balance: 100,
            pending_outgoing: 0,
            nonce: 0,
        };
        assert!(ok.check_against(&locked).is_err());
        let busy = Account {
            pending_outgoing: 1,
            balance: 100,
            nonce: 0,
            timelocked: false,
        };
        assert!(ok.check_against(&busy).is_err());
    }

    #[test]
    fn addresses_must_be_full_public_keys() {
        assert!(is_hex_address(&"a".repeat(ADDRESS_HEX_LEN)));
        assert!(!is_hex_address(&"a".repeat(64)));
        assert!(!is_hex_address(&"z".repeat(ADDRESS_HEX_LEN)));
    }
}
