// crates/godshield-cli/src/wallet.rs
//
// ═══════════════════════════════════════════════════════════════════════
// godshield wallet — everyday NEV369 wallets
//
//   godshield wallet new                         create nev369_wallet.json
//   godshield wallet open --wallet nev369_wallet.json
//   godshield wallet open --vault architect_vault.json
//   godshield wallet address --wallet nev369_wallet.json
//
// `new` makes a single password-sealed key (keyfile.rs) — the right tool
// for miners and anyone receiving NEV. Keys that must survive their owner
// belong in a Shamir vault (`godshield vault create`), and `open --vault`
// works with those too, asking for the share files at send time.
//
// `open` starts the local browser wallet (webwallet.rs).
// ═══════════════════════════════════════════════════════════════════════

use crate::keyfile::{WalletFile, MIN_PASSWORD_LEN};
use crate::send::short;
use crate::webwallet::{self, KeySource, WalletServer};
use anyhow::{anyhow, bail, Context};
use clap::{Args, Subcommand};
use colored::Colorize;
use godshield_core::GodKeyPair;
use nevaeh_vault::{SecretKind, TimeLockedVault};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Create a new NEV369 wallet: one key, sealed with your password
    New(NewArgs),
    /// Open the wallet in your browser — balance, send, receive, history (runs on this machine)
    Open(OpenArgs),
    /// Print a wallet's NEV369 address (the whole thing, for sharing)
    Address(AddressArgs),
}

#[derive(Args)]
pub struct NewArgs {
    /// Where to write the wallet file. Never overwrites an existing file.
    #[arg(long, default_value = "nev369_wallet.json")]
    output: PathBuf,
    /// A name for this wallet, shown when it is opened.
    #[arg(long, default_value = "My NEV369 wallet")]
    label: String,
}

#[derive(Args)]
pub struct OpenArgs {
    /// Password-sealed wallet file.
    #[arg(long, conflicts_with = "vault")]
    wallet: Option<PathBuf>,
    /// Or a Shamir vault (share files are chosen in the browser when sending).
    #[arg(long)]
    vault: Option<PathBuf>,
    /// NEV369 node HTTP API.
    #[arg(long, default_value = "http://localhost:8080")]
    node: String,
    /// Explorer used for "view transaction" links.
    #[arg(long, default_value = "https://q-lock-ecosystem.com/explorer/")]
    explorer: String,
    /// Local port for the wallet page.
    #[arg(long, default_value_t = 7369)]
    port: u16,
    /// Interface to listen on. Keep the default unless the browser cannot
    /// reach 127.0.0.1 (then `--bind 0.0.0.0` on a ChromeOS Linux container
    /// also prints a penguin.linux.test link).
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    /// Print the link without opening a browser.
    #[arg(long)]
    no_browser: bool,
}

#[derive(Args)]
pub struct AddressArgs {
    #[arg(long, conflicts_with = "vault")]
    wallet: Option<PathBuf>,
    #[arg(long)]
    vault: Option<PathBuf>,
}

pub fn run(cmd: WalletCommand) -> anyhow::Result<()> {
    match cmd {
        WalletCommand::New(a) => new(a),
        WalletCommand::Open(a) => open(a),
        WalletCommand::Address(a) => address(a),
    }
}

fn new(args: NewArgs) -> anyhow::Result<()> {
    if args.output.exists() {
        bail!(
            "{} already exists. Choose another --output — never overwrite a wallet file.",
            args.output.display()
        );
    }
    println!();
    println!("    {}", "NEW NEV369 WALLET".bold());
    println!("    Your key is sealed with a password (at least {MIN_PASSWORD_LEN} characters).");
    println!(
        "    {}",
        "There is no recovery: lose the file or the password and the NEV is gone.".yellow()
    );
    println!();

    let password = Zeroizing::new(rpassword::prompt_password("    Choose a password: ")?);
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("password must be at least {MIN_PASSWORD_LEN} characters — nothing was created");
    }
    let again = Zeroizing::new(rpassword::prompt_password("    Type it again:     ")?);
    if *password != *again {
        bail!("the passwords do not match — nothing was created");
    }

    println!("    Generating a Dilithium5 key and sealing it...");
    let kp = GodKeyPair::generate().map_err(|e| anyhow!("key generation: {e}"))?;
    let wallet = WalletFile::seal(&kp, &password, &args.label)?;
    drop(kp);
    // Prove the file opens before anyone sends NEV to it.
    wallet
        .open(&password)
        .context("self-test failed — nothing was written")?;
    wallet.save_new(&args.output)?;

    let address_file = args.output.with_extension("address.txt");
    fs::write(&address_file, format!("{}\n", wallet.address))?;

    println!();
    println!("    {} Wallet created and verified.", "✓".green().bold());
    println!("    Wallet file:   {}", args.output.display());
    println!("    Address:       {}", short(&wallet.address));
    println!(
        "    Full address:  {}  (public — share it to receive NEV)",
        address_file.display()
    );
    println!();
    println!("    {}", "Next".bold());
    println!(
        "      Open it:     godshield wallet open --wallet {}",
        args.output.display()
    );
    println!("      Mine to it:  put the full address in .env as NEV369_MINER_ADDRESS");
    println!(
        "      Back it up:  copy {} somewhere safe, and remember the password.",
        args.output.display()
    );
    println!();
    Ok(())
}

fn load_source(
    wallet: &Option<PathBuf>,
    vault: &Option<PathBuf>,
) -> anyhow::Result<(KeySource, String, String)> {
    match (wallet, vault) {
        (Some(p), _) => {
            let w = WalletFile::load(p)?;
            let (address, label) = (w.address.clone(), w.label.clone());
            Ok((KeySource::Wallet(w), address, label))
        }
        (None, Some(p)) => {
            let v = TimeLockedVault::from_json(&fs::read_to_string(p)?)?;
            if v.secret_kind != SecretKind::Dilithium5 {
                bail!(
                    "this vault holds {}, not a NEV369 key",
                    v.secret_kind.describe()
                );
            }
            let (address, label) = (v.public_identifier.clone(), v.label.clone());
            Ok((KeySource::Vault(v), address, label))
        }
        (None, None) => bail!("give --wallet <file> or --vault <file>"),
    }
}

fn open(args: OpenArgs) -> anyhow::Result<()> {
    let (source, address, label) = load_source(&args.wallet, &args.vault)?;
    let server = WalletServer::new(
        source,
        address,
        label.clone(),
        args.node.clone(),
        args.explorer,
        args.bind,
        args.port,
    );
    let url = server.url();

    println!();
    println!("    {} {}", "NEV369 WALLET".bold(), label);
    println!("    Node:  {}", args.node);
    println!();
    println!("    Open this link in your browser:");
    println!("    {}", url.bold());
    if let Some(alt) = server.chromeos_url() {
        println!("    On a Chromebook, if that one does not load:");
        println!("    {alt}");
    }
    println!();
    println!("    The link contains a one-time secret for this session — don't share it.");
    println!("    Keep this terminal open while you use the wallet. Ctrl+C closes it.");
    if server.exposed_beyond_this_machine() {
        println!(
            "    {}",
            "Listening beyond 127.0.0.1: only do this on a network you trust.".yellow()
        );
    }
    println!();

    if !args.no_browser {
        webwallet::open_browser(&url);
    }
    server.run()
}

fn address(args: AddressArgs) -> anyhow::Result<()> {
    let (_, address, _) = load_source(&args.wallet, &args.vault)?;
    println!("{address}");
    Ok(())
}
