// crates/godshield- cli/src/main.rs
//
// GodShield command-line interface.
//
// The vault subcommands are the ones that matter most — they run the key
// ceremony for the Architect wallet and Nevaeh's inheritance. See
// docs/nevaeh-vault- ceremony.md before running them.

mod keyfile;
mod send;
mod vault;
mod wallet;
mod webwallet;

use clap::{Parser, Subcommand};
use colored::Colorize;
use godshield_adapters::{AdapterRegistry, MigrationHelper};
use godshield_core::{GodKeyPair, GodPublicKey, GodShield, GodSignature, TripleHash};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "godshield",
    version,
    about = "GodShield — post-quantum cryptography for distributed ledgers",
    long_about = "Dilithium5 (NIST ML-DSA Level 5) signing with a triple-layer \
                      hash cascade, Shamir vaults, and NEV369 transfers."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a Dilithium5 keypair (plaintext JSON — use `vault create` for anything valuable)
    Keygen(KeygenArgs),
    /// Sign a message with a keypair file
    Sign(SignArgs),
    /// Verify a signature
    Verify(VerifyArgs),
    /// Scan source code for quantum-vulnerable cryptography
    Scan(ScanArgs),
    /// Show the address a key derives to on a given chain
    Address(AddressArgs),
    /// List supported chains and their interoperability status
    Chains,
    /// NEV369 wallets: create one, or open it in your browser to send and receive
    #[command(subcommand)]
    Wallet(wallet::WalletCommand),
    /// Send NEV369 from a wallet file or vault (key unlocked in memory only)
    Send(send::SendArgs),
    /// Show a NEV369 balance for a wallet, a vault, or any address
    Balance(send::BalanceArgs),
    /// Time-locked, Shamir-split vaults — the key ceremony
    #[command(subcommand)]
    Vault(vault::VaultCommand),
}

#[derive(clap::Args)]
struct KeygenArgs {
    #[arg(short, long)]
    output: PathBuf,
    /// Chain to display an address for
    #[arg(short, long, default_value = "nev369")]
    chain: String,
}

#[derive(clap::Args)]
struct SignArgs {
    #[arg(short, long)]
    key: PathBuf,
    #[arg(short, long)]
    message: String,
    #[arg(short, long)]
    output: PathBuf,
}
#[derive(clap::Args)]
struct VerifyArgs {
    #[arg(long)]
    public_key: PathBuf,
    #[arg(short, long)]
    signature: PathBuf,
    #[arg(short, long)]
    message: String,
}

#[derive(clap::Args)]
struct ScanArgs {
    path: PathBuf,
    /// Print a migration plan alongside the findings
    #[arg(long)]
    migrate: bool,
}

#[derive(clap::Args)]
struct AddressArgs {
    #[arg(short, long)]
    key: PathBuf,
    #[arg(short, long)]
    chain: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen(a) => keygen(a),
        Command::Sign(a) => sign(a),
        Command::Verify(a) => verify(a),
        Command::Scan(a) => scan(a),
        Command::Address(a) => address(a),
        Command::Chains => chains(),
        Command::Wallet(c) => wallet::run(c),
        Command::Send(a) => send::run(a),
        Command::Balance(a) => send::balance(a),
        Command::Vault(c) => vault::run(c),
    }
}

fn keygen(args: KeygenArgs) -> anyhow::Result<()> {
    println!("     Generating Dilithium5 keypair (NIST ML-DSA Level 5)...");
    let kp = GodKeyPair::generate()?;

    fs::write(&args.output, kp.to_json()?)?;

    println!();
    println!("     {} {}", "Public key:".bold(), &kp.public_key.len());
    println!("     {} {}", "Fingerprint:".bold(), kp.fingerprint);

    if let Some(adapter) = AdapterRegistry::new().get(&args.chain) {
        println!(
            "   {} {} ({:?})",
            "Address:".bold(),
            adapter.encode_public_key(&kp)?,
            adapter.interoperability()
        );
    }

    println!("    {} {}", "Written to:".bold(), args.output.display());
    println!();
    println!(
        "   {}",
        "⚠ This file contains the secret key in PLAINTEXT."
            .red()
            .bold()
    );
    println!(
        "   {}",
        "   For anything holding value, use `godshield vault create` instead —".red()
    );
    println!(
        "   {}",
        "   it splits the key across guardians so one lost file is not fatal.".red()
    );
    println!();
    Ok(())
}

fn sign(args: SignArgs) -> anyhow::Result<()> {
    let kp = GodKeyPair::from_json(&fs::read_to_string(&args.key)?)?;
    let sig = GodShield::sign(&kp, args.message.as_bytes())?;

    fs::write(&args.output, serde_json::to_string_pretty(&sig)?)?;

    println!("   {} Signed", "✓".green().bold());
    println!("   Fingerprint:{}", sig.signer_fingerprint);
    println!("   Written to:{}", args.output.display());
    Ok(())
}

fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    let kp = GodKeyPair::from_json(&fs::read_to_string(&args.public_key)?)?;
    let sig: GodSignature = serde_json::from_str(&fs::read_to_string(&args.signature)?)?;

    let public_key = GodPublicKey {
        public_key: kp.public_key.clone(),
        fingerprint: TripleHash::hash_hex(&kp.public_key),
    };
    if GodShield::verify(&public_key, &sig, args.message.as_bytes())? {
        println!("   {} Signature valid", "✓".green().bold());
        Ok(())
    } else {
        println!("   {} Signature INVALID", "✗".red().bold());
        println!("   The message may have been altered, or it was signed by a different key.");

        std::process::exit(1);
    }
}
fn scan(args: ScanArgs) -> anyhow::Result<()> {
    let source = fs::read_to_string(&args.path)?;
    let vulns = MigrationHelper::scan_vulnerabilities(&source);

    println!();
    if vulns.is_empty() {
        println!(
            "      {} No known-vulnerable primitives matched.",
            "○".yellow()
        );
        println!();
        println!(
            "   {}",
            "This is NOT a clean bill of health. Pattern matching cannot see".dimmed()
        );
        println!(
            "    {}",
            "cryptography reached through dependencies, dynamic dispatch, or FFI.".dimmed()
        );
    } else {
        println!(
            "       Found {} issue(s) in {}:",
            vulns.len(),
            args.path.display()
        );
        println!();
        for v in &vulns {
            let sev = if v.severity == "CRITICAL" {
                v.severity.red().bold()
            } else {
                v.severity.yellow().bold()
            };
            println!(
                "   [{}] line {} — {}",
                sev,
                v.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into()),
                v.crypto_type
            );
            println!(" {}", v.description.dimmed());
        }
        if args.migrate {
            println!();
            println!("{}", MigrationHelper::generate_migration_plan(&vulns));
        }
    }
    println!();
    Ok(())
}

fn address(args: AddressArgs) -> anyhow::Result<()> {
    let kp = GodKeyPair::from_json(&fs::read_to_string(&args.key)?)?;
    let registry = AdapterRegistry::new();
    let adapter = registry
        .get(&args.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", args.chain))?;

    println!();
    println!("     {} {}", "Chain:    ".bold(), adapter.chain_name());
    println!(
        "    {} {}",
        "Address:".bold(),
        adapter.encode_public_key(&kp)?
    );
    println!("    {} {:?}", "Status: ".bold(), adapter.interoperability());
    println!();
    Ok(())
}

fn chains() -> anyhow::Result<()> {
    println!();
    println!(
        "    {:<12} {:<12} {:<20} CONTRACTS",
        "KEY", "CHAIN", "INTEROPERABILITY"
    );
    println!("    {}", "─".repeat(62));
    for c in AdapterRegistry::new().describe() {
        let status = format!("{:?}", c.interoperability);
        let coloured = match c.interoperability {
            godshield_adapters::Interoperability::Native => status.green(),

            godshield_adapters::Interoperability::PendingStandard => status.yellow(),

            godshield_adapters::Interoperability::GodShieldOnly => status.red(),
        };
        println!(
            "   {:<12} {:<12} {:<20} {}",
            c.key,
            c.name,
            coloured,
            if c.smart_contracts { "yes" } else { "no" }
        );
    }
    println!();
    println!(
        "    {}",
        "Only 'Native' output is accepted by the live network. The others are".dimmed()
    );
    println!(
        "    {}",
        "forward-looking encodings for standards that have not activated.".dimmed()
    );
    println!();
    Ok(())
}
