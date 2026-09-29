// crates/godshield-cli/src/vault.rs
//
// Vault ceremony commands: create, recover, status, verify.
// See docs/nevaeh-vault-ceremony.md for the full procedure.
//
// ═══════════════════════════════════════════════════════════════════════
// REWRITTEN AGAINST THE CURRENT nevaeh-vault API
//
// The previous version was written against an older vault engine. It
// called `builder.build()`, `vault.recover()`,
// `vault.recover_ignoring_timelock()` and read `vault.public_key_hex` —
// none of which exist any more. The engine now distinguishes the secret it
// holds: `build_dilithium5` / `build_xrpl_seed`, `recover_godkeypair` /
// `recover_xrpl_seed`, and `public_identifier`. So this did not compile.
//
// More important than the compile error: it could only ever create
// Dilithium5 vaults. The ceremony's Step 2 vaults the XRPL SEED — the key
// that controls Nevaeh's actual inheritance — and there was no way to do
// it. Worse, `make vault-nevaeh-xrpl` passed no seed at all, so once
// patched to compile it would have SUCCEEDED, sealing a freshly generated
// Dilithium key into a vault labelled "nevaeh-xrpl-seed". Every screen
// would have said the seed was vaulted. It would not have been.
//
// Now:
//   --xrpl-address r...   vaults an XRPL family seed. The seed itself is
//                         read at a hidden prompt, twice, never from argv.
//   (no --xrpl-address)   generates and vaults a Dilithium5 keypair.
//   --notes "..."         where Owner and OfferSequence go.
// ═══════════════════════════════════════════════════════════════════════

use clap::{Args, Subcommand};
use colored::Colorize;
use godshield_core::{GodKeyPair, GodShield};
use nevaeh_vault::{
    LockStatus, SecretKind, TimeLockedVault, VaultBuilder, VaultShare, NEVAEH_UNLOCK_TIMESTAMP,
};
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Create a new time-locked, Shamir-split vault
    Create(CreateArgs),
    /// Recover the secret from a vault plus threshold shares
    Recover(RecoverArgs),
    /// Show lock status and time remaining
    Status(StatusArgs),
    /// Verify a vault file and its shares without unlocking
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    #[arg(long)]
    pub label: String,

    #[arg(long)]
    pub beneficiary: String,

    #[arg(long)]
    pub dob: Option<String>,

    /// Unlock date, YYYY-MM-DD. Defaults to 28 July 2039.
    #[arg(long)]
    pub unlock: Option<String>,

    /// No time-lock. For the Architect's own wallet.
    #[arg(long)]
    pub no_timelock: bool,

    #[arg(long, default_value_t = 3)]
    pub threshold: u8,

    #[arg(long, default_value_t = 5)]
    pub shares: u8,

    /// Repeatable: --guardian "Name:contact:location"
    #[arg(long = "guardian")]
    pub guardians: Vec<String>,

    /// Vault an XRPL family seed controlling this classic address, instead
    /// of generating a Dilithium5 key. You will be prompted for the seed.
    #[arg(long)]
    pub xrpl_address: Option<String>,

    /// Refused. Present only so it fails with an explanation rather than
    /// "unexpected argument". See create().
    #[arg(long, hide = true)]
    pub xrpl_seed: Option<String>,

    /// Free text sealed into the vault file. Record the XRPL escrow's Owner
    /// and OfferSequence here.
    #[arg(long)]
    pub notes: Option<String>,

    #[arg(long)]
    pub output: PathBuf,

    #[arg(long)]
    pub shares_dir: PathBuf,
}

#[derive(Args)]
pub struct RecoverArgs {
    #[arg(long)]
    pub vault: PathBuf,

    #[arg(long = "share")]
    pub shares: Vec<PathBuf>,

    /// Bypass the time-lock. Still requires the full share threshold, so it
    /// cannot be done by one person. Use for testing recovery, which you
    /// MUST do at creation and annually thereafter.
    #[arg(long)]
    pub test_mode: bool,

    /// Write the recovered secret here. Omit to show it on screen only.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct StatusArgs {
    #[arg(long)]
    pub vault: PathBuf,
}

#[derive(Args)]
pub struct VerifyArgs {
    #[arg(long)]
    pub vault: PathBuf,

    #[arg(long = "share")]
    pub shares: Vec<PathBuf>,
}

pub fn run(cmd: VaultCommand) -> anyhow::Result<()> {
    match cmd {
        VaultCommand::Create(a) => create(a),
        VaultCommand::Recover(a) => recover(a),
        VaultCommand::Status(a) => status(a),
        VaultCommand::Verify(a) => verify(a),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CREATE
// ═══════════════════════════════════════════════════════════════════════

/// What the vault seals, decided before anything is written.
enum Secret {
    Dilithium,
    Xrpl { seed: String, address: String },
}

fn create(args: CreateArgs) -> anyhow::Result<()> {
    // The seed on the command line lands in shell history and is visible
    // to every process on the machine through `ps` for as long as this
    // runs. For the key that controls the inheritance, that is not
    // acceptable, so it is refused outright.
    if args.xrpl_seed.is_some() {
        anyhow::bail!(
            "Do not pass the XRPL seed on the command line.\n\n\
             It is now in your shell history — clear it (`history -c`, or delete the \
             line from ~/.bash_history / ~/.zsh_history) before continuing.\n\n\
             Re-run with --xrpl-address only. You will be prompted for the seed, \
             hidden, twice."
        );
    }

    println!("{}", "─".repeat(70));
    println!("{}", "   VAULT CREATION CEREMONY".bold());
    println!("{}", "─".repeat(70));
    println!();
    println!("    Before continuing, confirm:");
    println!("       • You are on a machine you trust, ideally offline");
    println!("       • This session is not being recorded or screen-shared");
    println!("       • Your guardians are chosen and contactable");
    println!("       • You have physical media ready for each share");
    println!();
    println!(
        "    {}",
        "Shares are shown ONCE and cannot be regenerated.".yellow()
    );
    println!();

    if args.threshold < 2 {
        anyhow::bail!("threshold must be at least 2 — a 1-of-N split defeats the purpose");
    }
    if args.threshold > args.shares {
        anyhow::bail!(
            "threshold ({}) cannot exceed total shares ({})",
            args.threshold,
            args.shares
        );
    }
    if args.guardians.len() != args.shares as usize {
        anyhow::bail!(
            "expected {} --guardian entries to match --shares {}, got {}",
            args.shares,
            args.shares,
            args.guardians.len()
        );
    }

    // Decide the secret before building anything.
    let secret = match &args.xrpl_address {
        Some(address) => {
            println!("    Vaulting an XRPL family seed for {}", address.bold());
            println!(
                "    {}",
                "Input is hidden. Nothing is echoed or logged.".dimmed()
            );
            println!();
            let first = rpassword::prompt_password("    XRPL seed (s...): ")?;
            let second = rpassword::prompt_password("    Again, to confirm:  ")?;
            if first != second {
                anyhow::bail!("the two entries do not match — nothing was written");
            }
            let seed = first.trim().to_string();
            if !seed.starts_with('s') {
                anyhow::bail!(
                    "an XRPL family seed starts with 's'. Refusing to vault something \
                     that does not look like one — the mistake would only surface in 2039."
                );
            }
            println!();
            Secret::Xrpl {
                seed,
                address: address.trim().to_string(),
            }
        }
        None => Secret::Dilithium,
    };

    let unlock_ts = if args.no_timelock {
        1
    } else if let Some(date) = &args.unlock {
        parse_date(date)?
    } else {
        NEVAEH_UNLOCK_TIMESTAMP
    };

    let mut builder = VaultBuilder::new(&args.label, &args.beneficiary)
        .unlock_at(unlock_ts)
        .threshold(args.threshold, args.shares);

    if let Some(dob) = &args.dob {
        builder = builder.dob(dob);
    }
    if let Some(notes) = &args.notes {
        builder = builder.notes(notes);
    }

    for g in &args.guardians {
        let parts: Vec<&str> = g.splitn(3, ':').collect();
        builder = builder.guardian(
            parts.first().copied().unwrap_or("Unnamed"),
            parts.get(1).copied().unwrap_or(""),
            parts.get(2).copied().unwrap_or(""),
        );
    }

    let (vault, shares) = match &secret {
        Secret::Dilithium => {
            println!("    Generating Dilithium5 keypair...");
            builder.build_dilithium5()?
        }
        Secret::Xrpl { seed, address } => {
            println!("    Sealing XRPL seed...");
            builder.build_xrpl_seed(seed, address)?
        }
    };

    println!("    Encrypting secret (AES-256-GCM)...");
    println!(
        "    Splitting master key ({}-of-{} Shamir)...",
        args.threshold, args.shares
    );
    println!();

    // ── Self-test BEFORE anything is written ──
    //
    // A vault whose recovery has never been exercised is not a backup. And
    // it is tested before the files exist, so a failure cannot leave a
    // broken vault on disk for someone to trust later.
    print!("    Verifying recovery with {} shares... ", args.threshold);
    self_test(&vault, &shares[..args.threshold as usize], &secret)?;
    println!("{}", "PASSED".green().bold());

    if args.shares > args.threshold {
        print!("    Verifying an alternate share combination... ");
        let alt: Vec<VaultShare> = shares
            .iter()
            .rev()
            .take(args.threshold as usize)
            .cloned()
            .collect();
        self_test(&vault, &alt, &secret)?;
        println!("{}", "PASSED".green().bold());
    }
    println!();

    fs::write(&args.output, vault.to_json()?)?;
    fs::create_dir_all(&args.shares_dir)?;

    for share in &shares {
        let path = args.shares_dir.join(format!(
            "share_{}_{}.json",
            share.share_index,
            sanitize(&share.guardian_name)
        ));
        fs::write(&path, share.to_json()?)?;
        println!(
            "    {} share {} → {}   ({})",
            "✓".green(),
            share.share_index,
            path.display(),
            share.guardian_name
        );
    }

    println!();
    println!("    {} {}", "Vault file: ".bold(), args.output.display());
    println!(
        "    {} {}",
        "Holds:      ".bold(),
        vault.secret_kind.describe()
    );
    println!("    {} {}", "Identifier: ".bold(), vault.public_identifier);
    println!("    {} {}", "Fingerprint:".bold(), vault.fingerprint);
    if !args.no_timelock {
        println!("    {} {}", "Unlocks:    ".bold(), vault.unlock_human);
    }
    println!();

    println!("{}", "─".repeat(70));
    println!("{}", "      DO THESE NOW — NOT LATER".bold().yellow());
    println!("{}", "─".repeat(70));
    println!("     1. Copy the vault file to at least 4 places.");
    println!(
        "        It is safe to copy — useless without {} shares.",
        args.threshold
    );
    println!("     2. Deliver each share to its guardian in person or by post.");
    println!(
        "        {} Never email, upload, or paste a share anywhere.",
        "→".red()
    );
    println!("     3. Give each guardian a printed copy of the recovery instructions.");
    println!("     4. Record in your will: vault location, guardian list, this document.");
    println!(
        "     5. Delete {} from this machine once shares are distributed.",
        args.shares_dir.display()
    );
    println!("     6. Set an annual calendar reminder to re-verify.");
    if matches!(secret, Secret::Xrpl { .. }) && args.notes.is_none() {
        println!();
        println!(
            "     {} No --notes given. Once the XRPL escrow validates, record its",
            "!".yellow().bold()
        );
        println!("       Owner and OfferSequence: `qlock-inheritance record --tx-hash ...`");
    }
    println!();
    println!(
        "    {}",
        "An untested backup is not a backup. Re-test every year.".dimmed()
    );
    println!();
    Ok(())
}

/// Recover from `shares` and prove the result is the secret that was sealed.
fn self_test(
    vault: &TimeLockedVault,
    shares: &[VaultShare],
    secret: &Secret,
) -> anyhow::Result<()> {
    match secret {
        Secret::Dilithium => {
            let kp = vault.recover_godkeypair_ignoring_timelock(shares)?;
            // Compare the public key itself. The vault fingerprint is a
            // share-binding tag, not the key fingerprint — comparing the
            // two failed every self-test.
            if hex::encode(&kp.public_key) != vault.public_identifier {
                anyhow::bail!(
                    "SELF-TEST FAILED — recovered key does not match. Do not use this vault."
                );
            }
            // Prove the recovered key can sign, not merely reconstruct.
            let probe = b"vault self-test";
            let sig = GodShield::sign(&kp, probe)?;
            if !GodShield::verify(&kp.export_public(), &sig, probe)? {
                anyhow::bail!(
                    "SELF-TEST FAILED — recovered key cannot sign. Do not use this vault."
                );
            }
        }
        Secret::Xrpl { seed, .. } => {
            let recovered = vault.recover_xrpl_seed_ignoring_timelock(shares)?;
            if &recovered != seed {
                anyhow::bail!(
                    "SELF-TEST FAILED — recovered seed does not match. Do not use this vault."
                );
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// RECOVER
// ═══════════════════════════════════════════════════════════════════════

fn recover(args: RecoverArgs) -> anyhow::Result<()> {
    let vault = TimeLockedVault::from_json(&fs::read_to_string(&args.vault)?)?;
    let mut shares = Vec::new();
    for p in &args.shares {
        shares.push(VaultShare::from_json(&fs::read_to_string(p)?)?);
    }

    println!();
    println!("    Vault:        {}", vault.label);
    println!("    Beneficiary:  {}", vault.beneficiary);
    println!("    Holds:        {}", vault.secret_kind.describe());
    println!(
        "    Shares:       {} of {} required",
        shares.len(),
        vault.shares_required
    );
    println!();

    if args.test_mode {
        println!("    {}", "TEST MODE — bypassing time-lock".yellow());
        println!(
            "    {}",
            "(still requires the full share threshold)".dimmed()
        );
        println!();
    }

    match vault.secret_kind {
        SecretKind::Dilithium5 => {
            let kp: GodKeyPair = if args.test_mode {
                vault.recover_godkeypair_ignoring_timelock(&shares)?
            } else {
                vault.recover_godkeypair(&shares)?
            };
            println!("    {} Key recovered", "✓".green().bold());
            println!("    Public key:   {}", vault.public_identifier);
            println!("    Fingerprint:  {}", kp.fingerprint);
            println!();
            match &args.output {
                Some(out) => {
                    fs::write(out, kp.to_json()?)?;
                    warn_plaintext(out);
                }
                None => println!(
                    "    {}",
                    "Secret key not written to disk (no --output given).".dimmed()
                ),
            }
        }
        SecretKind::XrplSeed => {
            let seed = if args.test_mode {
                vault.recover_xrpl_seed_ignoring_timelock(&shares)?
            } else {
                vault.recover_xrpl_seed(&shares)?
            };
            println!("    {} Seed recovered", "✓".green().bold());
            println!("    Address:      {}", vault.public_identifier);
            println!();
            if args.test_mode {
                // A test proves recovery works. It does not need to put the
                // seed on a screen.
                println!(
                    "    {}",
                    "Test mode: seed verified but not displayed.".dimmed()
                );
            } else {
                match &args.output {
                    Some(out) => {
                        fs::write(out, &seed)?;
                        warn_plaintext(out);
                    }
                    None => {
                        println!("    Seed:         {}", seed.bold());
                        println!();
                        println!(
                            "    {}",
                            "Import this into a wallet on an OFFLINE machine.".yellow()
                        );
                        println!(
                            "    {}",
                            "Do not photograph it or write it to disk unencrypted.".yellow()
                        );
                    }
                }
            }
        }
        SecretKind::Raw => {
            let bytes = if args.test_mode {
                vault.recover_bytes_ignoring_timelock(&shares)?
            } else {
                vault.recover_bytes(&shares)?
            };
            println!("    {} {} bytes recovered", "✓".green().bold(), bytes.len());
            if let Some(out) = &args.output {
                fs::write(out, &bytes)?;
                warn_plaintext(out);
            }
        }
    }
    println!();
    Ok(())
}

fn warn_plaintext(out: &std::path::Path) {
    println!("    {} Written to {}", "⚠".yellow(), out.display());
    println!(
        "    {}",
        "This file contains the PLAINTEXT secret.".red().bold()
    );
    println!(
        "    {}",
        "Move it to secure storage and delete it from here.".red()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// STATUS / VERIFY
// ═══════════════════════════════════════════════════════════════════════

fn status(args: StatusArgs) -> anyhow::Result<()> {
    let vault = TimeLockedVault::from_json(&fs::read_to_string(&args.vault)?)?;
    let s: LockStatus = vault.lock_status();

    println!();
    println!("    {}", vault.label.bold());
    println!("    Beneficiary:  {}", vault.beneficiary);
    if let Some(dob) = &vault.beneficiary_dob {
        println!("    DOB:          {dob}");
    }
    println!("    Holds:        {}", vault.secret_kind.describe());
    println!("    Identifier:   {}", vault.public_identifier);
    println!(
        "    Threshold:    {} of {}",
        vault.shares_required, vault.shares_total
    );
    if !vault.notes.is_empty() {
        println!("    Notes:        {}", vault.notes);
    }
    println!();
    if s.unlocked {
        println!("    Status:       {}", "UNLOCKED".green().bold());
    } else {
        println!("    Status:       {}", "LOCKED".yellow().bold());
        println!("    Unlocks:      {}", s.unlocks_at_human);
        println!(
            "    Remaining:    {} days ({:.1} years)",
            s.days_remaining, s.years_remaining
        );
    }
    println!();
    println!("    {}", "Guardians:".bold());
    for g in &vault.guardian_directory {
        println!(
            "      {}. {} — {} ({})",
            g.share_index, g.guardian_name, g.guardian_contact, g.location_hint
        );
    }
    println!();
    match vault.verify_integrity() {
        Ok(()) => println!("    Integrity:    {}", "OK".green()),
        Err(e) => println!("    Integrity:    {} — {e}", "FAILED".red().bold()),
    }
    println!();
    Ok(())
}

fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    let vault = TimeLockedVault::from_json(&fs::read_to_string(&args.vault)?)?;

    print!("    Vault file integrity... ");
    match vault.verify_integrity() {
        Ok(()) => println!("{}", "OK".green()),
        Err(e) => {
            println!("{}", "FAILED".red().bold());
            anyhow::bail!("This copy is corrupted — use another backup. ({e})");
        }
    }

    let mut valid = 0;
    for p in &args.shares {
        let share = VaultShare::from_json(&fs::read_to_string(p)?)?;
        let matches = share.vault_fingerprint == vault.fingerprint;
        println!(
            "    Share {} ({})... {}",
            share.share_index,
            share.guardian_name,
            if matches {
                "OK".green()
            } else {
                "WRONG VAULT".red().bold()
            }
        );
        if matches {
            valid += 1;
        }
    }

    println!();
    if valid >= vault.shares_required as usize {
        println!(
            "    {} {valid} valid shares — recovery is possible.",
            "✓".green().bold()
        );
        println!(
            "    {}",
            "Run `vault recover --test-mode` to prove it end to end.".dimmed()
        );
    } else {
        println!(
            "    {} Only {valid} valid shares, need {}.",
            "✗".red().bold(),
            vault.shares_required
        );
        println!("    Contact the remaining guardians listed in the vault file.");
    }
    println!();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

fn parse_date(s: &str) -> anyhow::Result<i64> {
    use chrono::{NaiveDate, TimeZone, Utc};
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("date must be YYYY-MM-DD, got '{s}'"))?;
    let dt = d
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid time"))?;
    Ok(Utc.from_utc_datetime(&dt).timestamp())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════
// THE THREE VAULTS
// ═══════════════════════════════════════════════════════════════════════
//
//   make vault-nevaeh-xrpl      XRPL seed, 3-of-5, locked to 2039.
//                               THE ACTUAL INHERITANCE.
//   make vault-nevaeh-nev369    Dilithium5, 3-of-5, locked to 2039.
//   make vault-architect        Dilithium5, 2-of-3, no time-lock.
//
// Then, every year:
//
//   godshield vault status  --vault nevaeh_xrpl_vault.json
//   godshield vault recover --vault nevaeh_xrpl_vault.json \
//     --share s1.json --share s2.json --share s3.json --test-mode
//
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nevaeh_unlock_date_parses_to_the_chain_constant() {
        assert_eq!(parse_date("2039-07-28").unwrap(), NEVAEH_UNLOCK_TIMESTAMP);
    }

    #[test]
    fn share_filenames_are_safe() {
        assert_eq!(
            sanitize("Solicitor: Held with will"),
            "solicitor__held_with_will"
        );
    }
}
