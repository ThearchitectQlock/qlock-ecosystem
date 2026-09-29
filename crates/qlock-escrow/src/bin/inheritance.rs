// crates/qlock-escrow/src/bin/inheritance.rs
//
// ═══════════════════════════════════════════════════════════════════════
// INHERITANCE ESCROW CEREMONY
//
// Creates the 13-year XRPL escrow that holds Nevaeh's inheritance.
//
// WHY THIS EXISTS: inheritance.rs was written but nothing ever called it.
// The entire custody solution had no way to be invoked — a module with no
// entry point is the same as no module.
//
// This is a one-time ceremony, deliberately a CLI rather than a web UI.
// Locking a large sum for thirteen years is not something that should
// happen behind a button in a browser session.
//
//   cargo run -p qlock-escrow --bin qlock-inheritance -- create \
//       --grantor rYourAddress... \
//       --destination rNevaehAddress... \
//       --amount 10000 \
//       --unlock 2039-07-28
//
//   cargo run -p qlock-escrow --bin qlock-inheritance -- record \
//       --tx-hash <EscrowCreate hash>
//
// It does NOT sign or submit anything. It prints an unsigned transaction
// for you to approve in Xaman — no key material touches this process.
//
// ── RECONSTRUCTION NOTES ──────────────────────────────────────────────
//
// This file only survived as a hard-wrapped PDF render. Rebuilt by hand
// against the real inheritance.rs and xrpl.rs APIs. Three defects in the
// original were fixed rather than transcribed:
//
//   1. The PDF ate the hyphens inside the date defaults — "2039-0728" and
//      "2021-0728". parse_date() uses "%Y-%m-%d", so running with the
//      defaults would have rejected its own default value.
//
//   2. The ceremony told you to run `qlock-inheritance record --tx-hash
//      ... --offer-sequence ...` — and no `record` command existed. The
//      step that captures OfferSequence, the single most losable value in
//      the design, had no tool behind it. It exists now, and it looks the
//      OfferSequence up on-ledger instead of trusting a hand-copied number.
//
//   3. The amount went through f64. For the inheritance itself, against
//      the rule everything else in this codebase follows. Parsed as a
//      decimal string to drops now.
// ═══════════════════════════════════════════════════════════════════════

use clap::{Args, Parser, Subcommand};
use godshield_core::GodKeyPair;
use qlock_escrow::inheritance::{recovery_text, InheritanceBuilder, InheritanceRecord};
use qlock_escrow::xrpl::XrplClient;

const RULE: &str = "────────────────────────────────────────────────────────────";

#[derive(Parser)]
#[command(
    name = "qlock-inheritance",
    about = "Create and record a time-locked XRPL inheritance escrow",
    long_about = "Locks XRP on the XRP Ledger until a beneficiary's chosen date.\n\
                  Enforced by XRPL consensus — no code in this repository can\n\
                  release it early.\n\n\
                  Prints an unsigned transaction. Nothing is signed here."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Prepare the EscrowCreate and write a partial record.
    Create(CreateArgs),
    /// After the EscrowCreate validates: look up its OfferSequence on-ledger,
    /// verify it matches the attested terms, and complete the record.
    Record(RecordArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// Your XRPL address — the account funding the escrow.
    #[arg(long)]
    grantor: String,

    /// Beneficiary's XRPL address. MUST already be activated on-ledger.
    #[arg(long)]
    destination: String,

    /// Amount in XRP, as a decimal (e.g. 10000 or 10000.5). Up to 6 places.
    #[arg(long)]
    amount: String,

    /// Unlock date, YYYY-MM-DD.
    #[arg(long, default_value = "2039-07-28")]
    unlock: String,

    #[arg(long, default_value = "Nevaeh")]
    beneficiary: String,

    #[arg(long, default_value = "2021-07-28")]
    dob: String,

    /// XRPL JSON-RPC endpoint used to verify the destination is funded.
    #[arg(long, default_value = "https://xrplcluster.com")]
    xrpl_node: String,

    /// Skip the destination balance check. Testnet only — skipping it on
    /// mainnet risks an unreleasable escrow.
    #[arg(long)]
    skip_destination_check: bool,

    /// Where to write the record. Print it and store it with the vault files.
    #[arg(long, default_value = "./inheritance_record.json")]
    output: String,
}

#[derive(Args)]
struct RecordArgs {
    /// Hash of the validated EscrowCreate transaction.
    #[arg(long)]
    tx_hash: String,

    /// The partial record written by `create`.
    #[arg(long, default_value = "./inheritance_record.json")]
    record: String,

    #[arg(long, default_value = "https://xrplcluster.com")]
    xrpl_node: String,

    /// Optional: the OfferSequence you read off an explorer. If given, it is
    /// cross-checked against the ledger and a mismatch is fatal.
    #[arg(long)]
    offer_sequence: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Create(a) => create(a).await,
        Cmd::Record(a) => record(a).await,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CREATE
// ═══════════════════════════════════════════════════════════════════════

async fn create(args: CreateArgs) -> anyhow::Result<()> {
    println!();
    println!("  INHERITANCE ESCROW CEREMONY");
    println!("  {RULE}");
    println!();

    let unlock_ts = parse_date(&args.unlock)?;
    let amount_drops = xrp_to_drops(&args.amount)?;

    // ── Pre-flight: is the destination actually activated? ──
    //
    // An unfunded destination means EscrowFinish fails with tecNO_DST when
    // the lock expires. Discovering that in 2039 is unrecoverable, so it is
    // checked live rather than assumed.
    let destination_balance = if args.skip_destination_check {
        println!("  ⚠ Skipping destination balance check (--skip-destination-check).");
        println!("    On mainnet this risks an escrow that can never be released.");
        println!();
        None
    } else {
        print!("  Checking destination account is activated... ");
        let client = XrplClient::new(&args.xrpl_node);
        match client.get_balance(&args.destination).await {
            Ok(xrp) => {
                println!("✓ {xrp} XRP");
                // Presence check only — the precise figure is not used for
                // anything that moves money.
                Some((xrp * 1_000_000.0) as u64)
            }
            Err(e) => {
                println!("✗");
                println!();
                anyhow::bail!(
                    "Destination {} could not be found on-ledger ({}).\n\n\
                     Fund it with at least the base reserve BEFORE creating this \
                     escrow. An unactivated destination means EscrowFinish fails \
                     with tecNO_DST when the lock expires, and the funds become \
                     permanently unreleasable.",
                    args.destination,
                    e
                );
            }
        }
    };

    // ── Attestation identity ──
    //
    // Uses the platform's persistent identity if QLOCK_ATTESTATION_KEY is
    // set; otherwise a key generated for this ceremony alone.
    //
    // The ephemeral option is defensible here in a way it is not for the
    // escrow backend: the public key travels inside the record, and the
    // record is stored in three physical places. But a persistent identity
    // is stronger — a record signed by the published Q-Lock fingerprint
    // cannot be substituted by anyone who can merely write a file.
    let (attestation_key, key_kind) = match std::env::var("QLOCK_ATTESTATION_KEY") {
        Ok(json) if !json.trim().is_empty() => (
            GodKeyPair::from_json(&json)
                .map_err(|e| anyhow::anyhow!("QLOCK_ATTESTATION_KEY: {e}"))?,
            "persistent",
        ),
        _ => (GodKeyPair::generate()?, "ceremony-only"),
    };

    let escrow = InheritanceBuilder::prepare(
        &attestation_key,
        "inheritance-ceremony",
        &args.beneficiary,
        &args.dob,
        &args.grantor,
        &args.destination,
        amount_drops,
        unlock_ts,
        destination_balance,
    )?;

    println!(
        "  Beneficiary:  {} (b. {})",
        escrow.beneficiary_name, escrow.beneficiary_dob
    );
    println!("  Amount:       {} XRP", drops_to_xrp(amount_drops));
    println!("  Destination:  {}", escrow.destination_address);
    println!("  Unlocks:      {}", escrow.unlock_date);
    println!("  FinishAfter:  {} (ripple epoch)", escrow.finish_after);
    println!("  Attestation:  Dilithium5, {key_kind} key");
    println!();
    println!("  No CancelAfter is set. This is irrevocable — you cannot");
    println!("  reclaim it, and neither can anyone else.");
    println!();
    println!("  {RULE}");
    println!("  UNSIGNED TRANSACTION — approve this in Xaman");
    println!("  {RULE}");
    println!();
    println!("{}", serde_json::to_string_pretty(&escrow.txjson)?);
    println!();
    println!("  {RULE}");
    println!("  AFTER YOU SUBMIT IT — DO THIS IMMEDIATELY");
    println!("  {RULE}");
    println!();
    println!("  Once the transaction validates, run:");
    println!();
    println!("    qlock-inheritance record --tx-hash <hash>");
    println!();
    println!("  That looks up the OfferSequence on-ledger, checks the escrow");
    println!("  matches these terms, and completes the record. Without the");
    println!("  OfferSequence the funds are visible on-ledger and permanently");
    println!("  unreleasable.");
    println!();
    println!("  Then store the record with your vault files, print a copy,");
    println!("  and give one to your solicitor alongside your will.");
    println!();

    // Capture the terms now so nothing is lost if the record step is
    // delayed. offer_sequence 0 marks it incomplete.
    let record = InheritanceRecord::new(&escrow, 0, "PENDING", detect_network(&args.xrpl_node));
    std::fs::write(&args.output, serde_json::to_string_pretty(&record)?)?;
    println!("  Partial record written to {}", args.output);
    println!("  ⚠ offer_sequence is 0 — this record is INCOMPLETE until `record` runs.");
    println!();
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// RECORD
// ═══════════════════════════════════════════════════════════════════════

async fn record(args: RecordArgs) -> anyhow::Result<()> {
    println!();
    println!("  RECORDING OFFERSEQUENCE");
    println!("  {RULE}");
    println!();

    let raw = std::fs::read_to_string(&args.record)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", args.record))?;
    let mut rec: InheritanceRecord = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("{} is not an inheritance record: {e}", args.record))?;

    if rec.offer_sequence != 0 && rec.create_tx_hash != "PENDING" {
        anyhow::bail!(
            "{} is already complete (OfferSequence {}, tx {}). Refusing to overwrite a \
             completed record — if this is genuinely wrong, move it aside first.",
            args.record,
            rec.offer_sequence,
            rec.create_tx_hash
        );
    }

    let client = XrplClient::new(&args.xrpl_node);
    let info = client.get_escrow_create(&args.tx_hash).await?;

    // Every check below guards against recording a number that looks right
    // and opens nothing in 2039.
    let mut problems: Vec<String> = Vec::new();
    if !info.validated {
        problems.push("the transaction is not yet validated — wait and retry".into());
    }
    if info.transaction_type != "EscrowCreate" {
        problems.push(format!(
            "it is a {}, not an EscrowCreate",
            info.transaction_type
        ));
    }
    if info.result != "tesSUCCESS" {
        problems.push(format!("it did not succeed ({})", info.result));
    }
    if info.account != rec.grantor_address {
        problems.push(format!(
            "it was sent by {}, but the record's grantor is {}",
            info.account, rec.grantor_address
        ));
    }
    if info.destination != rec.destination_address {
        problems.push(format!(
            "its destination is {}, but the record says {}",
            info.destination, rec.destination_address
        ));
    }
    if info.amount_drops != Some(rec.amount_drops) {
        problems.push(format!(
            "it locked {:?} drops, but the record says {}",
            info.amount_drops, rec.amount_drops
        ));
    }
    if info.finish_after != Some(rec.finish_after_ripple) {
        problems.push(format!(
            "its FinishAfter is {:?}, but the record says {}",
            info.finish_after, rec.finish_after_ripple
        ));
    }
    if info.cancel_after.is_some() {
        problems.push(
            "it carries a CancelAfter — this escrow can be reclaimed, which is not what \
             the ceremony prepared"
                .into(),
        );
    }

    let offer_sequence = info.offer_sequence();
    if let Some(claimed) = args.offer_sequence {
        if claimed != offer_sequence {
            problems.push(format!(
                "you supplied OfferSequence {claimed}, but the ledger says {offer_sequence}"
            ));
        }
    }

    if !problems.is_empty() {
        println!("  ✗ This transaction does not match the record:");
        for p in &problems {
            println!("    • {p}");
        }
        println!();
        anyhow::bail!("record NOT updated");
    }

    rec.offer_sequence = offer_sequence;
    rec.create_tx_hash = args.tx_hash.clone();
    rec.recovery_instructions = recovery_text(
        &rec.beneficiary_name,
        &rec.unlock_date,
        &rec.grantor_address,
        offer_sequence,
        &rec.destination_address,
    );

    std::fs::write(&args.record, serde_json::to_string_pretty(&rec)?)?;

    println!("  ✓ Verified on-ledger:");
    println!("    Owner          {}", rec.grantor_address);
    println!("    OfferSequence  {offer_sequence}");
    println!("    Destination    {}", rec.destination_address);
    println!("    Amount         {} XRP", drops_to_xrp(rec.amount_drops));
    println!("    Unlocks        {}", rec.unlock_date);
    if info.ticket_sequence.is_some() && info.sequence == 0 {
        println!("    (created with a Ticket — OfferSequence is the TicketSequence)");
    }
    println!();
    println!("  Record completed: {}", args.record);
    println!();
    println!("  Write Owner and OfferSequence down in three places:");
    println!("    1. the vault notes");
    println!("    2. the ceremony document");
    println!("    3. your will");
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

/// "10000", "10000.5", "0.000001" → drops. Never through a float.
fn xrp_to_drops(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        anyhow::bail!("amount is empty");
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("amount must be a plain decimal number of XRP, got '{s}'");
    }
    if frac.len() > 6 {
        anyhow::bail!("XRP has 6 decimal places; '{s}' has {}", frac.len());
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse()? };
    let frac: u64 = format!("{frac:0<6}").parse()?;
    whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac))
        .filter(|d| *d > 0)
        .ok_or_else(|| anyhow::anyhow!("amount '{s}' is zero or too large"))
}

fn drops_to_xrp(drops: u64) -> String {
    let frac = format!("{:06}", drops % 1_000_000);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{}", drops / 1_000_000)
    } else {
        format!("{}.{}", drops / 1_000_000, frac)
    }
}

fn detect_network(node: &str) -> &'static str {
    if node.contains("altnet") || node.contains("testnet") {
        "testnet"
    } else if node.contains("devnet") {
        "devnet"
    } else {
        "mainnet"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dates_parse() {
        // The PDF rendering turned these into "2039-0728" / "2021-0728",
        // which the ceremony's own parser rejects.
        assert!(parse_date("2039-07-28").is_ok());
        assert!(parse_date("2021-07-28").is_ok());
        assert!(parse_date("2039-0728").is_err());
    }

    #[test]
    fn unlock_is_midnight_utc_on_her_18th_birthday() {
        assert_eq!(parse_date("2039-07-28").unwrap(), 2_195_424_000);
    }

    #[test]
    fn amounts_convert_exactly() {
        assert_eq!(xrp_to_drops("10000").unwrap(), 10_000_000_000);
        assert_eq!(xrp_to_drops("0.000001").unwrap(), 1);
        assert_eq!(xrp_to_drops("1.5").unwrap(), 1_500_000);
        // A value f64 cannot hold exactly after scaling.
        assert_eq!(
            xrp_to_drops("9007199254.740993").unwrap(),
            9_007_199_254_740_993
        );
    }

    #[test]
    fn bad_amounts_are_refused() {
        assert!(xrp_to_drops("0").is_err());
        assert!(xrp_to_drops("1.0000001").is_err(), "7 decimal places");
        assert!(xrp_to_drops("-5").is_err());
        assert!(xrp_to_drops("1e6").is_err());
        assert!(xrp_to_drops("").is_err());
    }

    #[test]
    fn drops_round_trip() {
        for s in ["10000", "1.5", "0.000001", "123.456789"] {
            assert_eq!(drops_to_xrp(xrp_to_drops(s).unwrap()), s);
        }
    }

    #[test]
    fn network_detection() {
        assert_eq!(
            detect_network("https://s.altnet.rippletest.net:51234"),
            "testnet"
        );
        assert_eq!(detect_network("https://xrplcluster.com"), "mainnet");
    }
}
