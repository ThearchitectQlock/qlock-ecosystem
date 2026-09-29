// crates/qlock-escrow/src/inheritance.rs
//
// ═══════════════════════════════════════════════════════════════════════
// 13-YEAR INHERITANCE ESCROW — XRPL native, consensus-enforced
//
// WHY THIS EXISTS:
//
// NEV369's time-lock is enforced by code the chain operator controls, on a
// chain secured by the operator's own hashrate. For a 13-year inheritance
// that is two bets stacked: that the operator never changes the code, and
// that nobody outbids the network's hashrate for 13 consecutive years as
// the locked value — and therefore the incentive to attack — grows.
//
// This module removes both bets. Funds sit in an XRPL native Escrow object
// with FinishAfter set to the beneficiary's 18th birthday. Release is
// enforced by XRPL consensus. Not by Q-Lock, not by NEV369, not by the
// Architect. There is no code path anywhere in this repository that can
// release those funds early, because the enforcement does not live here.
//
// ═══════════════════════════════════════════════════════════════════════
// CRITICAL DESIGN DECISIONS — read before changing any of these
// ═══════════════════════════════════════════════════════════════════════
//
// 1. NO CancelAfter.
//
//    XRPL's EscrowCancel returns funds to the sender once CancelAfter
//    passes. Setting it would give the Architect a way to reclaim the gift.
//    That is exactly what this is meant to prevent, so it is omitted.
//
//    The cost of omitting it, stated plainly: if EscrowFinish is never
//    submitted, the funds remain locked on-ledger permanently. There is no
//    recovery path. That is the deliberate trade — irrevocable in both
//    directions.
//
// 2. NO crypto-condition.
//
//    XRPL escrows can require a PREIMAGE-SHA-256 fulfilment. Adding one
//    would mean a secret must survive 13 years or the funds are lost
//    forever. Time alone is the condition; nothing needs to be remembered.
//
// 3. ANYONE can submit EscrowFinish.
//
//    With no condition set, XRPL permits any account to submit EscrowFinish
//    once FinishAfter has passed — and the funds go to Destination
//    regardless of who submits it. This is a feature here, not a gap:
//    Nevaeh does not need to still hold a key in 2039 for the release to be
//    triggerable. A solicitor, a family member, or a stranger can trigger
//    it and the XRP still goes to her address.
//
//    She does need the key to SPEND it afterwards. That is what the Shamir
//    vault protects.
//
// 4. The destination account must already exist and be funded with the
//    XRPL base reserve before the escrow is created, or EscrowFinish will
//    fail in 2039 with tecNO_DST. Checked below at creation time rather
//    than discovered thirteen years later.
// ═══════════════════════════════════════════════════════════════════════

use crate::attestation::{Attestation, QLockAttestor};
use godshield_core::GodKeyPair;
use serde::{Deserialize, Serialize};

/// Ripple epoch offset: seconds between the Unix epoch and 2000-01-01.
const RIPPLE_EPOCH_OFFSET: i64 = 946_684_800;

/// XRPL stores FinishAfter as a uint32 of ripple-epoch seconds, so the
/// maximum representable date is early 2136. 2039 is comfortably inside it,
/// but the check exists so a future longer lock fails loudly rather than
/// silently wrapping.
const RIPPLE_TIME_MAX: i64 = u32::MAX as i64;

/// Minimum XRP that must already sit in the destination account for it to
/// exist on-ledger. XRPL's base reserve has changed over time and can
/// change again by amendment — this is a floor for the pre-flight check,
/// not a protocol constant.
const MIN_DESTINATION_BALANCE_DROPS: u64 = 1_000_000; // 1 XRP

#[derive(Debug, thiserror::Error)]
pub enum InheritanceError {
    #[error("unlock date is in the past — an escrow that is already finishable provides no lock")]
    UnlockInPast,
    #[error("unlock date exceeds XRPL's representable range (max ~2136)")]
    UnlockTooFar,
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error(
        "destination account {address} does not exist on-ledger or is below the base reserve. \
         Fund it before creating the escrow — otherwise EscrowFinish will fail in {year} with \
         tecNO_DST and the funds will be unreleasable."
    )]
    DestinationNotFunded { address: String, year: i32 },
    #[error("source and destination are the same account — this escrows funds to yourself")]
    SelfEscrow,
    #[error("XRPL error: {0}")]
    Xrpl(String),
    #[error("attestation failed: {0}")]
    Attestation(String),
}

/// A prepared inheritance escrow, ready to be signed by the grantor's wallet.
///
/// This struct is never signed here. It is handed to Xaman or a Ledger
/// device, exactly like every other transaction in Q-Lock — no key material
/// touches this process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InheritanceEscrow {
    pub beneficiary_name: String,
    pub beneficiary_dob: String,
    pub grantor_address: String,
    pub destination_address: String,
    pub amount_drops: u64,
    /// Ripple-epoch seconds.
    pub finish_after: u32,
    /// Human-readable, for the record and for anyone reading this in 2039.
    pub unlock_date: String,
    /// The unsigned XRPL transaction, ready for Xaman/Ledger.
    pub txjson: serde_json::Value,
    /// Post-quantum attestation over the escrow's terms. Proves the
    /// commitment was made when it was claimed, verifiable after ECDSA is
    /// broken.
    pub attestation_signature_hex: String,
    pub attestation_public_key_hex: String,
    pub attestation_timestamp: i64,
}

pub struct InheritanceBuilder;

impl InheritanceBuilder {
    /// Prepare a 13-year inheritance escrow.
    ///
    /// `destination_balance_drops` must come from a live `account_info`
    /// lookup, not from a guess. Passing `None` skips the check, which is
    /// permitted for testnet but logged loudly.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        attestation_key: &GodKeyPair,
        device_id: &str,
        beneficiary_name: &str,
        beneficiary_dob: &str,
        grantor_address: &str,
        destination_address: &str,
        amount_drops: u64,
        unlock_unix_timestamp: i64,
        destination_balance_drops: Option<u64>,
    ) -> Result<InheritanceEscrow, InheritanceError> {
        if amount_drops == 0 {
            return Err(InheritanceError::ZeroAmount);
        }
        if grantor_address == destination_address {
            return Err(InheritanceError::SelfEscrow);
        }

        let now = chrono::Utc::now().timestamp();
        if unlock_unix_timestamp <= now {
            return Err(InheritanceError::UnlockInPast);
        }

        let finish_after_i64 = unlock_unix_timestamp - RIPPLE_EPOCH_OFFSET;
        if !(0..=RIPPLE_TIME_MAX).contains(&finish_after_i64) {
            return Err(InheritanceError::UnlockTooFar);
        }
        let finish_after = finish_after_i64 as u32;

        // Pre-flight the destination. Discovering in 2039 that the account
        // was never activated is not a recoverable mistake.
        match destination_balance_drops {
            Some(balance) if balance < MIN_DESTINATION_BALANCE_DROPS => {
                let year = chrono::DateTime::from_timestamp(unlock_unix_timestamp, 0)
                    .map(|d| d.format("%Y").to_string().parse().unwrap_or(2039))
                    .unwrap_or(2039);
                return Err(InheritanceError::DestinationNotFunded {
                    address: destination_address.to_string(),
                    year,
                });
            }
            Some(_) => {}
            None => {
                tracing::warn!(
                    destination = %destination_address,
                    "Destination balance not verified. If this account is not \
                     activated on-ledger, EscrowFinish will fail when the lock \
                     expires. Verify before mainnet."
                );
            }
        }

        let unlock_date = chrono::DateTime::from_timestamp(unlock_unix_timestamp, 0)
            .map(|d| d.format("%d %B %Y").to_string())
            .unwrap_or_else(|| "unknown".into());

        // The transaction itself. Note what is ABSENT: no CancelAfter, no
        // Condition. Both omissions are deliberate — see the header.
        let txjson = serde_json::json!({
            "TransactionType": "EscrowCreate",
            "Account": grantor_address,
            "Destination": destination_address,
            "Amount": amount_drops.to_string(),
            "FinishAfter": finish_after,
            "Memos": [{
                "Memo": {
                    "MemoType": hex::encode("inheritance"),
                    "MemoData": hex::encode(format!(
                        "For {beneficiary_name} (b. {beneficiary_dob}). Releasable on or after {unlock_date}. \
                         Irrevocable — no CancelAfter is set."
                    )),
                }
            }],
        });

        // Attest to the terms with the post-quantum key. If ECDSA is broken
        // by 2039, this record still proves what was committed and when.
        // The pipe-joined `terms` string that used to be built here is
        // gone. It was:
        //
        //     format!("{}|{}|{}|{}|{}", beneficiary_name,
        //             destination_address, amount_drops, finish_after,
        //             beneficiary_dob)
        //
        // with no escaping, so a beneficiary name containing "|"
        // re-partitioned every field after it and two different escrows
        // could sign identical bytes. Same ambiguity class as NEV369's
        // old delimiter-free signing bytes, which chain.rs documents as
        // CRITICAL — and worse here, because this attests the terms of a
        // thirteen-year inheritance whose entire purpose is proving in
        // 2039 what was committed in 2026.
        //
        // attest_escrow_canonical length-prefixes each field
        // individually under `qlock.escrow.v2`, so no field value can
        // impersonate a delimiter.
        let attestation: Attestation = QLockAttestor::attest_escrow_canonical(
            attestation_key,
            beneficiary_name,
            beneficiary_dob,
            destination_address,
            amount_drops,
            u64::from(finish_after),
            "inheritance_create",
            "", // no tx hash until it is submitted
            device_id,
        )
        .map_err(|e| InheritanceError::Attestation(e.to_string()))?;

        Ok(InheritanceEscrow {
            beneficiary_name: beneficiary_name.to_string(),
            beneficiary_dob: beneficiary_dob.to_string(),
            grantor_address: grantor_address.to_string(),
            destination_address: destination_address.to_string(),
            amount_drops,
            finish_after,
            unlock_date,
            txjson,
            // Field names match attestation.rs's Attestation, which calls
            // these `dilithium_signature` and `public_key`. This file was
            // written against an earlier attestation module that named them
            // `signature_hex` / `public_key_hex`; reading those names was a
            // compile error once the module was replaced. `timestamp` is
            // u64 there and i64 here — the cast is safe for any real
            // Unix time.
            attestation_signature_hex: attestation.dilithium_signature,
            attestation_public_key_hex: attestation.public_key,
            attestation_timestamp: attestation.timestamp as i64,
        })
    }

    /// Build the EscrowFinish transaction for 2039.
    ///
    /// `owner` is the grantor's address; `offer_sequence` is the Sequence
    /// number of the EscrowCreate transaction. Both are recorded at creation
    /// time and written into the recovery document — without them the escrow
    /// cannot be finished, even though the funds are visibly on-ledger.
    ///
    /// `submitter` can be ANY funded XRPL account. The funds go to the
    /// escrow's Destination regardless of who submits this.
    pub fn prepare_finish(submitter: &str, owner: &str, offer_sequence: u32) -> serde_json::Value {
        serde_json::json!({
            "TransactionType": "EscrowFinish",
            "Account": submitter,
            "Owner": owner,
            "OfferSequence": offer_sequence,
        })
    }
}

/// Everything needed to release the escrow in 2039, in one place.
///
/// Print this. Store it with the vault files and with the will. The escrow
/// is publicly visible on-ledger, but without `offer_sequence` nobody can
/// construct the EscrowFinish transaction — the funds would be visible and
/// unreachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InheritanceRecord {
    pub beneficiary_name: String,
    pub beneficiary_dob: String,
    pub destination_address: String,
    pub grantor_address: String,
    /// REQUIRED for EscrowFinish. Recorded once the EscrowCreate validates.
    pub offer_sequence: u32,
    pub create_tx_hash: String,
    pub amount_drops: u64,
    pub finish_after_ripple: u32,
    pub unlock_date: String,
    pub network: String,
    pub attestation_signature_hex: String,
    pub attestation_public_key_hex: String,
    pub recovery_instructions: String,
}

impl InheritanceRecord {
    pub fn new(
        escrow: &InheritanceEscrow,
        offer_sequence: u32,
        create_tx_hash: &str,
        network: &str,
    ) -> Self {
        Self {
            beneficiary_name: escrow.beneficiary_name.clone(),
            beneficiary_dob: escrow.beneficiary_dob.clone(),
            destination_address: escrow.destination_address.clone(),
            grantor_address: escrow.grantor_address.clone(),
            offer_sequence,
            create_tx_hash: create_tx_hash.to_string(),
            amount_drops: escrow.amount_drops,
            finish_after_ripple: escrow.finish_after,
            unlock_date: escrow.unlock_date.clone(),
            network: network.to_string(),
            attestation_signature_hex: escrow.attestation_signature_hex.clone(),
            attestation_public_key_hex: escrow.attestation_public_key_hex.clone(),
            recovery_instructions: recovery_text(
                &escrow.beneficiary_name,
                &escrow.unlock_date,
                &escrow.grantor_address,
                offer_sequence,
                &escrow.destination_address,
            ),
        }
    }

    pub fn amount_xrp(&self) -> f64 {
        self.amount_drops as f64 / 1_000_000.0
    }
}

/// Written for someone in 2039 with no crypto knowledge. Assume the person
/// reading it has never used a wallet and has never heard of Q-Lock.
/// Plain-English recovery instructions. Public so `qlock-inheritance record`
/// can regenerate them once the real OfferSequence is known — a record
/// carrying the placeholder 0 would tell someone in 2039 to submit an
/// EscrowFinish that can never succeed.
pub fn recovery_text(
    beneficiary: &str,
    unlock_date: &str,
    owner: &str,
    offer_sequence: u32,
    destination: &str,
) -> String {
    format!(
        "HOW TO RELEASE THESE FUNDS — on or after {unlock_date}\n\
         \n\
         WHAT THIS IS\n\
         A sum of XRP was locked on the XRP Ledger for {beneficiary}. It could \
         not be moved by anyone, including the person who locked it, until \
         {unlock_date}. That date has now passed or is close.\n\
         \n\
         WHO CAN DO THIS\n\
         Anyone. You do not need to be {beneficiary} and you do not need their \
         keys. The funds can only ever go to their address ({destination}) — \
         whoever submits the release transaction simply pays the network fee \
         (a fraction of a penny) and the XRP goes to them.\n\
         \n\
         WHAT YOU NEED\n\
         Any funded XRP Ledger account to submit from, and these two values:\n\
         \n\
           Owner:         {owner}\n\
           OfferSequence: {offer_sequence}\n\
         \n\
         Both are essential. Without OfferSequence the escrow cannot be \
         released even though it is publicly visible.\n\
         \n\
         HOW\n\
         Submit an EscrowFinish transaction:\n\
         \n\
           {{\n\
             \"TransactionType\": \"EscrowFinish\",\n\
             \"Account\": \"<any funded account you control>\",\n\
             \"Owner\": \"{owner}\",\n\
             \"OfferSequence\": {offer_sequence}\n\
           }}\n\
         \n\
         Any XRPL wallet or a developer can do this in minutes. The XRP will \
         arrive at {destination}.\n\
         \n\
         THEN WHAT\n\
         To SPEND the funds, {beneficiary} needs the key to that address. It \
         was split into five pieces held by five guardians — see the vault \
         file and docs/nevaeh-vault-ceremony.md. Any three pieces rebuild it.\n\
         \n\
         IF SOMETHING IS WRONG\n\
         Look up the address on any XRP Ledger explorer (xrpscan.com, \
         bithomp.com). The escrow is public and always has been. If it shows \
         as already finished, the funds have been released — check the \
         destination's balance and transaction history."
    )
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const NEVAEH_UNLOCK: i64 = 2_195_424_000; // 2039-07-28 00:00:00 UTC

    fn key() -> GodKeyPair {
        GodKeyPair::generate().unwrap()
    }

    fn prepare(
        amount: u64,
        unlock: i64,
        dest_balance: Option<u64>,
    ) -> Result<InheritanceEscrow, InheritanceError> {
        InheritanceBuilder::prepare(
            &key(),
            "test-device",
            "Nevaeh",
            "2021-07-28",
            "rGrantorAddressForTesting1234567",
            "rNevaehDestinationAddress9876543",
            amount,
            unlock,
            dest_balance,
        )
    }

    #[test]
    fn ripple_epoch_conversion_is_correct() {
        let e = prepare(1_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        assert_eq!(e.finish_after as i64, NEVAEH_UNLOCK - RIPPLE_EPOCH_OFFSET);
        assert_eq!(e.finish_after, 1_248_739_200);
    }

    #[test]
    fn unlock_date_renders_as_nevaehs_18th_birthday() {
        let e = prepare(1_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        assert!(e.unlock_date.contains("2039"));
        assert!(e.unlock_date.contains("28"));
        assert!(e.unlock_date.contains("July"));
    }

    /// The single most important property. If CancelAfter were present, the
    /// grantor could reclaim the gift — which is the whole thing this is
    /// meant to prevent.
    #[test]
    fn no_cancel_after_is_set() {
        let e = prepare(1_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        assert!(
            e.txjson.get("CancelAfter").is_none(),
            "CancelAfter must never be set — it would give the grantor a path \
             to reclaim the inheritance"
        );
    }

    /// A crypto-condition would mean a secret must survive 13 years or the
    /// funds are lost forever. Time alone is the condition.
    #[test]
    fn no_crypto_condition_is_set() {
        let e = prepare(1_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        assert!(e.txjson.get("Condition").is_none());
    }

    #[test]
    fn transaction_is_a_well_formed_escrow_create() {
        let e = prepare(5_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        assert_eq!(e.txjson["TransactionType"], "EscrowCreate");
        assert_eq!(e.txjson["Amount"], "5000000");
        assert_eq!(e.txjson["FinishAfter"], e.finish_after);
        assert!(e.txjson["Destination"].is_string());
    }

    #[test]
    fn past_unlock_date_is_rejected() {
        assert!(matches!(
            prepare(1_000_000, 1, Some(10_000_000)),
            Err(InheritanceError::UnlockInPast)
        ));
    }

    #[test]
    fn unlock_beyond_ripple_range_is_rejected() {
        // Year ~2200 — beyond XRPL's uint32 ripple-time range.
        assert!(matches!(
            prepare(1_000_000, 7_000_000_000, Some(10_000_000)),
            Err(InheritanceError::UnlockTooFar)
        ));
    }

    #[test]
    fn zero_amount_is_rejected() {
        assert!(matches!(
            prepare(0, NEVAEH_UNLOCK, Some(10_000_000)),
            Err(InheritanceError::ZeroAmount)
        ));
    }

    /// An unfunded destination means EscrowFinish fails with tecNO_DST
    /// in 2039. Catching it now is the difference between a fixable mistake
    /// and a permanent one.
    #[test]
    fn unfunded_destination_is_rejected_at_creation() {
        assert!(matches!(
            prepare(1_000_000, NEVAEH_UNLOCK, Some(0)),
            Err(InheritanceError::DestinationNotFunded { .. })
        ));
    }

    #[test]
    fn escrowing_to_yourself_is_rejected() {
        let r = InheritanceBuilder::prepare(
            &key(),
            "d",
            "Nevaeh",
            "2021-07-28",
            "rSameAddress123",
            "rSameAddress123",
            1_000_000,
            NEVAEH_UNLOCK,
            Some(10_000_000),
        );
        assert!(matches!(r, Err(InheritanceError::SelfEscrow)));
    }

    #[test]
    fn attestation_is_produced_and_bound_to_terms() {
        let e = prepare(1_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        assert!(!e.attestation_signature_hex.is_empty());
        // Dilithium5 public key = 2592 bytes = 5184 hex chars.
        assert_eq!(e.attestation_public_key_hex.len(), 5184);
    }

    #[test]
    fn finish_transaction_is_well_formed() {
        let tx = InheritanceBuilder::prepare_finish("rAnyone123", "rGrantor456", 42);
        assert_eq!(tx["TransactionType"], "EscrowFinish");
        assert_eq!(tx["Owner"], "rGrantor456");
        assert_eq!(tx["OfferSequence"], 42);
    }

    #[test]
    fn recovery_record_contains_the_offer_sequence() {
        let e = prepare(36_900_000_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        let record = InheritanceRecord::new(&e, 7, "0xTXHASH", "mainnet");

        assert_eq!(record.offer_sequence, 7);
        assert!(
            record.recovery_instructions.contains("OfferSequence"),
            "without this value the escrow is visible but unreleasable"
        );
        assert!(record.recovery_instructions.contains("Anyone"));
        assert_eq!(record.amount_xrp(), 36_900_000.0);
    }

    #[test]
    fn memo_records_irrevocability() {
        let e = prepare(1_000_000, NEVAEH_UNLOCK, Some(10_000_000)).unwrap();
        let memo_hex = e.txjson["Memos"][0]["Memo"]["MemoData"].as_str().unwrap();
        let memo = String::from_utf8(hex::decode(memo_hex).unwrap()).unwrap();
        assert!(memo.contains("Irrevocable"));
        assert!(memo.contains("Nevaeh"));
    }
}
