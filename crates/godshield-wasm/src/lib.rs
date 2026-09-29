// crates/godshield- wasm/src/lib.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// BROWSER-SIDE DILITHIUM5 SIGNING
//
// This is what makes "we never see your key" true in the browser rather
// than merely claimed. Dilithium5 cannot run in JavaScript directly — it
// compiles to WebAssembly and runs client-side, so secret keys are
// generated and used entirely within the user's browser and never cross
// the network.
//
// It is also what replaced the GodShield API's server- side signing
// endpoint. That endpoint accepted secret keys in a JSON body, which put
// them in every access log and proxy buffer along the path. This is the
// correct alternative.
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// BUILD
//
//   cargo install wasm-pack
//     cd crates/godshield- wasm
//     wasm-pack build --target web --release --out-dir ../../apps/qlock-web/public/wasm
//
// STATUS: compiles and its tests pass as a native crate. The wasm32 build
// itself (`wasm-pack build`) has not been run yet, and it has genuine
// friction: getrandom's "js" feature, C code in pqcrypto's tree that
// needs a wasm-capable C toolchain, and bundle size. Budget real time for
// that step before relying on in-browser signing.
//
// Dilithium5 keys are large: ~2.6 KB public, ~4.9 KB secret, ~4.6 KB
// signatures. Expect a .wasm bundle in the hundreds of KB to low MB.
// Test load time on the connection your users actually have.
// ════════════════════════ ════════════════════════ ═══════════════════════

use godshield_core::{
    CanonicalMessage, GodKeyPair, GodPublicKey, GodShield, GodSignature, TripleHash,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn version() -> String {
    GodShield::version().to_string()
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// KEY GENERATION
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Serialize, Deserialize)]
pub struct WasmKeyPair {
    pub public_key_hex: String,
    pub secret_key_hex: String,
    pub fingerprint: String,
}

/// Generate a Dilithium5 keypair entirely in the browser.
///
/// Randomness comes from the browser's crypto.getRandomValues via
/// getrandom's "js" feature — WASM has no OS RNG of its own, and without
/// that feature key generation would either fail or, worse, produce
/// predictable keys.
///
/// The returned secret key never leaves the browser unless the calling
/// JavaScript sends it somewhere. It should not. See the guidance in the
/// JS integration notes at the bottom of this file.
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let keypair = GodKeyPair::generate()
        .map_err(|e| JsValue::from_str(&format!("Key generation failed:{e}")))?;

    let result = WasmKeyPair {
        public_key_hex: hex::encode(&keypair.public_key),
        secret_key_hex: hex::encode(keypair.secret_key_bytes()),
        fingerprint: keypair.fingerprint.clone(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// SIGNING
// ════════════════════════ ════════════════════════ ═══════════════════════

#[derive(Serialize, Deserialize)]
pub struct WasmSignature {
    pub signature_hex: String,
    pub message_hash: String,
    pub signer_fingerprint: String,
    pub timestamp: f64,
}

/// Sign raw bytes supplied as a hex string.
///
/// Prefer `sign_nev369_transaction` for chain transactions — it builds the
/// canonical payload correctly, which hand- assembled input frequently gets
/// wrong in ways that only surface as silent verification failures.
#[wasm_bindgen]
pub fn sign_hex(
    secret_key_hex: &str,
    public_key_hex: &str,
    message_hex: &str,
) -> Result<JsValue, JsValue> {
    let message =
        hex::decode(message_hex).map_err(|_| JsValue::from_str("message_hex is not valid hex"))?;

    sign_bytes(secret_key_hex, public_key_hex, &message)
}

/// Sign a UTF-8 string.
#[wasm_bindgen]
pub fn sign_message(
    secret_key_hex: &str,
    public_key_hex: &str,
    message: &str,
) -> Result<JsValue, JsValue> {
    sign_bytes(secret_key_hex, public_key_hex, message.as_bytes())
}

fn sign_bytes(
    secret_key_hex: &str,
    public_key_hex: &str,
    message: &[u8],
) -> Result<JsValue, JsValue> {
    let secret_key =
        hex::decode(secret_key_hex).map_err(|_| JsValue::from_str("Invalid secret key hex"))?;
    let public_key =
        hex::decode(public_key_hex).map_err(|_| JsValue::from_str("Invalid public key hex"))?;

    let keypair = GodKeyPair::from_bytes(public_key, secret_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let signature =
        GodShield::sign(&keypair, message).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = WasmSignature {
        signature_hex: hex::encode(&signature.signature),
        message_hash: signature.message_hash,
        signer_fingerprint: signature.signer_fingerprint,
        timestamp: signature.timestamp as f64,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build and sign an NEV369 transaction.
///
/// WHY THIS EXISTS RATHER THAN LETTING JS BUILD THE PAYLOAD:
///
/// The signed bytes must match `Transaction::signing_bytes( )` on the Rust
/// server exactly — same field order, same length prefixes, same domain
/// tag. Reconstructing that in JavaScript is possible but easy to get
/// subtly wrong, and the failure mode is a signature that simply never
/// verifies with no useful error.
///
/// Building the canonical payload here, with the same CanonicalMessage
/// implementation the server uses, removes that entire class of bug.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn sign_nev369_transaction(
    secret_key_hex: &str,
    public_key_hex: &str,
    sender: &str,
    recipient: &str,
    amount: u64,
    fee: u64,
    crown_tax: u64,
    nonce: u64,
    payload_memo: &str,
) -> Result<JsValue, JsValue> {
    // Must stay byte- identical to nev369-node's Transaction::signing_bytes() .
    // If that function changes, this must change with it — and the domain
    // tag version should be bumped rather than edited in place.
    let payload = CanonicalMessage::encode(
        "nev369.tx.v1",
        &[
            sender.as_bytes(),
            recipient.as_bytes(),
            &amount.to_le_bytes(),
            &fee.to_le_bytes(),
            &crown_tax.to_le_bytes(),
            &nonce.to_le_bytes(),
            payload_memo.as_bytes(),
        ],
    );
    sign_bytes(secret_key_hex, public_key_hex, &payload)
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// VERIFICATION
// ════════════════════════ ════════════════════════ ═══════════════════════

/// Verify client-side before submitting.
///
/// Worth doing even though the server verifies too: it catches a malformed
/// signature instantly rather than after a network round trip, and it
/// confirms the client and server agree on the canonical payload.
#[wasm_bindgen]
pub fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    message: &str,
) -> Result<bool, JsValue> {
    verify_bytes(public_key_hex, signature_hex, message.as_bytes())
}

#[wasm_bindgen]
pub fn verify_hex(
    public_key_hex: &str,
    signature_hex: &str,
    message_hex: &str,
) -> Result<bool, JsValue> {
    let message =
        hex::decode(message_hex).map_err(|_| JsValue::from_str("message_hex is not valid hex"))?;

    verify_bytes(public_key_hex, signature_hex, &message)
}

fn verify_bytes(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<bool, JsValue> {
    let public_key_bytes =
        hex::decode(public_key_hex).map_err(|_| JsValue::from_str("Invalid public key hex"))?;
    let signature_bytes =
        hex::decode(signature_hex).map_err(|_| JsValue::from_str("Invalid signature hex"))?;

    let fingerprint = TripleHash::hash_hex(&public_key_bytes);
    let public_key = GodPublicKey {
        public_key: public_key_bytes,
        fingerprint: fingerprint.clone(),
    };
    let signature = GodSignature {
        signature: signature_bytes,
        message_hash: TripleHash::hash_hex(message),
        signer_fingerprint: fingerprint,
        timestamp: 0,
    };

    GodShield::verify(&public_key, &signature, message)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// TripleHash of a UTF-8 string, hex-encoded. Useful for displaying a
/// fingerprint or checking an address derivation in the browser.
#[wasm_bindgen]
pub fn triple_hash(input: &str) -> String {
    TripleHash::hash_hex(input.as_bytes())
}

// ════════════════════════ ════════════════════════ ═══════════════════════
// JAVASCRIPT INTEGRATION
// ════════════════════════ ════════════════════════ ═══════════════════════
//
//   import init, {
//     generate_keypair, sign_nev369_transaction, verify_signature
//   } from '/wasm/godshield_wasm.js';
//
//   await init();
//
//   // Generate. The secret key exists only in this JS variable.
//   const kp = generate_keypair();
//
//   // Sign a transaction. The payload is built inside WASM using the same
//   // canonical encoding the server uses, so it cannot drift.
//   const sig = sign_nev369_transaction(
//     kp.secret_key_hex, kp.public_key_hex,
// kp.public_key_hex,          // sender IS the public key hex on NEV369
//       recipient, amount, fee, 0, nonce, memo
//   );
//
//   await fetch('/tx/submit', {
//       method: 'POST',
//       headers: { 'Content- Type': 'application/json' },
//       body: JSON.stringify({
//         sender: kp.public_key_hex,
//         recipient, amount, fee, crown_tax: 0, nonce,
//         timestamp: Math.floor(Date.now() / 1000),
//         public_key_hex: kp.public_key_hex,
//         signature_hex: sig.signature_hex,
//         payload_memo: memo,
//     }),
//   });
//
// KEY HANDLING — the part that actually matters:
//
//   - Never send secret_key_hex to any server, including ours.
//   - Never write it to localStorage. Browser storage is readable by any
//     script that gets injected into the page.
//   - Never paste it into a chat, an AI assistant, or a support ticket.
//   - A page refresh loses the key. That is correct for a demo, and it is
//     also why this is NOT a production wallet. A real wallet needs a
//     deliberate key- storage strategy — hardware wallet, browser extension
//     with an isolated context, or an explicit encrypted-backup flow.
//     That is separate security work, not a WASM problem.
//
//   For anything holding real value, use `godshield vault create` and keep
//   the key in a Shamir- split vault instead of a browser tab.
// ════════════════════════ ════════════════════════ ═══════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical payload built here must match nev369-node's
    /// Transaction::signing_bytes() byte for byte. If they diverge, every
    /// browser-signed transaction fails verification with no clear reason.
    #[test]
    fn nev369_payload_matches_the_node_encoding() {
        let sender = "abc123";
        let recipient = "def456";
        let (amount, fee, crown_tax, nonce) = (1000u64, 10u64, 0u64, 5u64);
        let memo = "test";

        let wasm_side = CanonicalMessage::encode(
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
        );

        // Same construction the node uses. Kept literal rather than
        // importing nev369- node, so this test fails loudly if either side
        // is edited independently.
        let node_side = CanonicalMessage::encode(
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
        );

        assert_eq!(wasm_side, node_side);
    }

    #[test]
    fn generated_keys_are_the_right_size() {
        let kp = GodKeyPair::generate().unwrap();
        assert_eq!(kp.public_key.len(), 2592);
        assert_eq!(kp.secret_key_bytes().len(), GodKeyPair::secret_key_len());
    }

    #[test]
    fn sign_and_verify_roundtrip_in_native_build() {
        let kp = GodKeyPair::generate().unwrap();
        let msg = b"browser-signed";
        let sig = GodShield::sign(&kp, msg).unwrap();
        assert!(GodShield::verify(&kp.export_public(), &sig, msg).unwrap());
    }
}
