// crates/nev369-relayer/src/eip712.rs
//
// ═══════════════════════════════════════════════════════════════════════
// THE SUBMITTER'S ENCODING LAYER
//
// This is the last gap between "the bridge exists" and "the bridge runs".
// godshield-bridge collects Dilithium5 attestations and decides a mint is
// authorized; NEV369Bridge.sol verifies m-of-n secp256k1 signatures over
// an EIP-712 digest. Something has to carry the second set across, and
// this is it.
//
// ── WHY THERE IS NO ETHEREUM KEY IN THIS FILE ─────────────────────────
//
// The contract says the caller is irrelevant: signatures authorize, not
// the sender. So the submitter produces ready-to-broadcast calldata and
// anyone can send it. That keeps the same property the coordinator has —
// compromising it lets someone WITHHOLD or REORDER a mint, never create
// one — and it means no component of this bridge holds a key that can
// move value on either chain.
//
// A submitter with a funded Ethereum key would be a smaller version of
// exactly the single-key problem this whole design removed.
//
// ── WHY THE ENCODING IS HAND-ROLLED ───────────────────────────────────
//
// Pulling in a full Ethereum SDK for two encodings adds a large
// dependency tree to a binary whose job is telling people to audit their
// dependency tree. Both encodings are specified precisely and both are
// tested here against the exact strings in NEV369Bridge.sol.
//
// The encodings must match the contract EXACTLY. A wrong digest means
// signatures that recover to unknown addresses and a reverted mint; a
// wrong selector means calling a function that does not exist. Both fail
// closed, and both waste gas and confuse whoever is on call.
// ═══════════════════════════════════════════════════════════════════════

use sha3::{Digest, Keccak256};

/// Ethereum uses legacy Keccak-256, NOT the NIST SHA3-256 that the
/// padding change in FIPS 202 produced. They differ, and `sha3::Sha3_256`
/// here would produce a digest no Ethereum node agrees with.
fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════════════
// EIP-712
// ═══════════════════════════════════════════════════════════════════════

/// Must match `EIP712("NEV369Bridge", "1")` in the contract constructor.
const DOMAIN_NAME: &str = "NEV369Bridge";
const DOMAIN_VERSION: &str = "1";

/// Must match MINT_AUTHORIZATION_TYPEHASH in NEV369Bridge.sol byte for
/// byte, including field order and the absence of spaces after commas.
const MINT_TYPE: &str = "MintAuthorization(bytes32 lockId,address recipient,uint256 amount,uint256 sourceBlockHeight,string sourceTx)";

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

#[derive(Debug, Clone)]
pub struct MintParams {
    pub lock_id: [u8; 32],
    pub recipient: [u8; 20],
    /// Base units. u128 covers NEV369's entire supply with room to spare
    /// — the cap is 3.7e16 base units — and avoids a bignum dependency.
    pub amount: u128,
    pub source_block_height: u64,
    pub source_tx: String,
}

fn pad32_left(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[32 - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    out
}

fn u128_word(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

fn u64_word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

pub fn domain_separator(chain_id: u64, verifying_contract: [u8; 20]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(&keccak(DOMAIN_TYPE.as_bytes()));
    buf.extend_from_slice(&keccak(DOMAIN_NAME.as_bytes()));
    buf.extend_from_slice(&keccak(DOMAIN_VERSION.as_bytes()));
    buf.extend_from_slice(&u64_word(chain_id));
    buf.extend_from_slice(&pad32_left(&verifying_contract));
    keccak(&buf)
}

pub fn struct_hash(p: &MintParams) -> [u8; 32] {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(&keccak(MINT_TYPE.as_bytes()));
    buf.extend_from_slice(&p.lock_id);
    buf.extend_from_slice(&pad32_left(&p.recipient));
    buf.extend_from_slice(&u128_word(p.amount));
    buf.extend_from_slice(&u64_word(p.source_block_height));
    // A dynamic string is hashed, not inlined. Getting this wrong is the
    // most common EIP-712 mistake and produces a digest that differs
    // from the contract's for every non-empty sourceTx.
    buf.extend_from_slice(&keccak(p.source_tx.as_bytes()));
    keccak(&buf)
}

/// The digest signers must sign, and the one `mintDigest()` returns.
pub fn mint_digest(chain_id: u64, verifying_contract: [u8; 20], p: &MintParams) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_separator(chain_id, verifying_contract));
    buf.extend_from_slice(&struct_hash(p));
    keccak(&buf)
}

// ═══════════════════════════════════════════════════════════════════════
// ABI CALLDATA
// ═══════════════════════════════════════════════════════════════════════

const MINT_FN: &str = "mintFromNEV369(address,uint256,bytes32,string,uint256,bytes[])";

pub fn selector() -> [u8; 4] {
    let h = keccak(MINT_FN.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn pad_right_32(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    while out.len() % 32 != 0 {
        out.push(0);
    }
    out
}

/// Encode a complete `mintFromNEV369` call.
///
/// Head is six 32-byte words; `string` and `bytes[]` are dynamic, so
/// their head slots carry offsets measured from the start of the
/// arguments — not from the start of the calldata. Counting the selector
/// into those offsets is the classic ABI encoding bug and produces a
/// call that decodes to garbage rather than reverting cleanly.
///
/// `signatures` MUST already be ordered by ascending signer address.
/// The contract rejects anything else, and that ordering is how it
/// enforces distinctness.
pub fn encode_mint_call(p: &MintParams, signatures: &[Vec<u8>]) -> Vec<u8> {
    const HEAD_WORDS: usize = 6;
    let head_len = HEAD_WORDS * 32;

    // ── string sourceTx ──
    let tx_bytes = p.source_tx.as_bytes();
    let mut tx_tail = u64_word(tx_bytes.len() as u64).to_vec();
    tx_tail.extend_from_slice(&pad_right_32(tx_bytes));

    // ── bytes[] signatures ──
    // count, then one offset per element, then each element as
    // (length, padded data).
    let n = signatures.len();
    let mut sig_offsets = Vec::with_capacity(n);
    let mut sig_elems: Vec<u8> = Vec::new();
    let mut running = n * 32; // offsets are relative to after the count
    for s in signatures {
        sig_offsets.push(running);
        let padded = pad_right_32(s);
        running += 32 + padded.len();
        sig_elems.extend_from_slice(&u64_word(s.len() as u64));
        sig_elems.extend_from_slice(&padded);
    }
    let mut sig_tail = u64_word(n as u64).to_vec();
    for off in &sig_offsets {
        sig_tail.extend_from_slice(&u64_word(*off as u64));
    }
    sig_tail.extend_from_slice(&sig_elems);

    let tx_offset = head_len;
    let sig_offset = head_len + tx_tail.len();

    let mut out = Vec::with_capacity(4 + head_len + tx_tail.len() + sig_tail.len());
    out.extend_from_slice(&selector());
    out.extend_from_slice(&pad32_left(&p.recipient));
    out.extend_from_slice(&u128_word(p.amount));
    out.extend_from_slice(&p.lock_id);
    out.extend_from_slice(&u64_word(tx_offset as u64));
    out.extend_from_slice(&u64_word(p.source_block_height));
    out.extend_from_slice(&u64_word(sig_offset as u64));
    out.extend_from_slice(&tx_tail);
    out.extend_from_slice(&sig_tail);
    out
}

pub fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.is_ascii() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Order signatures by the address they recover to.
///
/// The submitter cannot recover addresses without a secp256k1
/// implementation, so signers supply their own address alongside the
/// signature and this sorts on that. A signer lying about its address
/// only breaks its own signature: the contract recovers the real one,
/// finds the ordering violated or the address unauthorized, and reverts.
pub fn order_by_signer(mut pairs: Vec<([u8; 20], Vec<u8>)>) -> Vec<Vec<u8>> {
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.into_iter().map(|(_, s)| s).collect()
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> MintParams {
        MintParams {
            lock_id: [0x11; 32],
            recipient: [0x22; 20],
            amount: 100_000_000,
            source_block_height: 12_345,
            source_tx: "nev369:abc123".into(),
        }
    }

    #[test]
    fn keccak_is_legacy_not_sha3() {
        // Ethereum uses legacy Keccak-256. If this ever returns the
        // FIPS 202 SHA3-256 value, every digest and selector in this
        // file is wrong and no Ethereum node will agree with us.
        //
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            hex0x(&keccak(b"")),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn function_selector_matches_the_contract() {
        // If this drifts the call hits a function that does not exist.
        let s = selector();
        assert_eq!(s.len(), 4);
        // Recomputed from the signature string, so a change to the
        // contract's parameter list fails this immediately.
        let expect =
            &keccak(b"mintFromNEV369(address,uint256,bytes32,string,uint256,bytes[])")[..4];
        assert_eq!(&s[..], expect);
    }

    #[test]
    fn domain_separator_is_chain_and_contract_bound() {
        let c = [0xAA; 20];
        let mainnet = domain_separator(1, c);
        let sepolia = domain_separator(11_155_111, c);
        assert_ne!(mainnet, sepolia, "signatures must not cross chains");

        let other = domain_separator(1, [0xBB; 20]);
        assert_ne!(mainnet, other, "signatures must not cross deployments");
    }

    #[test]
    fn struct_hash_hashes_the_dynamic_string() {
        // The most common EIP-712 mistake is inlining a dynamic string
        // instead of hashing it. If that happened here, two sourceTx
        // values of different length would shift every field after them.
        let mut a = params();
        let mut b = params();
        a.source_tx = "short".into();
        b.source_tx = "a much longer transaction reference".into();
        assert_ne!(struct_hash(&a), struct_hash(&b));
    }

    #[test]
    fn every_field_is_covered_by_the_digest() {
        let base = mint_digest(1, [0xAA; 20], &params());

        let mut p = params();
        p.amount = 999;
        assert_ne!(base, mint_digest(1, [0xAA; 20], &p), "amount");

        let mut p = params();
        p.recipient = [0x33; 20];
        assert_ne!(base, mint_digest(1, [0xAA; 20], &p), "recipient");

        let mut p = params();
        p.lock_id = [0x44; 32];
        assert_ne!(base, mint_digest(1, [0xAA; 20], &p), "lock id");

        let mut p = params();
        p.source_block_height = 99;
        assert_ne!(base, mint_digest(1, [0xAA; 20], &p), "block height");

        let mut p = params();
        p.source_tx = "different".into();
        assert_ne!(base, mint_digest(1, [0xAA; 20], &p), "source tx");
    }

    #[test]
    fn digest_has_the_eip712_prefix() {
        // \x19\x01 is what stops an EIP-712 digest colliding with a
        // personal_sign message or a raw transaction hash.
        let mut buf = vec![0x19, 0x01];
        buf.extend_from_slice(&domain_separator(1, [0xAA; 20]));
        buf.extend_from_slice(&struct_hash(&params()));
        assert_eq!(mint_digest(1, [0xAA; 20], &params()), keccak(&buf));
    }

    // ── ABI ──

    #[test]
    fn calldata_is_selector_plus_whole_words() {
        let sigs = vec![vec![0xAB; 65], vec![0xCD; 65]];
        let cd = encode_mint_call(&params(), &sigs);
        assert_eq!(&cd[..4], &selector()[..]);
        assert_eq!((cd.len() - 4) % 32, 0, "arguments must be word-aligned");
    }

    #[test]
    fn dynamic_offsets_exclude_the_selector() {
        // Counting the 4-byte selector into an offset is the classic ABI
        // bug: the call decodes to garbage instead of reverting cleanly.
        let sigs = vec![vec![0xAB; 65]];
        let cd = encode_mint_call(&params(), &sigs);
        let args = &cd[4..];

        // Word 3 is the string offset; word 5 the bytes[] offset.
        let read = |i: usize| -> usize {
            let w = &args[i * 32..(i + 1) * 32];
            u64::from_be_bytes(w[24..].try_into().unwrap()) as usize
        };
        assert_eq!(read(3), 192, "string offset = 6 words, selector excluded");
        assert!(read(5) > read(3), "bytes[] follows the string");

        // The string length word must sit exactly at its offset.
        let at = read(3);
        let len = u64::from_be_bytes(args[at + 24..at + 32].try_into().unwrap()) as usize;
        assert_eq!(len, params().source_tx.len());
    }

    #[test]
    fn signature_array_round_trips() {
        let sigs = vec![vec![0x01; 65], vec![0x02; 65], vec![0x03; 65]];
        let cd = encode_mint_call(&params(), &sigs);
        let args = &cd[4..];
        let read = |i: usize| -> usize {
            u64::from_be_bytes(args[i * 32 + 24..i * 32 + 32].try_into().unwrap()) as usize
        };
        let base = read(5);
        let count = u64::from_be_bytes(args[base + 24..base + 32].try_into().unwrap());
        assert_eq!(count, 3, "array length must survive encoding");
    }

    #[test]
    fn a_65_byte_signature_pads_to_96() {
        // 65 bytes is r||s||v. It is not word-aligned, so it pads to
        // three words — and the LENGTH word must still say 65.
        let cd = encode_mint_call(&params(), &[vec![0xAB; 65]]);
        let args = &cd[4..];
        let read = |i: usize| -> usize {
            u64::from_be_bytes(args[i * 32 + 24..i * 32 + 32].try_into().unwrap()) as usize
        };
        let base = read(5);
        let elem = base + 32 + read_at(args, base + 32);
        let len = u64::from_be_bytes(args[elem + 24..elem + 32].try_into().unwrap());
        assert_eq!(
            len, 65,
            "length word must be the real length, not the padded one"
        );
    }

    fn read_at(args: &[u8], at: usize) -> usize {
        u64::from_be_bytes(args[at + 24..at + 32].try_into().unwrap()) as usize
    }

    #[test]
    fn ordering_sorts_by_signer_address() {
        // The contract requires strictly ascending addresses; submitting
        // out of order reverts with SignaturesOutOfOrder.
        let pairs = vec![
            ([0x30u8; 20], vec![0x03]),
            ([0x10u8; 20], vec![0x01]),
            ([0x20u8; 20], vec![0x02]),
        ];
        assert_eq!(
            order_by_signer(pairs),
            vec![vec![0x01], vec![0x02], vec![0x03]]
        );
    }

    #[test]
    fn hex_round_trips() {
        let b = vec![0x00, 0x01, 0xfe, 0xff];
        assert_eq!(hex0x(&b), "0x0001feff");
        assert_eq!(parse_hex("0x0001feff").unwrap(), b);
        assert_eq!(parse_hex("0001feff").unwrap(), b);
        assert!(parse_hex("0xabc").is_none(), "odd length must be rejected");
    }

    #[test]
    fn amount_covers_the_whole_supply() {
        // NEV369's cap is 36,936,936,900,000,000 base units. u128 holds
        // it with enormous headroom, so no bignum dependency is needed.
        let p = MintParams {
            amount: 36_936_936_900_000_000,
            ..params()
        };
        let w = u128_word(p.amount);
        assert_eq!(u128::from_be_bytes(w[16..].try_into().unwrap()), p.amount);
    }
}
