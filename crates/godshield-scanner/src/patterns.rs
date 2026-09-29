// crates/godshield-scanner/src/patterns.rs
//
// ═══════════════════════════════════════════════════════════════════════
// THE PATTERN TABLE
//
// The previous table lived in godshield-adapters and had seven entries
// matched with `line.to_lowercase().contains(pattern)`. Both halves of
// that were wrong.
//
// ── SUBSTRING MATCHING PRODUCED FALSE CRITICALS ───────────────────────
//
// "RSA" is three letters that appear inside ordinary English. Running
// the old logic over representative lines:
//
//   RSA   fn walk(dir: &Path) { /* tree traversal */ }
//   RSA   let adversary_model = ThreatModel::Hndl;
//   RSA   pub const UNIVERSAL_TIMEOUT: u64 = 30;
//   RSA   let reversal = items.iter().rev();
//   RSA   let parsable = serde_json::from_str::<Config>(&s).is_ok();
//
// t-r-a-v-e-[r-s-a]-l. Every one of those is reported CRITICAL, and
// "traversal" and "adversary" are words that appear constantly in
// security code — including in GodShield's own comments and in this
// repository's own security-guard script. A scanner that screams
// CRITICAL at the word "adversary" gets muted, and then it catches
// nothing at all. That is the actual failure: not the noise, the muting.
//
// ── AND MISSED REAL PRIMITIVES ────────────────────────────────────────
//
// Same logic, lines it called clean:
//
//   clean  use p256::NistP256;              // P-256, written as p256
//   clean  use bls12_381::G1Projective;     // pairing curve, Shor-broken
//
// The pattern was the literal string "P-256". The RustCrypto crate is
// `p256`, the OpenSSL name is `prime256v1`, the SEC name is `secp256r1`.
// Three spellings of one curve, one of them matched.
//
// bls12-381 and bn254 are absent entirely. Both are discrete-log based,
// both break completely under Shor, and both are everywhere in ZK and
// rollup code — exactly the kind of codebase someone runs this tool
// against.
//
// ── HOW MATCHING WORKS NOW ────────────────────────────────────────────
//
// Identifier-boundary matching, CamelCase aware. A candidate match is
// kept only if:
//
//   before: start of input, or a non-alphanumeric char, or a
//           lowercase → uppercase transition (so `NistP256` matches
//           `p256`, while `traversal` does not match `rsa`)
//   after:  end of input, or a non-alphanumeric char, or an uppercase
//           char (so `RsaPrivateKey` and `ECDSA_P256_SHA256` match)
//
// That single rule removes every false positive listed above and
// recovers both false negatives.
// ═══════════════════════════════════════════════════════════════════════

/// What a match means for quantum resistance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Signature or key-agreement scheme broken outright by Shor.
    ShorBroken,
    /// Post-quantum, but below GodShield's Level 5 target.
    WeakPqLevel,
    /// Classically broken hash. Not a quantum issue; flagged because
    /// finding one usually means the surrounding crypto is old too.
    LegacyHash,
    /// A library that commonly *hosts* vulnerable primitives. Finding it
    /// is not itself a finding — it tells a reviewer where to look.
    ReviewHint,
    /// Level-5 primitives: correct, never reported.
    ///
    /// These exist in the table purely to claim their byte span during
    /// overlap resolution. Without them, `ml_dsa_87` matches the `DSA`
    /// pattern at offset 3 (the preceding `_` is a valid identifier
    /// boundary), so the scanner reports CRITICAL classical DSA against
    /// the exact algorithm GodShield is migrating *to*. Same for
    /// `ml_kem_1024` and `kyber1024`.
    Approved,
}

impl Class {
    pub fn severity(self) -> &'static str {
        match self {
            Class::ShorBroken => "CRITICAL",
            Class::WeakPqLevel => "MEDIUM",
            Class::LegacyHash => "MEDIUM",
            Class::ReviewHint => "INFO",
            Class::Approved => "OK",
        }
    }

    /// Whether a match of this class reaches the report.
    pub fn is_reportable(self) -> bool {
        self != Class::Approved
    }
}

pub struct Pattern {
    /// Canonical name reported as `crypto_type`.
    pub name: &'static str,
    /// Spellings to match, lowercased. Longest-first within a position.
    pub aliases: &'static [&'static str],
    pub class: Class,
    pub description: &'static str,
    pub remediation: &'static str,
}

/// Ordered longest-alias-first so `secp256k1` is preferred over a
/// hypothetical `secp` and `EdDSA` over bare `DSA` at the same offset.
pub const PATTERNS: &[Pattern] = &[
    // ── Approved — present only to claim their span ──────────────────
    Pattern {
        name: "Dilithium5",
        aliases: &["dilithium5", "ml_dsa_87", "ml-dsa-87"],
        class: Class::Approved,
        description: "NIST Level 5. This is the target.",
        remediation: "",
    },
    Pattern {
        name: "ML-KEM-1024",
        aliases: &["kyber1024", "ml_kem_1024", "ml-kem-1024"],
        class: Class::Approved,
        description: "NIST Level 5 KEM.",
        remediation: "",
    },
    Pattern {
        name: "SHA3/BLAKE3",
        aliases: &["sha3_512", "sha3-512", "blake3", "sha3_256"],
        class: Class::Approved,
        description: "Quantum-adjusted margin is sufficient; Grover halves preimage \
                      resistance, which SHA3-512 absorbs.",
        remediation: "",
    },
    // ── Elliptic-curve signatures ────────────────────────────────────
    Pattern {
        name: "secp256k1",
        aliases: &["secp256k1", "k256"],
        class: Class::ShorBroken,
        description: "Bitcoin/Ethereum curve. Shor recovers the private key from any \
                      exposed public key; on-chain keys are permanently public.",
        remediation: "Replace with godshield-core (Dilithium5 / ML-DSA Level 5). \
                      For chains requiring secp256k1 at consensus, use hybrid mode \
                      and treat the ECDSA signature as a compatibility shim.",
    },
    Pattern {
        name: "ECDSA",
        aliases: &["ecdsa"],
        class: Class::ShorBroken,
        description: "ECDSA over any curve is fully broken by Shor's algorithm.",
        remediation: "Replace signing with GodShield::sign() and verification with \
                      GodShield::verify().",
    },
    Pattern {
        name: "Ed25519",
        aliases: &["ed25519", "curve25519", "eddsa"],
        class: Class::ShorBroken,
        description: "EdDSA over Curve25519. Discrete-log based, fully broken by Shor.",
        remediation: "Replace with Dilithium5. Note the size change: ~2.6 KB public \
                      keys and ~4.6 KB signatures against Ed25519's 32 and 64 bytes.",
    },
    Pattern {
        name: "Ed448",
        aliases: &["ed448", "curve448"],
        class: Class::ShorBroken,
        description: "EdDSA over Curve448. Larger classical margin, no quantum margin.",
        remediation: "Replace with Dilithium5.",
    },
    Pattern {
        name: "P-256",
        aliases: &["prime256v1", "secp256r1", "nistp256", "p-256", "p256"],
        class: Class::ShorBroken,
        description: "NIST P-256. Four common spellings of one curve — the previous \
                      scanner matched only the literal \"P-256\".",
        remediation: "Replace with Dilithium5.",
    },
    Pattern {
        name: "P-384/P-521",
        aliases: &[
            "secp384r1",
            "secp521r1",
            "nistp384",
            "nistp521",
            "p-384",
            "p-521",
        ],
        class: Class::ShorBroken,
        description: "Larger NIST curves. A bigger classical key buys nothing against \
                      Shor — the attack scales polynomially in key size.",
        remediation: "Replace with Dilithium5. Do not migrate to a larger curve.",
    },
    Pattern {
        name: "Schnorr",
        aliases: &["schnorr", "musig"],
        class: Class::ShorBroken,
        description: "Schnorr signatures rest on discrete log. Taproot's signature \
                      scheme is in this family.",
        remediation: "Replace with Dilithium5, or hybrid-sign during migration.",
    },
    // ── Factoring / discrete log ─────────────────────────────────────
    Pattern {
        name: "RSA",
        aliases: &["rsa"],
        class: Class::ShorBroken,
        description: "Integer factorisation. Shor solves it in polynomial time.",
        remediation: "Replace with Dilithium5 for signatures, ML-KEM (Kyber) for \
                      key encapsulation.",
    },
    Pattern {
        name: "DSA",
        aliases: &["dsa"],
        class: Class::ShorBroken,
        description: "Finite-field DSA. Discrete log, broken by Shor.",
        remediation: "Replace with Dilithium5.",
    },
    Pattern {
        name: "Diffie-Hellman",
        aliases: &["diffie-hellman", "diffie_hellman", "ecdh", "x25519", "x448"],
        class: Class::ShorBroken,
        description: "Key agreement over discrete log. Recorded handshakes are \
                      decryptable retroactively once a CRQC exists — the core \
                      harvest-now-decrypt-later exposure.",
        remediation: "Migrate to ML-KEM (Kyber), or a hybrid X25519+ML-KEM construction \
                      during transition.",
    },
    // ── Pairing curves — entirely absent from the previous table ─────
    Pattern {
        name: "BLS12-381",
        aliases: &["bls12_381", "bls12-381", "bls381"],
        class: Class::ShorBroken,
        description: "Pairing-friendly curve used for BLS signatures and most ZK \
                      systems. Discrete-log based, fully broken by Shor. Missing \
                      entirely from the previous pattern set despite being ubiquitous \
                      in rollup and ZK code.",
        remediation: "No drop-in post-quantum replacement for pairings. Aggregate \
                      signatures need redesign, not substitution. Treat as a research \
                      item, not a migration task.",
    },
    Pattern {
        name: "BN254",
        aliases: &["bn254", "bn128", "alt_bn128"],
        class: Class::ShorBroken,
        description: "Pairing curve behind Ethereum's precompiles. Shor-broken, and \
                      already below 128-bit classical security.",
        remediation: "Same as BLS12-381 — pairing-based constructions need redesign.",
    },
    // ── Post-quantum, wrong level ────────────────────────────────────
    Pattern {
        name: "Dilithium2",
        aliases: &["dilithium2", "ml_dsa_44", "ml-dsa-44"],
        class: Class::WeakPqLevel,
        description: "NIST Level 2. GodShield targets Level 5. FIPS 204 renamed \
                      Dilithium to ML-DSA, so standards-conformant code spells this \
                      ml_dsa_44 — which the previous table did not match.",
        remediation: "Move to dilithium5 / ml_dsa_87.",
    },
    Pattern {
        name: "Dilithium3",
        aliases: &["dilithium3", "ml_dsa_65", "ml-dsa-65"],
        class: Class::WeakPqLevel,
        description: "NIST Level 3. GodShield targets Level 5.",
        remediation: "Move to dilithium5 / ml_dsa_87.",
    },
    Pattern {
        name: "Kyber512/768",
        aliases: &["kyber512", "kyber768", "ml_kem_512", "ml_kem_768"],
        class: Class::WeakPqLevel,
        description: "ML-KEM below Level 5.",
        remediation: "Move to kyber1024 / ml_kem_1024.",
    },
    // ── Legacy hashes ────────────────────────────────────────────────
    Pattern {
        name: "MD5",
        aliases: &["md5"],
        class: Class::LegacyHash,
        description: "Collisions are practical. Not a quantum issue — a present one.",
        remediation: "Replace with SHA3-512, or TripleHash for signed payloads.",
    },
    Pattern {
        name: "SHA-1",
        aliases: &["sha-1", "sha1"],
        class: Class::LegacyHash,
        description: "Chosen-prefix collisions are practical.",
        remediation: "Replace with SHA3-512, or TripleHash for signed payloads.",
    },
    // ── Review hints ─────────────────────────────────────────────────
    Pattern {
        name: "openssl",
        aliases: &["openssl"],
        class: Class::ReviewHint,
        description: "Commonly hosts RSA and EC primitives selected at runtime, which \
                      no static scan can see. Flagged as a place to look, not a finding.",
        remediation: "Enumerate which algorithms are actually configured. Pattern \
                      matching cannot determine this.",
    },
    Pattern {
        name: "ring",
        aliases: &["ring::signature", "ring::agreement"],
        class: Class::ReviewHint,
        description: "Algorithm chosen by constant at the call site; the constant may \
                      be built elsewhere.",
        remediation: "Check which algorithm constants are reachable.",
    },
];

/// True if a match spanning `[start, end)` in `hay` sits on identifier
/// boundaries. See the header comment for why this rule exists.
///
/// `hay` must be the ORIGINAL-case text — the CamelCase clauses depend
/// on it, and passing a lowercased copy silently reverts this to
/// substring matching.
pub fn on_identifier_boundary(hay: &str, start: usize, end: usize) -> bool {
    let b = hay.as_bytes();

    let before_ok = if start == 0 {
        true
    } else {
        let prev = b[start - 1];
        let cur = b[start];
        !prev.is_ascii_alphanumeric() || (cur.is_ascii_uppercase() && prev.is_ascii_lowercase())
    };

    let after_ok = if end >= b.len() {
        true
    } else {
        let next = b[end];
        !next.is_ascii_alphanumeric() || next.is_ascii_uppercase()
    };

    before_ok && after_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_rsa_inside_english_words() {
        // Every one of these was reported CRITICAL by the previous scanner.
        for word in [
            "traversal",
            "adversary",
            "universal",
            "reversal",
            "parsable",
            "versatile",
            "conversation",
        ] {
            let idx = word
                .to_lowercase()
                .find("rsa")
                .expect("test word must contain rsa");
            assert!(
                !on_identifier_boundary(word, idx, idx + 3),
                "{word} must not match RSA"
            );
        }
    }

    #[test]
    fn accepts_real_rsa_identifiers() {
        for (hay, pat) in [
            ("use rsa::RsaPrivateKey;", "rsa"),
            ("RsaPrivateKey", "rsa"),
            ("RSA_PKCS1_SHA256", "rsa"),
        ] {
            let low = hay.to_lowercase();
            let idx = low.find(pat).unwrap();
            assert!(
                on_identifier_boundary(hay, idx, idx + pat.len()),
                "{hay} must match {pat}"
            );
        }
    }

    #[test]
    fn camelcase_start_boundary_catches_nistp256() {
        // The previous scanner called `use p256::NistP256;` clean.
        let hay = "NistP256";
        let idx = hay.to_lowercase().find("p256").unwrap();
        assert!(on_identifier_boundary(hay, idx, idx + 4));
    }

    #[test]
    fn underscore_after_is_a_boundary() {
        let hay = "ECDSA_P256_SHA256_ASN1";
        assert!(on_identifier_boundary(hay, 0, 5));
    }
}
