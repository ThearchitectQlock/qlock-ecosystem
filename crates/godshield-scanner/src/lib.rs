// crates/godshield-scanner/src/lib.rs
//
// ═══════════════════════════════════════════════════════════════════════
// GODSHIELD SCANNER
//
// WHY THIS CRATE EXISTS AS A CRATE.
//
// Both README variants list `crates/godshield-scanner/` in the
// repository layout. The workspace Cargo.toml does not include it as a
// member, and the scanner code actually lives inside
// godshield-adapters as `MigrationHelper`. So the crate the docs
// advertise does not exist, and the code that does exist sits in a
// chain-adapter crate it shares nothing with — meaning anyone who wants
// to scan source pulls in Bitcoin, Ethereum and Solana encoders to do it.
//
// This is the crate. `godshield-adapters` re-exports from here, so the
// existing CLI (`use godshield_adapters::{AdapterRegistry,
// MigrationHelper}`) compiles unchanged. Add to adapters/src/lib.rs and
// delete the old inline scanner:
//
//     pub use godshield_scanner::{MigrationHelper, VulnerabilityReport};
//
// ── WHAT CHANGED BEYOND THE MOVE ──────────────────────────────────────
//
//  1. Identifier-boundary matching. See patterns.rs — substring matching
//     reported "traversal" and "adversary" as CRITICAL RSA findings.
//
//  2. Real comment handling. The old rule was `trimmed.starts_with("//")`,
//     which meant:
//
//       - a trailing comment was NOT skipped, so
//         `let x = 1; // we migrated away from secp256k1`
//         was reported as a live secp256k1 dependency. The existing test
//         `scanner_skips_comments` passes only because its fixture puts
//         the comment at the start of the line.
//       - block comments were NOT skipped, because the opening `/*` line
//         starts with neither `//` nor `*`.
//       - `#` was treated as a comment marker, so every Rust attribute
//         was skipped — including
//         `#[cfg(feature = "secp256k1")] mod legacy;`, which is exactly
//         the conditional legacy-crypto path a migration audit needs to
//         find.
//
//     Now a proper lexer blanks comments in place, preserving line and
//     column numbers, and leaves attributes alone.
//
//  3. String literals are scanned but marked. A curve name in a string
//     is usually a feature flag or an algorithm parameter, so dropping
//     them loses real findings; treating them as code produces noise
//     from URLs and doc text. They are reported at reduced confidence.
//
//  4. Directory walking. The CLI calls `fs::read_to_string(&args.path)`,
//     so `godshield scan ./src` fails with "Is a directory". Both
//     READMEs document `godshield scan <path>`.
//
//  5. Exit-code support, so this can gate CI. `scan` previously always
//     returned Ok, which makes it unusable as a build gate.
//
// ── WHAT HAS NOT CHANGED ──────────────────────────────────────────────
//
// The honesty. This is still name matching over source text. It cannot
// see cryptography reached through opaque dependencies, dynamic
// dispatch, FFI, or runtime algorithm selection. A clean result is not a
// clean bill of health and this tool is not a certification. Every
// output path says so.
// ═══════════════════════════════════════════════════════════════════════

pub mod patterns;

use patterns::{on_identifier_boundary, PATTERNS};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════
// REPORT
// ═══════════════════════════════════════════════════════════════════════

/// Field-compatible with the `VulnerabilityReport` the CLI already
/// consumes (`crypto_type`, `severity`, `description`, `recommendation`,
/// `line`). The additions are `#[serde(default)]` so existing persisted
/// reports still deserialise.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityReport {
    pub crypto_type: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
    pub line: Option<usize>,

    #[serde(default)]
    pub column: Option<usize>,
    #[serde(default)]
    pub snippet: String,
    /// `false` when the match was inside a string literal. A curve name
    /// in a string may be a feature flag or a URL; the reviewer decides.
    #[serde(default = "default_true")]
    pub high_confidence: bool,
    #[serde(default)]
    pub file: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Medium,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "medium" => Some(Self::Medium),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LEXER — blank comments, mark strings, keep positions
// ═══════════════════════════════════════════════════════════════════════

/// Per-byte mask of what kind of text a source byte belongs to.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Code,
    Comment,
    Str,
}

/// Classify every byte of `src`, preserving length so offsets stay valid.
///
/// Handles `//`, `/* */` (nested, as Rust allows), `"..."`, `'...'`,
/// escapes, and Rust raw strings (`r"..."`, `r#"..."#`). Deliberately
/// does NOT treat `#` as a comment marker — that is the bug that hid
/// every `#[cfg(feature = "...")]` gate from the previous scanner.
fn classify(src: &str) -> Vec<Kind> {
    let b = src.as_bytes();
    let mut kinds = vec![Kind::Code; b.len()];
    let mut i = 0usize;
    let mut block_depth = 0usize;

    while i < b.len() {
        if block_depth > 0 {
            if b[i..].starts_with(b"/*") {
                block_depth += 1;
                kinds[i] = Kind::Comment;
                kinds[i + 1] = Kind::Comment;
                i += 2;
                continue;
            }
            if b[i..].starts_with(b"*/") {
                block_depth -= 1;
                kinds[i] = Kind::Comment;
                kinds[i + 1] = Kind::Comment;
                i += 2;
                continue;
            }
            kinds[i] = Kind::Comment;
            i += 1;
            continue;
        }

        // Line comment — runs to newline. Covers trailing comments,
        // which the previous `starts_with("//")` check did not.
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                kinds[i] = Kind::Comment;
                i += 1;
            }
            continue;
        }

        if b[i..].starts_with(b"/*") {
            block_depth = 1;
            kinds[i] = Kind::Comment;
            kinds[i + 1] = Kind::Comment;
            i += 2;
            continue;
        }

        // Raw string: r"..." or r#"..."# with any number of hashes.
        if b[i] == b'r' && i + 1 < b.len() {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let start = i;
                j += 1;
                while j < b.len() && !b[j..].starts_with(&close) {
                    j += 1;
                }
                let end = (j + close.len()).min(b.len());
                kinds[start..end].fill(Kind::Str);
                i = end;
                continue;
            }
        }

        if b[i] == b'"' || b[i] == b'\'' {
            let quote = b[i];
            let start = i;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == quote || b[i] == b'\n' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            kinds[start..i.min(b.len())].fill(Kind::Str);
            continue;
        }

        i += 1;
    }

    kinds
}

// ═══════════════════════════════════════════════════════════════════════
// SCANNING
// ═══════════════════════════════════════════════════════════════════════

/// Scan a single source string.
///
/// Signature-compatible with the previous `scan_vulnerabilities`, so
/// existing callers need no change.
pub fn scan_source(source_code: &str) -> Vec<VulnerabilityReport> {
    let kinds = classify(source_code);
    let lower = source_code.to_lowercase();
    let mut out: Vec<VulnerabilityReport> = Vec::new();

    // Byte offset → 1-based line, and the start offset of each line.
    let mut line_of = Vec::with_capacity(source_code.len() + 1);
    let mut line_starts = vec![0usize];
    let mut line = 1usize;
    for (idx, ch) in source_code.bytes().enumerate() {
        line_of.push(line);
        if ch == b'\n' {
            line += 1;
            line_starts.push(idx + 1);
        }
    }
    line_of.push(line);

    // PASS 1 — collect every boundary-valid candidate. Sequential
    // claiming does not work here: whichever pattern the table happens
    // to list first wins, so `DSA` (listed before Dilithium2) claims
    // offset 3 of `ml_dsa_44` and both get reported. Gather first,
    // resolve after.
    struct Candidate {
        start: usize,
        end: usize,
        pat: &'static patterns::Pattern,
    }
    let mut cands: Vec<Candidate> = Vec::new();

    for pat in PATTERNS {
        for alias in pat.aliases {
            let mut from = 0usize;
            while let Some(rel) = lower[from..].find(alias) {
                let start = from + rel;
                let end = start + alias.len();
                from = start + 1;

                if kinds.get(start).copied() == Some(Kind::Comment) {
                    continue;
                }
                if !on_identifier_boundary(source_code, start, end) {
                    continue;
                }
                cands.push(Candidate { start, end, pat });
            }
        }
    }

    // PASS 2 — longest match wins. Sorting by (start asc, length desc)
    // then keeping only non-overlapping spans means `ml_dsa_87` (span
    // 0..9, Approved) consumes the `dsa` at 3..6 and the false CRITICAL
    // never reaches the report.
    cands.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
    });

    let mut consumed_to = 0usize;
    let mut seen: Vec<(usize, &str)> = Vec::new();

    for c in &cands {
        if c.start < consumed_to {
            continue;
        }
        consumed_to = c.end;

        if !c.pat.class.is_reportable() {
            continue;
        }

        let in_string = kinds.get(c.start).copied() == Some(Kind::Str);
        let ln = line_of.get(c.start).copied().unwrap_or(1);
        let ls = line_starts.get(ln - 1).copied().unwrap_or(0);

        // One finding per primitive per line. `use p256::NistP256;`
        // contains two valid p256 matches; a reviewer needs to look at
        // that line once, not twice.
        if seen.contains(&(ln, c.pat.name)) {
            continue;
        }
        seen.push((ln, c.pat.name));

        let snippet = source_code[ls..]
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .chars()
            .take(120)
            .collect::<String>();

        out.push(VulnerabilityReport {
            crypto_type: c.pat.name.to_string(),
            severity: c.pat.class.severity().to_string(),
            description: c.pat.description.to_string(),
            recommendation: c.pat.remediation.to_string(),
            line: Some(ln),
            column: Some(c.start - ls + 1),
            snippet,
            high_confidence: !in_string,
            file: None,
        });
    }

    out.sort_by_key(|r| (r.line.unwrap_or(0), r.column.unwrap_or(0)));
    out
}

/// Extensions worth reading. Everything else is skipped rather than
/// scanned as text — a scanner that reports findings inside a minified
/// bundle or a lockfile is reporting noise.
const SOURCE_EXTS: &[&str] = &[
    "rs", "sol", "ts", "tsx", "js", "jsx", "py", "go", "java", "kt", "c", "h", "cpp", "hpp", "cs",
    "rb", "php", "swift", "toml", "yaml", "yml", "json",
];

/// Directories never worth walking. `lib/` is here for Foundry's
/// dependency tree: scanning vendored OpenZeppelin reports hundreds of
/// findings in code you do not maintain, which buries your own.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    "out",
    "lib",
    "vendor",
    ".venv",
    "__pycache__",
    "cache",
    "broadcast",
    ".sqlx",
];

#[derive(Debug, Default)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub findings: Vec<VulnerabilityReport>,
}

impl ScanSummary {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings
            .iter()
            .filter_map(|f| Severity::parse(&f.severity))
            .max()
    }

    pub fn count(&self, sev: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| Severity::parse(&f.severity) == Some(sev))
            .count()
    }

    /// True if anything at or above `threshold` was found. This is the
    /// CI gate the previous implementation had no way to express.
    pub fn should_fail(&self, threshold: Severity) -> bool {
        self.max_severity().is_some_and(|m| m >= threshold)
    }
}

/// Scan a file or a directory tree.
pub fn scan_path(root: &Path) -> std::io::Result<ScanSummary> {
    let mut sum = ScanSummary::default();
    walk(root, &mut sum)?;
    sum.findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    Ok(sum)
}

fn walk(path: &Path, sum: &mut ScanSummary) -> std::io::Result<()> {
    let meta = fs::metadata(path)?;

    if meta.is_file() {
        let wanted = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SOURCE_EXTS.contains(&e));

        // Explicitly-named files are scanned whatever the extension —
        // if someone points at one file, they mean that file.
        if !wanted && sum.files_scanned + sum.files_skipped > 0 {
            sum.files_skipped += 1;
            return Ok(());
        }

        match fs::read_to_string(path) {
            Ok(src) => {
                let mut found = scan_source(&src);
                for f in &mut found {
                    f.file = Some(path.to_path_buf());
                }
                sum.findings.extend(found);
                sum.files_scanned += 1;
            }
            // Binary or non-UTF-8. Not an error worth aborting a tree walk.
            Err(_) => sum.files_skipped += 1,
        }
        return Ok(());
    }

    if meta.is_dir() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if SKIP_DIRS.contains(&name) {
            return Ok(());
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        entries.sort();
        for e in entries {
            // A failure on one file must not abort the whole scan.
            let _ = walk(&e, sum);
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// BACKWARDS-COMPATIBLE FACADE
//
// Keeps `MigrationHelper::scan_vulnerabilities` and
// `generate_migration_plan` so godshield-cli and godshield-api compile
// against this crate without edits.
// ═══════════════════════════════════════════════════════════════════════

pub struct MigrationHelper;

impl MigrationHelper {
    /// Flag quantum-vulnerable primitives in source code.
    ///
    /// SCOPE, stated plainly: this is identifier matching over source
    /// text. It cannot see cryptography reached through opaque
    /// dependencies, dynamic dispatch, FFI, or runtime algorithm
    /// selection. It is a starting point for manual review. It is NOT a
    /// certification, and a clean result does not mean a codebase is
    /// quantum-safe.
    pub fn scan_vulnerabilities(source_code: &str) -> Vec<VulnerabilityReport> {
        scan_source(source_code)
    }

    pub fn generate_migration_plan(vulns: &[VulnerabilityReport]) -> String {
        if vulns.is_empty() {
            return "No known-vulnerable primitives matched.\n\n\
                    This is NOT a clean bill of health. Identifier matching cannot see \
                    cryptography invoked through dependencies, dynamic dispatch, FFI, or \
                    runtime algorithm selection. Manual review is still required."
                .to_string();
        }

        let mut plan = String::from("GODSHIELD MIGRATION PLAN\n\n");

        let crit = vulns.iter().filter(|v| v.severity == "CRITICAL").count();
        let low_conf = vulns.iter().filter(|v| !v.high_confidence).count();
        plan.push_str(&format!(
            "{} finding(s): {} CRITICAL. {} matched inside string literals and need \
             a human to judge whether they are live dependencies or just text.\n\n",
            vulns.len(),
            crit,
            low_conf
        ));

        for (i, v) in vulns.iter().enumerate() {
            plan.push_str(&format!(
                "{}. [{}]{} {} at {}:{}\n     {}\n     → {}\n",
                i + 1,
                v.severity,
                if v.high_confidence {
                    ""
                } else {
                    " (in string)"
                },
                v.crypto_type,
                v.file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<input>".into()),
                v.line.map(|l| l.to_string()).unwrap_or_else(|| "?".into()),
                v.description,
                v.recommendation
            ));
        }

        plan.push_str(
            "\nSTEPS:\n\
             1. Add godshield-core to Cargo.toml\n\
             2. Replace key generation with GodKeyPair::generate()\n\
             3. Replace signing with GodShield::sign()\n\
             4. Replace verification with GodShield::verify()\n\
             5. Use CanonicalMessage for any multi-field signed payload — naive\n\
                concatenation is ambiguous and has produced real signature-reuse\n\
                bugs in this codebase\n\
             6. Commission an independent audit. This tool is not one, and a\n\
                library being open-source is not the same as an integration being\n\
                audited.\n",
        );

        plan
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS — each one pins a defect in the previous implementation
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn types(src: &str) -> Vec<String> {
        scan_source(src)
            .into_iter()
            .map(|r| r.crypto_type)
            .collect()
    }

    // ── False positives ──────────────────────────────────────────────

    #[test]
    fn english_words_containing_rsa_are_not_findings() {
        let src = "fn walk(dir: &Path) {}\n\
                   let adversary_model = ThreatModel::Hndl;\n\
                   pub const UNIVERSAL_TIMEOUT: u64 = 30;\n\
                   let reversal = items.iter().rev();\n\
                   let traversal_guard = true;\n";
        assert!(
            scan_source(src).is_empty(),
            "previous scanner reported five CRITICAL RSA findings here: {:?}",
            types(src)
        );
    }

    // ── Comment handling ─────────────────────────────────────────────

    #[test]
    fn trailing_comment_is_not_a_finding() {
        // The previous rule only skipped comments at line start, so this
        // was reported as a live secp256k1 dependency.
        let src = "let x = 1; // we migrated away from secp256k1 last year\n";
        assert!(scan_source(src).is_empty());
    }

    #[test]
    fn block_comment_is_not_a_finding() {
        // The opening `/*` line starts with neither `//` nor `*`, so the
        // previous check let the whole block through.
        let src = "/*\n  legacy notes: this used ECDSA over secp256k1\n*/\nlet x = 1;\n";
        assert!(scan_source(src).is_empty());
    }

    #[test]
    fn attributes_are_code_not_comments() {
        // `#` was treated as a comment marker, which hid every cfg gate —
        // including the conditional legacy-crypto paths a migration audit
        // most needs to find.
        let src = "#[cfg(feature = \"secp256k1\")]\nmod legacy;\n";
        let found = types(src);
        assert!(found.contains(&"secp256k1".to_string()), "got {found:?}");
    }

    // ── False negatives ──────────────────────────────────────────────

    #[test]
    fn p256_spellings_all_match() {
        for src in [
            "use p256::NistP256;",
            "let c = \"prime256v1\";",
            "EC_GROUP_new_by_curve_name(NID_secp256r1)",
        ] {
            assert!(!scan_source(src).is_empty(), "missed P-256 in: {src}");
        }
    }

    #[test]
    fn pairing_curves_are_detected() {
        // Absent entirely from the previous pattern table.
        assert!(types("use bls12_381::G1Projective;").contains(&"BLS12-381".to_string()));
        assert!(types("import alt_bn128;").contains(&"BN254".to_string()));
    }

    #[test]
    fn ml_dsa_names_match_dilithium_levels() {
        // FIPS 204 renamed Dilithium to ML-DSA; standards-conformant code
        // uses the new names, which the old table did not match.
        assert!(types("use ml_dsa_44::sign;").contains(&"Dilithium2".to_string()));
        assert!(types("use ml_dsa_65::sign;").contains(&"Dilithium3".to_string()));
    }

    #[test]
    fn dilithium5_is_not_flagged() {
        assert!(scan_source("use pqcrypto_dilithium::dilithium5;").is_empty());
        assert!(scan_source("use ml_dsa_87::sign;").is_empty());
    }

    // ── Dedupe and positioning ───────────────────────────────────────

    #[test]
    fn dsa_inside_ecdsa_is_not_double_reported() {
        let found = types("use k256::ecdsa::SigningKey;");
        assert!(!found.contains(&"DSA".to_string()), "got {found:?}");
    }

    #[test]
    fn ml_dsa_is_not_reported_as_classical_dsa() {
        // `ml_dsa_87` contains "dsa" at offset 3, preceded by `_` — a
        // valid identifier boundary. Without longest-match resolution the
        // scanner reports CRITICAL classical DSA against the exact
        // algorithm GodShield migrates TO.
        for src in [
            "use ml_dsa_87::sign;",
            "use ml_dsa_44::sign;",
            "ml_kem_1024",
        ] {
            let found = types(src);
            assert!(!found.contains(&"DSA".to_string()), "{src} → {found:?}");
        }
        // ml_dsa_44 is still correctly flagged as a below-Level-5 level.
        assert!(types("use ml_dsa_44::sign;").contains(&"Dilithium2".to_string()));
    }

    #[test]
    fn one_finding_per_primitive_per_line() {
        // `p256` matches twice here (`p256::` and `NistP256`); a reviewer
        // needs to look at the line once.
        let v = scan_source("use p256::NistP256;");
        assert_eq!(v.len(), 1, "got {:?}", types("use p256::NistP256;"));
        assert_eq!(v[0].crypto_type, "P-256");

        let v2 = scan_source("use rsa::RsaPrivateKey;");
        assert_eq!(v2.len(), 1);
    }

    #[test]
    fn approved_primitives_never_appear_in_output() {
        for src in [
            "use pqcrypto_dilithium::dilithium5;",
            "use ml_dsa_87::sign;",
            "let h = blake3::hash(&data);",
            "use sha3::Sha3_512;",
        ] {
            assert!(scan_source(src).is_empty(), "{src} → {:?}", types(src));
        }
    }

    #[test]
    fn reports_line_and_column() {
        let src = "let a = 1;\nuse secp256k1::Secp256k1;\nlet b = 2;";
        let v = scan_source(src);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(2));
        assert_eq!(v[0].column, Some(5));
    }

    #[test]
    fn string_matches_are_lower_confidence() {
        let v = scan_source("let url = \"https://docs.example/ecdsa-guide\";");
        assert_eq!(v.len(), 1);
        assert!(!v[0].high_confidence, "a match in a string must be marked");
    }

    // ── Honesty ──────────────────────────────────────────────────────

    #[test]
    fn empty_result_does_not_claim_safety() {
        let plan = MigrationHelper::generate_migration_plan(&[]);
        assert!(plan.contains("NOT a clean bill of health"));
    }

    #[test]
    fn plan_mentions_audit() {
        let v = scan_source("use rsa::RsaPrivateKey;");
        let plan = MigrationHelper::generate_migration_plan(&v);
        assert!(plan.contains("independent audit"));
    }

    // ── Gate ─────────────────────────────────────────────────────────

    #[test]
    fn severity_ordering_gates_correctly() {
        let s = ScanSummary {
            findings: scan_source("use rsa::RsaPrivateKey;"),
            ..Default::default()
        };
        assert_eq!(s.max_severity(), Some(Severity::Critical));
        assert!(s.should_fail(Severity::Critical));
        assert!(s.should_fail(Severity::Medium));

        let t = ScanSummary {
            findings: scan_source("use ml_dsa_44::sign;"),
            ..Default::default()
        };
        assert_eq!(t.max_severity(), Some(Severity::Medium));
        assert!(!t.should_fail(Severity::Critical));
    }

    #[test]
    fn clean_summary_does_not_fail_the_gate() {
        let s = ScanSummary::default();
        assert!(!s.should_fail(Severity::Info));
    }
}
