// crates/qlock- escrow/src/lib.rs
//
// Library surface for qlock-escrow.
//
// WHY THIS EXISTS: the crate had only a binary (main.rs), so its modules
// could not be shared. The inheritance ceremony binary needs
// inheritance.rs and xrpl.rs, and there was no way to reach them —
// inheritance.rs sat as dead code with no possible caller.
//
// Only the modules that genuinely need sharing are public. auth, billing
// and ratelimit are HTTP- layer concerns owned by main.rs and stay private
// to it — exposing them would invite use from contexts where their
// assumptions (an axum request, an AppState) don't hold.

pub mod attestation;
pub mod inheritance;
pub mod xrpl;
pub mod xumm;

/// Re-exported so callers get the same types without depending on
/// godshield-core directly.
pub use godshield_core::{GodKeyPair, GodPublicKey, GodShield, GodSignature, TripleHash};

// NOTE: auth, billing and ratelimit are deliberately NOT declared here.
// main.rs owns them with its own `mod auth; mod billing; mod ratelimit;`.
// Declaring them in both places compiles each file twice — once into the
// library, once into the binary — yielding two distinct types with the
// same name and errors of the form "expected auth::Claims, found
// auth::Claims". The comment above states the intent; this enforces it.
