// crates/nev369-node/src/checkpoints.rs
//
// ═══════════════════════════════════════════════════════════════════════
// CHECKPOINTS — hardcoded block hashes that fork choice will not overturn
//
// Ported from the "NEV369 — Complete File Set" merge, unchanged in
// substance: this file has no dependency on the Amount type, so it needed
// no f64→u64 work. Only the import path changed (crate::chain::Block).
//
// Starts EMPTY. Zero protection until real entries are added as the chain
// progresses — e.g. after a dry run confirms a block is correct, hardcode
// its hash here and ship it in the next release.
//
// consensus.rs's MAX_REORG_DEPTH (100 blocks) already refuses a reorg past
// that depth unconditionally. Checkpoints are a second, independent gate:
// they name specific blocks no reorg may cross, regardless of depth,
// once you've decided by hand that a given point in history is settled.
// ═══════════════════════════════════════════════════════════════════════

use crate::chain::Block;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Checkpoints {
    known: HashMap<u64, String>,
}

impl Checkpoints {
    pub fn new() -> Self {
        Self {
            known: HashMap::new(),
        }
    }

    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn add(&mut self, height: u64, hash: String) {
        self.known.insert(height, hash);
    }

    /// Returns an error naming the first conflict found, if any block in
    /// `chain` at a checkpointed height doesn't match the pinned hash.
    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn validate_chain(&self, chain: &[Block]) -> Result<(), String> {
        for (height, expected_hash) in &self.known {
            if let Some(block) = chain.iter().find(|b| b.index == *height) {
                if &block.hash != expected_hash {
                    return Err(format!(
                        "chain rejected: block {} hash {} conflicts with checkpoint {}",
                        height, block.hash, expected_hash
                    ));
                }
            }
        }
        Ok(())
    }

    /// Would accepting a reorg that discards these blocks cross a
    /// checkpoint? Call this before committing a `Reorganised` outcome,
    /// not just at load time — a live reorg is exactly the case
    /// checkpoints exist to stop.
    pub fn forbids_discarding(&self, disconnected: &[Block]) -> Option<u64> {
        disconnected
            .iter()
            .map(|b| b.index)
            .find(|height| self.known.contains_key(height))
    }

    #[allow(dead_code)] // API kept for tooling/tests; not yet called by the node itself
    pub fn highest_checkpoint(&self) -> u64 {
        self.known.keys().copied().max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(index: u64, hash: &str) -> Block {
        Block {
            index,
            timestamp: 0,
            transactions: vec![],
            previous_hash: "0".repeat(128),
            hash: hash.to_string(),
            nonce: 0,
            difficulty: 1,
            miner: "test".into(),
            block_dedication: String::new(),
        }
    }

    #[test]
    fn empty_checkpoints_validate_anything() {
        let cp = Checkpoints::new();
        assert!(cp.validate_chain(&[block(0, "a"), block(1, "b")]).is_ok());
    }

    #[test]
    fn matching_checkpoint_passes() {
        let mut cp = Checkpoints::new();
        cp.add(1, "b".into());
        assert!(cp.validate_chain(&[block(0, "a"), block(1, "b")]).is_ok());
    }

    #[test]
    fn conflicting_checkpoint_fails() {
        let mut cp = Checkpoints::new();
        cp.add(1, "expected".into());
        assert!(cp
            .validate_chain(&[block(0, "a"), block(1, "different")])
            .is_err());
    }

    #[test]
    fn forbids_discarding_a_checkpointed_block() {
        let mut cp = Checkpoints::new();
        cp.add(5, "pinned".into());
        let disconnected = vec![block(5, "pinned"), block(6, "x")];
        assert_eq!(cp.forbids_discarding(&disconnected), Some(5));
    }

    #[test]
    fn allows_discarding_uncheckpointed_blocks() {
        let cp = Checkpoints::new();
        let disconnected = vec![block(5, "a"), block(6, "b")];
        assert_eq!(cp.forbids_discarding(&disconnected), None);
    }
}
