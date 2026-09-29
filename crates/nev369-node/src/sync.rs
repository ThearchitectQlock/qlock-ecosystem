// crates/nev369- node/src/sync.rs
//
// ════════════════════════ ════════════════════════ ═══════════════════════
// BLOCK SYNC — libp2p request/response
//
// WHAT WAS MISSING:
//
// consensus.rs had locator() and blocks_after() but nothing to carry them
// between peers. Gossip only propagates NEW blocks — a node joining the
// network had no way to obtain history. It would start from its own
// genesis and diverge on block 1, permanently, with no error.
//
// This adds a request/response protocol alongside gossipsub:
//
//   1. On connecting to a peer, exchange tip status (height + work).
//   2. If the peer has more cumulative work, send our locator.
//   3. Peer replies with the most recent block we share.
//   4. Request blocks after that point, in batches.
//   5. Feed each into accept_block, which handles reorg if needed.
//
// Everything received here is untrusted and goes through the same
// validation as gossip and API submissions. A peer cannot bypass signature
// checks, the time-lock, or the supply cap by feeding us blocks during sync.
// ════════════════════════ ════════════════════════ ═══════════════════════

use crate::chain::Block;
use serde::{Deserialize, Serialize};

/// Blocks per batch. Dilithium5 signatures are ~4.6 KB, so a block with
/// many transactions is large — 50 keeps a response comfortably under the
/// 4 MB gossipsub/request- response transmit limit.
pub const SYNC_BATCH_SIZE: usize = 50;

/// Ceiling on how many blocks a peer may push in one sync session, so a
/// malicious peer cannot stream indefinitely and exhaust us.
pub const MAX_SYNC_BLOCKS: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// "Where are you?" Cheap, sent on every new connection.
    Status,
    /// "Here are hashes I know — which is the most recent one you also
    /// have?" Finds the fork point in one round trip rather than walking
    /// back block by block.
    FindForkPoint { locator: Vec<String> },
    /// "Send me what comes after this."
    GetBlocks { after_hash: String, limit: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Status {
        height: u64,
        tip_hash: String,
        /// Cumulative work, as a decimal string. u128 does not survive a
        /// JSON round trip through every client cleanly, so it is sent as
        /// text and parsed back.
        cumulative_work: String,
        genesis_hash: String,
    },
    ForkPoint {
        /// None means no shared history — almost always a different genesis.
        hash: Option<String>,
    },
    Blocks {
        blocks: Vec<Block>,
        /// True when more remain after this batch.
        has_more: bool,
    },
    /// Explicit refusal, so a peer can distinguish "no" from a timeout.
    Refused { reason: String },
}

impl SyncResponse {
    pub fn work(&self) -> u128 {
        match self {
            Self::Status {
                cumulative_work, ..
            } => cumulative_work.parse().unwrap_or(0),
            _ => 0,
        }
    }
}

/// Tracks an in-progress sync with one peer.
#[allow(dead_code)] // peer/target fields kept for logging and peer-selection heuristics
pub struct SyncSession {
    pub peer: String,
    pub target_height: u64,
    pub target_work: u128,
    pub blocks_received: usize,
    pub fork_point: Option<String>,
    pub started_at: u64,
}

impl SyncSession {
    pub fn new(peer: String, target_height: u64, target_work: u128) -> Self {
        Self {
            peer,
            target_height,
            target_work,
            blocks_received: 0,
            fork_point: None,
            started_at: crate::chain::now(),
        }
    }

    /// Stop if the peer has sent more than any legitimate sync would need.
    pub fn should_abort(&self) -> Option<&'static str> {
        if self.blocks_received > MAX_SYNC_BLOCKS {
            return Some("peer exceeded the maximum blocks for one sync session");
        }
        if crate::chain::now().saturating_sub(self.started_at) > 3600 {
            return Some("sync session exceeded one hour");
        }
        None
    }
}

/// Decide whether a peer is worth syncing from.
///
/// Compares WORK, not height. A peer with a longer chain of cheap blocks
/// has done less work than one with a shorter chain of expensive blocks,
/// and syncing to the former would be following the weaker chain.
pub fn should_sync_from(
    our_work: u128,
    peer: &SyncResponse,
    our_genesis: &str,
) -> Result<bool, String> {
    match peer {
        SyncResponse::Status {
            cumulative_work,
            genesis_hash,
            ..
        } => {
            // A different genesis means a different network entirely.
            // Syncing would be meaningless and the blocks would all fail
            // validation anyway — better to say so clearly.
            if genesis_hash != our_genesis {
                return Err(format!(
                    "peer is on a different chain (genesis {} vs ours {})",
                    &genesis_hash[..16.min(genesis_hash.len())],
                    &our_genesis[..16.min(our_genesis.len())]
                ));
            }
            let peer_work: u128 = cumulative_work.parse().unwrap_or(0);
            Ok(peer_work > our_work)
        }

        SyncResponse::Refused { reason } => Err(reason.clone()),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(height: u64, work: u128, genesis: &str) -> SyncResponse {
        SyncResponse::Status {
            height,
            tip_hash: "tip".into(),
            cumulative_work: work.to_string(),
            genesis_hash: genesis.into(),
        }
    }

    #[test]
    fn syncs_from_a_peer_with_more_work() {
        let peer = status(10, 5000, "genesis_a");
        assert!(should_sync_from(1000, &peer, "genesis_a").unwrap());
    }

    #[test]
    fn does_not_sync_from_a_peer_with_less_work() {
        let peer = status(100, 500, "genesis_a");
        assert!(!should_sync_from(5000, &peer, "genesis_a").unwrap());
    }

    /// Height alone is not the criterion. A peer with a much longer chain
    /// of low-difficulty blocks has done less work and must not win.
    #[test]
    fn height_alone_does_not_justify_syncing() {
        let long_but_cheap = status(1000, 100, "genesis_a");
        assert!(
            !should_sync_from(5000, &long_but_cheap, "genesis_a").unwrap(),
            "fork choice must follow work, not length"
        );
    }

    #[test]
    fn refuses_peers_on_a_different_genesis() {
        let peer = status(1000, u128::MAX, "different_genesis");
        let result = should_sync_from(1, &peer, "our_genesis");
        assert!(
            result.is_err(),
            "a different genesis is a different network"
        );
        assert!(result.unwrap_err().contains("different chain"));
    }

    #[test]
    fn work_is_parsed_back_from_its_string_form() {
        let big = u128::MAX / 2;
        let s = status(1, big, "g");
        assert_eq!(s.work(), big, "u128 must survive the JSON round trip");
    }
    #[test]
    fn session_aborts_on_excessive_blocks() {
        let mut session = SyncSession::new("peer".into(), 100, 1000);
        assert!(session.should_abort().is_none());

        session.blocks_received = MAX_SYNC_BLOCKS + 1;
        assert!(session.should_abort().is_some());
    }

    #[test]
    fn session_aborts_when_it_runs_too_long() {
        let mut session = SyncSession::new("peer".into(), 100, 1000);
        session.started_at = crate::chain::now().saturating_sub(7200);
        assert!(session.should_abort().is_some());
    }

    #[test]
    fn requests_and_responses_round_trip_as_json() {
        let req = SyncRequest::FindForkPoint {
            locator: vec!["a".into(), "b".into()],
        };
        let encoded = serde_json::to_vec(&req).unwrap();
        let decoded: SyncRequest = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(decoded, SyncRequest::FindForkPoint { .. }));

        let resp = SyncResponse::ForkPoint {
            hash: Some("abc".into()),
        };
        let encoded = serde_json::to_vec(&resp).unwrap();
        let decoded: SyncResponse = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(decoded, SyncResponse::ForkPoint { hash: Some(_) }));
    }
}
