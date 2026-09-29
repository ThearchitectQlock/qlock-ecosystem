// crates/nev369-node/src/p2p.rs
//
// ═══════════════════════════════════════════════════════════════════════
// P2P NETWORKING — gossipsub for propagation, request/response for sync
//
// This is new: the u64 lineage (chain.rs / consensus.rs / genesis.rs /
// sync.rs) had a complete blockchain engine with no network layer wired
// to it. sync.rs already defines the full SyncRequest/SyncResponse
// protocol and SyncSession bookkeeping — this file is what actually opens
// sockets and drives them.
//
// The swarm/transport/gossipsub/mdns boilerplate below is adapted from a
// working reference (the "Complete File Set" f64 main.rs's p2p.rs) — that
// part is protocol plumbing, agnostic to Amount's type, and there was no
// reason to rewrite it from scratch. Everything that touches chain state
// is new: block/tx handling calls straight into `chain::BlockchainApp`
// (`accept_block`, `connect_orphans`, `submit_transaction`) instead of the
// hand-rolled fork logic that reference file carried, because
// consensus.rs::BlockTree::accept() already IS that logic, done once,
// correctly, with reorg and orphan buffering built in.
//
// Compiled and tested against libp2p 0.53 (Rust 1.88.0). Needs the
// `request-response` and `cbor` libp2p features, enabled in the workspace
// Cargo.toml. Multi-node sync is exercised by docker-compose.nev369.yml.
// ═══════════════════════════════════════════════════════════════════════

use futures::StreamExt;
use libp2p::{
    gossipsub, identify, identity, mdns, noise, ping,
    request_response::{self, OutboundRequestId, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::chain::{Block, BlockchainApp, Transaction};
use crate::checkpoints::Checkpoints;
use crate::consensus::AcceptOutcome;
use crate::sync::{should_sync_from, SyncRequest, SyncResponse, SyncSession, SYNC_BATCH_SIZE};

const TOPIC_BLOCKS: &str = "nev369-blocks-v1";
const TOPIC_TX: &str = "nev369-transactions-v1";
const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/nev369/sync/1.0.0");

pub type SharedState = Arc<RwLock<BlockchainApp>>;
pub type SharedCheckpoints = Arc<RwLock<Checkpoints>>;

// ── Gossip payloads ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
enum GossipMessage {
    NewBlock(Block),
    NewTransaction(Transaction),
}

// ── Commands the rest of the app (HTTP handlers, miner) sends inward ───

#[derive(Debug)]
pub enum NetworkCommand {
    BroadcastBlock(Block),
    BroadcastTransaction(Transaction),
}

pub type NetworkCommandSender = mpsc::UnboundedSender<NetworkCommand>;

// ── Peer reputation ─────────────────────────────────────────────────────
// Ported near-verbatim from the reference p2p_sync.rs. PeerId-and-strikes
// bookkeeping has no dependency on Amount, so no f64/u64 concern here.

const MAX_STRIKES: u32 = 3;
const BAN_DURATION: Duration = Duration::from_secs(3600);

pub struct PeerReputation {
    strikes: HashMap<PeerId, (u32, Instant)>,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerReputation {
    pub fn new() -> Self {
        Self {
            strikes: HashMap::new(),
        }
    }

    /// Returns true if this strike just crossed the ban threshold.
    pub fn add_strike(&mut self, peer: PeerId, reason: &str) -> bool {
        let entry = self.strikes.entry(peer).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
        tracing::warn!(peer = %peer, strikes = entry.0, reason, "peer strike recorded");
        entry.0 >= MAX_STRIKES
    }

    pub fn is_banned(&self, peer: &PeerId) -> bool {
        match self.strikes.get(peer) {
            Some((count, since)) if *count >= MAX_STRIKES => since.elapsed() < BAN_DURATION,
            _ => false,
        }
    }
}

// ── Swarm behaviour ──────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct Nev369Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}

pub struct NetworkConfig {
    pub listen_port: u16,
    pub bootstrap_peers: Vec<Multiaddr>,
}

/// How often a node with no peers re-dials its bootstrap list.
const BOOTSTRAP_REDIAL: Duration = Duration::from_secs(60);

/// Peers this node is connected to right now. Written by the swarm task,
/// read by GET /info — so anyone can see the network is more than one node.
pub static CONNECTED_PEERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One `NEV369_BOOTSTRAP_PEERS` entry → dialable addresses.
///
/// libp2p is built without its DNS transport, so `/dns4/host/tcp/port`
/// (also `/dns/`, `/dns6/`, with an optional trailing `/p2p/<id>`) is
/// resolved here, once, at startup. That lets miners bootstrap from
/// `/dns4/q-lock-ecosystem.com/tcp/4001` rather than an IP that can change.
/// Anything else must parse as a multiaddr. Entries that fail are logged
/// and skipped: a bad bootstrap line must not stop a node from starting.
pub fn resolve_bootstrap(entry: &str) -> Vec<Multiaddr> {
    use std::net::{IpAddr, ToSocketAddrs};
    let entry = entry.trim();
    let parts: Vec<&str> = entry.trim_start_matches('/').split('/').collect();
    if let [proto @ ("dns" | "dns4" | "dns6"), host, "tcp", port, rest @ ..] = parts.as_slice() {
        let Ok(port) = port.parse::<u16>() else {
            tracing::warn!(entry, "bootstrap peer: bad TCP port — skipped");
            return Vec::new();
        };
        let suffix = if rest.is_empty() {
            String::new()
        } else {
            format!("/{}", rest.join("/"))
        };
        let resolved = match (*host, port).to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::warn!(entry, error = %e, "bootstrap peer: DNS lookup failed — skipped");
                return Vec::new();
            }
        };
        let mut out: Vec<Multiaddr> = Vec::new();
        for a in resolved {
            let ip = match (a.ip(), *proto) {
                (IpAddr::V4(v4), "dns" | "dns4") => format!("/ip4/{v4}"),
                (IpAddr::V6(v6), "dns" | "dns6") => format!("/ip6/{v6}"),
                _ => continue,
            };
            if let Ok(m) = format!("{ip}/tcp/{port}{suffix}").parse::<Multiaddr>() {
                if !out.contains(&m) {
                    out.push(m);
                }
            }
        }
        if out.is_empty() {
            tracing::warn!(entry, "bootstrap peer: no usable address — skipped");
        }
        return out;
    }
    match entry.parse::<Multiaddr>() {
        Ok(m) => vec![m],
        Err(e) => {
            tracing::warn!(entry, error = %e, "bootstrap peer: not a multiaddr — skipped");
            Vec::new()
        }
    }
}

impl NetworkConfig {
    pub fn from_env() -> Self {
        let listen_port = std::env::var("NEV369_P2P_PORT")
            .unwrap_or_else(|_| "9369".to_string())
            .parse()
            .unwrap_or(9369);
        let bootstrap_peers = std::env::var("NEV369_BOOTSTRAP_PEERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .flat_map(resolve_bootstrap)
            .collect();
        Self {
            listen_port,
            bootstrap_peers,
        }
    }
}

fn build_sync_behaviour() -> request_response::cbor::Behaviour<SyncRequest, SyncResponse> {
    request_response::cbor::Behaviour::new(
        [(SYNC_PROTOCOL, ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(20)),
    )
}

// ── Gossip handling — delegates entirely to BlockchainApp ──────────────

/// A gossiped block goes through exactly the same `accept_block` path a
/// mined block does. No separate fork-resolution logic here: `AcceptOutcome`
/// already tells the caller what happened (Extended / Reorganised /
/// SideChain / Orphaned / Duplicate), and `accept_block` has already done
/// whatever persistence and mempool reconciliation that outcome requires.
async fn handle_gossiped_block(
    block: Block,
    from_peer: PeerId,
    app_state: &SharedState,
    checkpoints: &SharedCheckpoints,
    reputation: &mut PeerReputation,
) {
    let hash = block.hash.clone();
    let mut app = app_state.write().await;

    let outcome = match app.accept_block(block) {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(peer = %from_peer, error = %e, "rejected gossiped block");
            if reputation.add_strike(from_peer, "invalid block") {
                tracing::warn!(peer = %from_peer, "peer banned after repeated strikes");
            }
            return;
        }
    };

    if let AcceptOutcome::Reorganised { disconnected, .. } = &outcome {
        let cps = checkpoints.read().await;
        if let Some(height) = cps.forbids_discarding(disconnected) {
            // The block validated and the tree accepted it, but committing
            // this reorg would discard a checkpointed block. This can only
            // be reached if MAX_REORG_DEPTH (consensus.rs) let something
            // through that a checkpoint independently forbids — belt and
            // suspenders. There is no clean undo at this layer; surface it
            // loudly rather than silently keep serving a chain state that
            // disagrees with the checkpoint pin.
            tracing::error!(
                peer = %from_peer, checkpoint_height = height,
                "REORG CROSSED A CHECKPOINT — chain state and checkpoint pin now disagree, \
                 manual intervention required"
            );
        }
    }

    tracing::debug!(peer = %from_peer, hash = %hash, ?outcome, "gossiped block processed");

    // Whatever this block unlocked, connect it now — a formerly-orphaned
    // child of THIS block may itself have been buffered.
    let connected = app.connect_orphans(&hash);
    if connected > 0 {
        tracing::info!(connected, "buffered orphans connected after gossiped block");
    }
}

async fn handle_gossiped_transaction(
    tx: Transaction,
    from_peer: PeerId,
    app_state: &SharedState,
    reputation: &mut PeerReputation,
) {
    let mut app = app_state.write().await;
    match app.submit_transaction(tx) {
        Ok(_hash) => {}
        // Duplicate/ConflictsWithPending are routine gossip noise (the
        // same tx often arrives from several peers) — not a strike.
        Err(crate::chain::ChainError::Duplicate)
        | Err(crate::chain::ChainError::ConflictsWithPending) => {}
        Err(e) => {
            tracing::warn!(peer = %from_peer, error = %e, "rejected gossiped transaction");
            if reputation.add_strike(from_peer, "invalid transaction") {
                tracing::warn!(peer = %from_peer, "peer banned after repeated strikes");
            }
        }
    }
}

// ── Sync request handling (we are the one being asked) ─────────────────

async fn handle_sync_request(request: SyncRequest, app_state: &SharedState) -> SyncResponse {
    let app = app_state.read().await;
    match request {
        SyncRequest::Status => SyncResponse::Status {
            height: app.height(),
            tip_hash: app.latest_hash(),
            cumulative_work: app.cumulative_work().to_string(),
            genesis_hash: app
                .chain
                .first()
                .map(|b| b.hash.clone())
                .unwrap_or_default(),
        },
        SyncRequest::FindForkPoint { locator } => SyncResponse::ForkPoint {
            hash: app.find_fork_point(&locator),
        },
        SyncRequest::GetBlocks { after_hash, limit } => {
            let capped = limit.min(SYNC_BATCH_SIZE);
            // Ask for one extra to know whether more remain, without
            // exposing that probe as part of the returned batch.
            let mut blocks = app.blocks_after(&after_hash, capped + 1);
            let has_more = blocks.len() > capped;
            blocks.truncate(capped);
            SyncResponse::Blocks { blocks, has_more }
        }
    }
}

// ── Sync response handling (we asked, peer answered) ────────────────────

struct SyncState {
    session: SyncSession,
    peer: PeerId,
}

async fn handle_sync_response(
    from: PeerId,
    request_id: OutboundRequestId,
    response: SyncResponse,
    app_state: &SharedState,
    in_flight: &mut HashMap<OutboundRequestId, SyncState>,
    swarm_sync: &mut request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    known_peer_ids: &HashSet<PeerId>,
) {
    let Some(SyncState { peer, mut session }) = in_flight.remove(&request_id) else {
        // Untracked reply: the only peer we know is the one that sent it.
        let peer = from;
        // Status probe sent outside a tracked session, or a stale reply.
        // Only real actionable case here is a fresh Status we decide is
        // worth following up on.
        if let SyncResponse::Status { .. } = &response {
            let app = app_state.read().await;
            let our_work = app.cumulative_work();
            let our_genesis = app
                .chain
                .first()
                .map(|b| b.hash.clone())
                .unwrap_or_default();
            drop(app);

            match should_sync_from(our_work, &response, &our_genesis) {
                Ok(true) => {
                    let app = app_state.read().await;
                    let locator = app.locator();
                    let target_height = if let SyncResponse::Status { height, .. } = &response {
                        *height
                    } else {
                        0
                    };
                    drop(app);
                    let req_id =
                        swarm_sync.send_request(&peer, SyncRequest::FindForkPoint { locator });
                    in_flight.insert(
                        req_id,
                        SyncState {
                            peer,
                            session: SyncSession::new(
                                peer.to_string(),
                                target_height,
                                response.work(),
                            ),
                        },
                    );
                }
                Ok(false) => {}
                Err(reason) => tracing::warn!(peer = %peer, reason, "not syncing from peer"),
            }
        }
        let _ = known_peer_ids; // reserved for future peer-selection heuristics
        return;
    };

    if let Some(reason) = session.should_abort() {
        tracing::warn!(peer = %peer, reason, "aborting sync session");
        return;
    }

    match response {
        SyncResponse::ForkPoint {
            hash: Some(fork_hash),
        } => {
            session.fork_point = Some(fork_hash.clone());
            let req_id = swarm_sync.send_request(
                &peer,
                SyncRequest::GetBlocks {
                    after_hash: fork_hash,
                    limit: SYNC_BATCH_SIZE,
                },
            );
            in_flight.insert(req_id, SyncState { peer, session });
        }
        SyncResponse::ForkPoint { hash: None } => {
            tracing::warn!(peer = %peer, "peer found no shared history despite matching genesis — not syncing");
        }
        SyncResponse::Blocks { blocks, has_more } => {
            if blocks.is_empty() {
                tracing::debug!(peer = %peer, "sync complete — peer had nothing further");
                return;
            }
            let last_hash = blocks.last().unwrap().hash.clone();
            let batch_len = blocks.len();

            let mut app = app_state.write().await;
            for block in blocks {
                let hash = block.hash.clone();
                match app.accept_block(block) {
                    Ok(_) => {
                        app.connect_orphans(&hash);
                    }
                    Err(e) => {
                        tracing::warn!(peer = %peer, error = %e, "sync block rejected — aborting session");
                        return;
                    }
                }
            }
            drop(app);

            session.blocks_received += batch_len;
            tracing::info!(peer = %peer, received = session.blocks_received, "sync batch applied");

            if has_more {
                let req_id = swarm_sync.send_request(
                    &peer,
                    SyncRequest::GetBlocks {
                        after_hash: last_hash,
                        limit: SYNC_BATCH_SIZE,
                    },
                );
                in_flight.insert(req_id, SyncState { peer, session });
            } else {
                tracing::info!(peer = %peer, total = session.blocks_received, "sync session complete");
            }
        }
        SyncResponse::Refused { reason } => {
            tracing::warn!(peer = %peer, reason, "peer refused sync request");
        }
        SyncResponse::Status { .. } => {
            // Shouldn't arrive mid-session; ignore rather than panic.
        }
    }
}

// ── Swarm setup and event loop ──────────────────────────────────────────

pub async fn spawn_network(
    app_state: SharedState,
    checkpoints: SharedCheckpoints,
    config: NetworkConfig,
) -> Result<NetworkCommandSender, Box<dyn std::error::Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    tracing::info!(peer_id = %local_peer_id, "P2P identity generated (transport identity — separate from GodShield signing keys)");

    let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            };
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                // Dilithium5 signatures are ~4.6 KB; a block with many
                // transactions is large. See sync.rs's SYNC_BATCH_SIZE
                // comment for the same reasoning applied to sync batches.
                .max_transmit_size(4 * 1024 * 1024)
                .build()
                .expect("valid gossipsub config");
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("valid gossipsub");
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .expect("valid mdns");
            let identify = identify::Behaviour::new(identify::Config::new(
                "/nev369/1.0.0".to_string(),
                key.public(),
            ));
            let ping = ping::Behaviour::new(ping::Config::default());
            let sync = build_sync_behaviour();
            Nev369Behaviour {
                gossipsub,
                mdns,
                identify,
                ping,
                sync,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let blocks_topic = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
    let tx_topic = gossipsub::IdentTopic::new(TOPIC_TX);
    swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)?;
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", config.listen_port).parse()?)?;
    for addr in &config.bootstrap_peers {
        match swarm.dial(addr.clone()) {
            Ok(()) => tracing::info!(peer = %addr, "dialling bootstrap peer"),
            Err(e) => tracing::warn!(peer = %addr, error = %e, "bootstrap dial failed"),
        }
    }

    // Re-dial the bootstrap list whenever this node has no peers at all.
    // Without it, a server reboot or a dropped Wi-Fi connection left a
    // miner cut off, mining a chain nobody else saw, until restarted.
    let bootstrap = config.bootstrap_peers.clone();
    let mut redial = tokio::time::interval_at(
        tokio::time::Instant::now() + BOOTSTRAP_REDIAL,
        BOOTSTRAP_REDIAL,
    );
    redial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<NetworkCommand>();
    let mut reputation = PeerReputation::new();
    let mut in_flight: HashMap<OutboundRequestId, SyncState> = HashMap::new();
    let mut known_peers: HashSet<PeerId> = HashSet::new();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = redial.tick(), if !bootstrap.is_empty() => {
                    if swarm.connected_peers().next().is_none() {
                        for addr in &bootstrap {
                            match swarm.dial(addr.clone()) {
                                Ok(()) => tracing::info!(peer = %addr, "no peers — re-dialling bootstrap peer"),
                                Err(e) => tracing::debug!(peer = %addr, error = %e, "bootstrap re-dial failed"),
                            }
                        }
                    }
                }

                Some(cmd) = cmd_rx.recv() => {
                    let (topic, payload) = match cmd {
                        NetworkCommand::BroadcastBlock(block) => (blocks_topic.clone(), GossipMessage::NewBlock(block)),
                        NetworkCommand::BroadcastTransaction(tx) => (tx_topic.clone(), GossipMessage::NewTransaction(tx)),
                    };
                    if let Ok(bytes) = serde_json::to_vec(&payload) {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                            tracing::debug!(error = %e, "gossip publish failed (no peers yet?)");
                        }
                    }
                }

                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(Nev369BehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                            if reputation.is_banned(&propagation_source) { continue; }

                            match serde_json::from_slice::<GossipMessage>(&message.data) {
                                Ok(GossipMessage::NewBlock(block)) => {
                                    handle_gossiped_block(block, propagation_source, &app_state, &checkpoints, &mut reputation).await;
                                }
                                Ok(GossipMessage::NewTransaction(tx)) => {
                                    handle_gossiped_transaction(tx, propagation_source, &app_state, &mut reputation).await;
                                }
                                Err(e) => tracing::warn!(error = %e, "failed to deserialize gossip message"),
                            }
                        }

                        SwarmEvent::Behaviour(Nev369BehaviourEvent::Sync(request_response::Event::Message { peer, message, .. })) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => {
                                    let response = handle_sync_request(request, &app_state).await;
                                    let _ = swarm.behaviour_mut().sync.send_response(channel, response);
                                }
                                request_response::Message::Response { request_id, response } => {
                                    handle_sync_response(peer, request_id, response, &app_state, &mut in_flight, &mut swarm.behaviour_mut().sync, &known_peers).await;
                                    let _ = peer;
                                }
                            }
                        }

                        SwarmEvent::Behaviour(Nev369BehaviourEvent::Sync(request_response::Event::OutboundFailure { request_id, error, .. })) => {
                            tracing::warn!(?error, "sync request failed");
                            in_flight.remove(&request_id);
                        }

                        SwarmEvent::Behaviour(Nev369BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                            for (peer_id, _addr) in peers {
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                known_peers.insert(peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(Nev369BehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                            for (peer_id, _addr) in peers {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                known_peers.remove(&peer_id);
                            }
                        }

                        // New connection: ask where they are. This is what
                        // kicks off catch-up sync for a node that just
                        // joined — nothing else triggers a Status probe.
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            CONNECTED_PEERS.store(swarm.connected_peers().count(), std::sync::atomic::Ordering::Relaxed);
                            let req_id = swarm.behaviour_mut().sync.send_request(&peer_id, SyncRequest::Status);
                            // No SyncState tracked yet — handle_sync_response's
                            // "not found in in_flight" branch treats a bare
                            // Status reply as the entry point into a session.
                            let _ = req_id;
                        }

                        SwarmEvent::ConnectionClosed { .. } => {
                            CONNECTED_PEERS.store(swarm.connected_peers().count(), std::sync::atomic::Ordering::Relaxed);
                        }

                        SwarmEvent::NewListenAddr { address, .. } => {
                            tracing::info!(address = %address, "P2P node listening");
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(cmd_tx)
}

#[cfg(test)]
mod tests {
    use super::resolve_bootstrap;

    #[test]
    fn a_dns_bootstrap_entry_resolves_to_ip_addresses() {
        let got = resolve_bootstrap("/dns4/localhost/tcp/4001");
        assert!(
            got.iter()
                .any(|m| m.to_string() == "/ip4/127.0.0.1/tcp/4001"),
            "{got:?}"
        );
        assert!(got.iter().all(|m| m.to_string().starts_with("/ip4/")));
    }

    #[test]
    fn a_peer_id_suffix_is_kept() {
        let id = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        let got = resolve_bootstrap(&format!("/dns4/localhost/tcp/4001/p2p/{id}"));
        assert!(
            got.iter()
                .any(|m| m.to_string() == format!("/ip4/127.0.0.1/tcp/4001/p2p/{id}")),
            "{got:?}"
        );
    }

    #[test]
    fn ip_multiaddrs_pass_through_and_junk_is_skipped() {
        let got = resolve_bootstrap(" /ip4/203.0.113.7/tcp/4001 ");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to_string(), "/ip4/203.0.113.7/tcp/4001");
        assert!(resolve_bootstrap("not an address").is_empty());
        assert!(resolve_bootstrap("/dns4/localhost/tcp/notaport").is_empty());
    }
}
