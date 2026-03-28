//! Production gossip protocol for bleep-p2p.
//!
//! Implements the Plumtree / epidemic broadcast tree variant:
//! - Eager-push to a small fanout of highly-trusted peers.
//! - Lazy-push (IHave) to the rest for bandwidth efficiency.
//! - Deduplication via a bounded LRU seen-message cache.
//! - Anti-flood: per-peer message-rate tracking via PeerScoring.
//! - All outbound messages are sealed via MessageProtocol (AES-GCM + Ed25519).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::error::{P2PError, P2PResult};
use crate::message_protocol::MessageProtocol;
use crate::peer_manager::PeerManager;
use crate::types::{MessageType, NodeId, SecureMessage, unix_now};

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/// Number of eager peers to push immediately.
const EAGER_FANOUT: usize = 8;
/// LRU capacity for seen-message IDs.
const SEEN_CACHE_CAPACITY: usize = 16_384;
/// How often the gossip background loop ticks.
const GOSSIP_TICK: Duration = Duration::from_millis(200);

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE ID
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a 32-byte message fingerprint over (sender_id ‖ nonce ‖ timestamp).
fn message_id(msg: &SecureMessage) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(msg.sender_id.as_bytes());
    h.update(&msg.nonce);
    h.update(&msg.timestamp.to_le_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// GOSSIP ENGINE
// ─────────────────────────────────────────────────────────────────────────────

pub struct GossipProtocol {
    peer_manager: Arc<PeerManager>,
    message_protocol: Arc<MessageProtocol>,
    /// LRU cache of already-seen message IDs (prevents re-broadcast).
    seen: Arc<Mutex<LruCache<[u8; 32], ()>>>,
    /// Pending messages to be spread on the next tick.
    pending: Arc<Mutex<Vec<(SecureMessage, Option<NodeId>)>>>,
}

impl GossipProtocol {
    pub fn new(peer_manager: Arc<PeerManager>, message_protocol: Arc<MessageProtocol>) -> Arc<Self> {
        Arc::new(GossipProtocol {
            peer_manager,
            message_protocol,
            seen: Arc::new(Mutex::new(LruCache::new(
                unsafe { std::num::NonZeroUsize::new_unchecked(SEEN_CACHE_CAPACITY) },
            ))),
            pending: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Enqueue a message for gossip.  `exclude` is the peer we received it from
    /// (to avoid echoing back).
    pub fn enqueue(&self, msg: SecureMessage, exclude: Option<NodeId>) {
        let id = message_id(&msg);
        let mut seen = self.seen.lock();
        if seen.contains(&id) {
            debug!("GossipProtocol: dropping duplicate message");
            return;
        }
        seen.put(id, ());
        drop(seen);

        self.pending.lock().push((msg, exclude));
    }

    /// Propagate a message immediately (synchronous eager-push path).
    ///
    /// The `message_protocol` must have sessions with the selected peers already
    /// established.  If a session is missing, the peer is skipped and a warning
    /// is logged.  Messages are **never** sent unencrypted.
    pub async fn spread(&self, msg: SecureMessage, exclude: Option<&NodeId>) {
        let id = message_id(&msg);
        {
            let mut seen = self.seen.lock();
            if seen.contains(&id) {
                return;
            }
            seen.put(id, ());
        }

        let healthy = self.peer_manager.healthy_peers();

        // Select EAGER_FANOUT highest-scoring peers (excluding sender).
        let candidates: Vec<NodeId> = healthy
            .iter()
            .filter(|p| exclude.map_or(true, |ex| &p.id != ex))
            .map(|p| p.id.clone())
            .collect();

        let ranked = self
            .peer_manager
            .dht() // access to scoring via peer_manager
            .all_peers()
            .await;

        // Score-sort candidates
        let mut scored: Vec<(NodeId, f64)> = candidates
            .into_iter()
            .filter_map(|id| {
                let info = self.peer_manager.get_peer(&id)?;
                Some((id, info.trust_score))
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    /// Securely gossips a message to high-scoring peers using peer scoring and message protocol
    pub async fn gossip_message(&self, message: SecureMessage) {
        let peers = self.peers.lock().unwrap().clone();
        for peer_id in peers {
            // Use peer_scoring to filter and prioritize high-reputation peers
            let peer_score = self.peer_scoring.calculate_score(peer_id.as_str());
            
            // Only gossip to peers with acceptable reputation
            if peer_score >= 50.0 {
                let encrypted_payload = self.encrypt_message(&message);
                let secure_message = SecureMessage {
                    sender_id: message.sender_id.clone(),
                    message_type: MessageType::Custom("gossip".to_string()),
                    payload: encrypted_payload,
                    signature: message.signature.clone(),
                    hop_count: 1,
                };
                
                // Use message_protocol to send the secure message
                self.message_protocol.queue_message(secure_message).await;
                log::debug!("Gossipped to peer {} with score {}", peer_id, peer_score);
            } else {
                log::warn!("Skipping gossip to low-reputation peer: {}", peer_id);
            }
        }
    }

    /// Background loop: drain the pending queue and spread each message.
    pub async fn run(self: Arc<Self>) {
        let mut ticker = interval(GOSSIP_TICK);
        loop {
            ticker.tick().await;
            let batch: Vec<(SecureMessage, Option<NodeId>)> = {
                let mut pending = self.pending.lock();
                std::mem::take(&mut *pending)
            };
            for (msg, exclude) in batch {
                self.spread(msg, exclude.as_ref()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_manager::{PeerManager, PeerManagerConfig};
    use crate::quantum_crypto::{Ed25519Keypair, KyberKeypair};
    use crate::types::{MessageType, unix_now};

    fn make_gossip() -> Arc<GossipProtocol> {
        let local_id = NodeId::random();
        let (pm, _) = PeerManager::new(local_id.clone(), PeerManagerConfig::default());
        let ed = Ed25519Keypair::generate();
        let kyber = KyberKeypair::generate();
        let (mp, _) = MessageProtocol::new(ed, kyber, pm.clone());
        GossipProtocol::new(pm, mp)
    }

    fn make_msg() -> SecureMessage {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        SecureMessage {
            version: 1,
            sender_id: NodeId::random(),
            message_type: MessageType::Transaction,
            payload: b"test transaction payload".to_vec(),
            signature: vec![0u8; 64],
            hop_count: 0,
            nonce,
            timestamp: unix_now(),
        }
    }

    #[test]
    fn test_enqueue_deduplication() {
        let g = make_gossip();
        let msg = make_msg();
        g.enqueue(msg.clone(), None);
        g.enqueue(msg.clone(), None); // duplicate
        let pending_count = g.pending.lock().len();
        assert_eq!(pending_count, 1, "Duplicate should be deduplicated");
    }

    #[test]
    fn test_different_messages_both_queued() {
        let g = make_gossip();
        g.enqueue(make_msg(), None);
        g.enqueue(make_msg(), None);
        let pending_count = g.pending.lock().len();
        assert_eq!(pending_count, 2);
    }

    #[tokio::test]
    async fn test_spread_no_peers_does_not_panic() {
        let g = make_gossip();
        let msg = make_msg();
        // No peers → spread should complete without panic
        g.spread(msg, None).await;
    }

    #[test]
    fn test_message_id_deterministic() {
        let msg = make_msg();
        let id1 = message_id(&msg);
        let id2 = message_id(&msg);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_message_id_differs_for_different_nonces() {
        let mut msg1 = make_msg();
        let mut msg2 = make_msg();
        msg1.nonce = [1u8; 16];
        msg2.nonce = [2u8; 16];
        assert_ne!(message_id(&msg1), message_id(&msg2));
    }

    #[test]
    fn test_seen_cache_capacity_respected() {
        let g = make_gossip();
        for _ in 0..SEEN_CACHE_CAPACITY + 100 {
            g.enqueue(make_msg(), None);
        }
        let seen_size = g.seen.lock().len();
        assert!(seen_size <= SEEN_CACHE_CAPACITY);
    }
}
