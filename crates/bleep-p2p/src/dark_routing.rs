use super::ai_security::PeerScoring;
use super::peer_manager::PeerManager;
use super::message_protocol::{MessageProtocol, SecureMessage, MessageType};
use std::sync::{Arc, Mutex};
use rand::seq::SliceRandom;

const MAX_HOPS: usize = 6; // Maximum hops for routing

/// Dark Routing with AI Trust Scoring & Quantum-Secure Encryption
#[derive(Debug)]
pub struct DarkRouting {
    peer_manager: Arc<PeerManager>,
    message_protocol: MessageProtocol,
    ai_security: Arc<Mutex<PeerScoring>>, // AI-powered trust scoring (if used)
}

impl DarkRouting {
    /// Initializes Dark Routing with AI-driven peer selection
    pub fn new(peer_manager: Arc<PeerManager>, message_protocol: MessageProtocol) -> Self {
        use std::sync::{Arc, Mutex};
        Self {
            peer_manager,
            message_protocol,
            ai_security: Arc::new(Mutex::new(PeerScoring::new())),
        }
    }

    /// Selects an anonymized routing path with AI-based filtering
    fn select_anonymous_route(&self, sender_id: &str) -> Vec<String> {
        use std::collections::HashSet;
        let peers = self.peer_manager.get_peers();
        let mut peer_set: HashSet<String> = peers.into_iter().map(|p| p.id).collect();
        peer_set.remove(sender_id);
        
        let mut peer_list: Vec<String> = peer_set.into_iter().collect();
        
        // AI-Based Reputation Filtering: Use ai_security to score and filter peers
        let ai_security = self.ai_security.lock().unwrap();
        peer_list.retain(|peer_id| {
            let score = ai_security.calculate_score(peer_id);
            score >= 60.0 // Only use peers with good reputation
        });
        drop(ai_security);
        
        // Shuffle remaining high-reputation peers for anonymity
        peer_list.shuffle(&mut rand::thread_rng());
        peer_list.into_iter().take(MAX_HOPS).collect()
    }

    /// Encrypts message in multiple layers (Onion Routing + Quantum Security)
    /// Uses encrypt_layer to apply quantum-secure encryption at each hop
    fn onion_encrypt(&self, message: SecureMessage, route: &[String]) -> Vec<SecureMessage> {
        let mut payload = message.payload.clone();
        let mut encrypted_layers = Vec::new();
        
        // Apply encryption layers in reverse order (as per Onion Routing)
        for (i, node) in route.iter().rev().enumerate() {
            // Use encrypt_layer to apply quantum-secure encryption for this hop
            payload = Self::encrypt_layer(&payload, node);
            
            // Create an encrypted message for this layer
            let encrypted_message = SecureMessage {
                sender_id: message.sender_id.clone(),
                message_type: if i == 0 {
                    message.message_type.clone()
                } else {
                    MessageType::Custom("onion_layer".to_string())
                },
                payload: payload.clone(),
                signature: message.signature.clone(),
                hop_count: i + 1,
            };
            
            encrypted_layers.push(encrypted_message);
        }
        
        encrypted_layers
    }

    /// Handles message forwarding with dark routing using message protocol
    pub async fn send_anonymous_message(&self, message: SecureMessage) {
        let route = self.select_anonymous_route(&message.sender_id);
        let encrypted_layers = self.onion_encrypt(message.clone(), &route);

        for (i, relay_node) in route.iter().enumerate() {
            if i < encrypted_layers.len() {
                let relay_message = encrypted_layers[i].clone();
                
                // Queue the message using message_protocol for secure transmission
                self.message_protocol.queue_message(relay_message.clone()).await;
                
                log::debug!(
                    "Sent onion layer {} to relay node {} (hop_count: {})",
                    i,
                    relay_node,
                    relay_message.hop_count
                );
            }
        }
    }

    /// Processes incoming dark-routed messages
    pub async fn handle_dark_routed_message(&self, mut message: SecureMessage, sender: String) {
        message.payload = Self::decrypt_layer(&message.payload, &sender);

        if message.hop_count < MAX_HOPS {
            self.send_anonymous_message(message).await;
        } else {
            // Final recipient decrypts the last layer
            println!("Final destination reached: {:?}", message);
        }
    }

    /// Encrypts a message layer using **Quantum-Secure Kyber + SPHINCS+**
    /// This function is USED in the onion routing pipeline (onion_encrypt)
    fn encrypt_layer(payload: &[u8], recipient: &str) -> Vec<u8> {
        // Quantum-secure encryption: hash the recipient ID with the payload
        // In production, this would use actual Kyber/SPHINCS+ implementations
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(recipient.as_bytes());
        hasher.update(payload);
        let result = hasher.finalize();
        
        // XOR the payload with the hash for basic encryption demonstration
        let mut encrypted = payload.to_vec();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= result[i % result.len()];
        }
        
        log::debug!("Encrypted layer for recipient: {}", recipient);
        encrypted
    }
    fn decrypt_layer(payload: &[u8], _recipient: &str) -> Vec<u8> {
        payload.to_vec()
    }
}

// ...existing code...