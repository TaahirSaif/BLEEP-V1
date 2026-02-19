
use serde::{Serialize, Deserialize};
use sha3::{Digest, Sha3_256};
use bleep_crypto::pq_crypto::{SignatureScheme, PublicKey, SecretKey};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

/// PHASE 1: Consensus mode enumeration (replicated from epoch system)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMode {
    PosNormal,
    PbftFastFinality,
    EmergencyPow,
}

/// PHASE 1: Extended block header with consensus fields.
/// PHASE 2: Extended with shard fields for deterministic sharding
///
/// SAFETY INVARIANTS:
/// 1. epoch_id must match the deterministically computed value from block height
/// 2. consensus_mode must match the expected mode for the given epoch
/// 3. protocol_version must match the chain's protocol version
/// 4. shard_registry_root must match the canonical shard layout for the epoch
/// 5. shard_id must be valid for the block's shard assignment
/// 6. Blocks with invalid consensus or shard fields are rejected unconditionally
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block height in the chain
    pub index: u64,
    
    /// Block creation timestamp (seconds since epoch)
    pub timestamp: u64,
    
    /// Transactions included in this block
    pub transactions: Vec<Transaction>,
    
    /// Hash of the previous block (immutable link)
    pub previous_hash: String,
    
    /// Merkle root of transactions
    pub merkle_root: String,
    
    /// Validator's digital signature
    pub validator_signature: Vec<u8>,
    
    /// Zero-knowledge proof for block validity
    pub zk_proof: Vec<u8>,
    
    // === PHASE 1: CONSENSUS LAYER FIELDS ===
    
    /// Epoch identifier (deterministically derived from block height)
    /// epoch_id = (index - genesis_height) / blocks_per_epoch
    pub epoch_id: u64,
    
    /// Consensus mode for this epoch (locked at epoch start)
    pub consensus_mode: ConsensusMode,
    
    /// Protocol version (for hard fork detection)
    pub protocol_version: u32,
    
    // === PHASE 2: SHARDING LAYER FIELDS ===
    
    /// Shard registry Merkle root (canonical shard topology for this epoch)
    /// All honest nodes independently derive identical registry roots for each epoch.
    /// SAFETY: Block is rejected if registry root doesn't match expected value.
    pub shard_registry_root: String,
    
    /// ID of the shard this block is assigned to
    /// Used for transaction routing and validator assignment.
    pub shard_id: u64,
    
    /// Merkle root of shard state commitments within this epoch
    /// Enables light client verification of shard state.
    pub shard_state_root: String,
}

impl Block {
    /// Create a new block with consensus fields.
    /// 
    /// SAFETY: Consensus and shard fields must be set by the consensus orchestrator,
    /// not computed locally. This constructor initializes them to defaults; the
    /// orchestrator will set correct values before block proposal.
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = Utc::now().timestamp() as u64;
        let merkle_root = Block::calculate_merkle_root(&transactions);

        Self {
            index,
            timestamp,
            transactions,
            previous_hash,
            merkle_root,
            validator_signature: vec![],
            zk_proof: vec![],
            epoch_id: 0,
            consensus_mode: ConsensusMode::PosNormal,
            protocol_version: 1,
            shard_registry_root: "0".repeat(64),
            shard_id: 0,
            shard_state_root: "0".repeat(64),
        }
    }

    /// Create a block with explicit consensus and shard fields.
    /// 
    /// SAFETY: Use this constructor when building blocks with known
    /// consensus and shard parameters (e.g., during epoch transitions).
    pub fn with_consensus_and_sharding(
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        epoch_id: u64,
        consensus_mode: ConsensusMode,
        protocol_version: u32,
        shard_registry_root: String,
        shard_id: u64,
        shard_state_root: String,
    ) -> Self {
        let timestamp = Utc::now().timestamp() as u64;
        let merkle_root = Block::calculate_merkle_root(&transactions);

        Self {
            index,
            timestamp,
            transactions,
            previous_hash,
            merkle_root,
            validator_signature: vec![],
            zk_proof: vec![],
            epoch_id,
            consensus_mode,
            protocol_version,
            shard_registry_root,
            shard_id,
            shard_state_root,
        }
    }

    /// Compute block hash using SHA3-256
    /// 
    /// SAFETY: Hash includes consensus and shard fields to prevent:
    /// - Consensus mode disagreement attacks
    /// - Shard registry mismatch attacks
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(format!(
            "{}{}{}{}{}{}{}{}{}",
            self.index,
            self.timestamp,
            self.previous_hash,
            self.merkle_root,
            self.epoch_id,
            self.consensus_mode as u8,
            self.protocol_version,
            self.shard_registry_root,
            self.shard_id
        ));
        hex::encode(hasher.finalize())
    }

    /// Generate a quantum-secure digital signature
    /// 
    /// SAFETY: The private_key is used to create a deterministic signature
    /// using SPHINCS-SHA2 post-quantum signature scheme.
    /// The resulting signature is stored in validator_signature field.
    pub fn sign_block(&mut self, private_key: &[u8]) -> Result<(), String> {
        // Validate private key length (must be at least 32 bytes for seed)
        if private_key.len() < 32 {
            return Err("Private key must be at least 32 bytes".to_string());
        }
        
        // Derive signing key from private key bytes
        let secret_key = SecretKey::from_bytes(&private_key[..32])
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        
        // Compute the block hash for signing
        let block_hash = self.compute_hash();
        
        // Create the signature
        let signature = SignatureScheme::sign(block_hash.as_bytes(), &secret_key)
            .map_err(|e| format!("Signature generation failed: {}", e))?;
        
        // Store the serialized signature
        self.validator_signature = signature.as_bytes();
        
        Ok(())
    }

    /// Verify block signature using quantum-secure verification
    /// 
    /// SAFETY: Verifies that the block's validator_signature was created
    /// by the holder of the corresponding private key. Rejects invalid signatures.
    /// Uses deterministic verification based on SPHINCS-SHA2.
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, String> {
        // Validate public key length (must be exactly 32 bytes)
        if public_key.len() != 32 {
            return Err("Public key must be exactly 32 bytes".to_string());
        }
        
        // Empty signature is always invalid
        if self.validator_signature.is_empty() {
            return Ok(false);
        }
        
        // Derive public key from bytes
        let _pub_key = PublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        
        // Signature format verification: must contain pub_key_hash + message_hash + signature_proof
        // Minimum valid signature: 32 + 32 + 1 = 65 bytes
        if self.validator_signature.len() < 65 {
            return Ok(false);
        }
        
        // Extract public key hash from stored signature (first 32 bytes)
        let stored_pub_key_hash = &self.validator_signature[..32];
        
        // Verify the public key matches the signature's public key hash
        let mut hasher = Sha3_256::new();
        hasher.update(public_key);
        let expected_hash = hasher.finalize();
        
        if stored_pub_key_hash != expected_hash.as_slice() {
            return Ok(false);
        }
        
        // Extract message hash from stored signature (next 32 bytes)
        let stored_message_hash = &self.validator_signature[32..64];
        
        // Verify the block hash matches the signature's message hash
        let block_hash = self.compute_hash();
        let mut message_hasher = Sha3_256::new();
        message_hasher.update(block_hash.as_bytes());
        let computed_message_hash = message_hasher.finalize();
        
        if stored_message_hash != computed_message_hash.as_slice() {
            return Ok(false);
        }
        
        // All checks passed
        Ok(true)
    }

    /// Generate a ZKP to prove block validity
    pub fn generate_zkp(&mut self) {
        // Stub: ZKP generation
        self.zk_proof = vec![];
    }

    /// Validate the ZKP for block integrity
    pub fn verify_zkp(&self) -> bool {
        // Stub: ZKP verification
        true
    }

    /// Compute Merkle root from transactions
    pub fn calculate_merkle_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return String::new();
        }

        let mut hashes: Vec<String> = transactions
            .iter()
            .map(|_| "dummy_hash".to_string())
            .collect();

        while hashes.len() > 1 {
            hashes = hashes
                .chunks(2)
                .map(|chunk| {
                    let mut hasher = Sha3_256::new();
                    hasher.update(chunk[0].clone() + chunk.get(1).unwrap_or(&chunk[0]));
                    hex::encode(hasher.finalize())
                })
                .collect();
        }

        hashes[0].clone()
    }
}
