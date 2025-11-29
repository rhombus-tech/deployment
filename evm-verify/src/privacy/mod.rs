//! 🔒 ULTIMATE PRIVACY SYSTEM FOR zkEVM
//!
//! This module provides comprehensive transactional privacy while maintaining
//! security analysis and vulnerability detection capabilities.
//!
//! ## Features:
//! - Private sender addresses (zk-SNARK proofs)
//! - Private receiver addresses
//! - Optional amount hiding with range proofs
//! - Privacy-preserving smart contract calls
//! - Integrated vulnerability analysis for private transactions
//! - Regulatory compliance through selective disclosure

use anyhow::{anyhow, Result};
use ethers::types::{H160, H256, U256};
use serde::{Deserialize, Serialize};
use ark_bn254::Fr;
use ark_ff::Field;
use std::collections::HashMap;

pub mod circuits;
pub mod private_transaction;
pub mod range_proof;
pub mod selective_disclosure;

pub use circuits::*;
pub use private_transaction::*;
pub use range_proof::*;
pub use selective_disclosure::*;

/// Privacy level for transactions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrivacyLevel {
    /// Fully public (like standard Ethereum)
    Public,
    /// Private addresses, public amounts
    AddressPrivate,
    /// Private addresses and amounts
    FullyPrivate,
    /// Selective disclosure (regulatory compliance mode)
    SelectiveDisclosure,
}

/// Privacy mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Default privacy level for new transactions
    pub default_level: PrivacyLevel,
    /// Enable regulatory compliance features
    pub enable_selective_disclosure: bool,
    /// Require privacy for contract deployments
    pub require_private_deployments: bool,
    /// Allowed public transaction types
    pub public_transaction_allowlist: Vec<String>,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            default_level: PrivacyLevel::Public, // Start permissive
            enable_selective_disclosure: true,
            require_private_deployments: false,
            public_transaction_allowlist: vec![],
        }
    }
}

/// Privacy metadata attached to transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyMetadata {
    /// Privacy level used
    pub level: PrivacyLevel,
    /// Address commitment (hash)
    pub sender_commitment: H256,
    /// Receiver commitment (if private)
    pub receiver_commitment: Option<H256>,
    /// Amount commitment (if private)
    pub amount_commitment: Option<H256>,
    /// Nullifier (prevents double-spending in private mode)
    pub nullifier: H256,
    /// ZK proof that transaction is valid
    pub validity_proof: Vec<u8>,
    /// Optional disclosure key for regulatory compliance
    pub disclosure_key: Option<Vec<u8>>,
}

impl PrivacyMetadata {
    /// Create privacy metadata for a public transaction
    pub fn public(sender: H160, receiver: H160, amount: U256) -> Self {
        use sha3::{Keccak256, Digest};
        
        let mut hasher = Keccak256::new();
        hasher.update(sender.as_bytes());
        let sender_commitment = H256::from_slice(&hasher.finalize());
        
        let mut hasher = Keccak256::new();
        hasher.update(receiver.as_bytes());
        let receiver_commitment = H256::from_slice(&hasher.finalize());
        
        let mut hasher = Keccak256::new();
        hasher.update(&{ let mut bytes = [0u8; 32]; amount.to_big_endian(&mut bytes); bytes });
        hasher.update(&sender.as_bytes());
        let nullifier = H256::from_slice(&hasher.finalize());
        
        Self {
            level: PrivacyLevel::Public,
            sender_commitment,
            receiver_commitment: Some(receiver_commitment),
            amount_commitment: None,
            nullifier,
            validity_proof: vec![],
            disclosure_key: None,
        }
    }
}

/// Privacy-aware transaction pool
#[derive(Debug)]
pub struct PrivateTransactionPool {
    /// Pending private transactions
    pending: HashMap<H256, PrivateTransaction>,
    /// Used nullifiers (prevent double-spending)
    used_nullifiers: std::collections::HashSet<H256>,
    /// Privacy configuration
    config: PrivacyConfig,
}

impl PrivateTransactionPool {
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            pending: HashMap::new(),
            used_nullifiers: std::collections::HashSet::new(),
            config,
        }
    }
    
    /// Add a private transaction to the pool
    pub fn add_transaction(&mut self, tx: PrivateTransaction) -> Result<()> {
        // Verify nullifier is unique
        if self.used_nullifiers.contains(&tx.metadata.nullifier) {
            return Err(anyhow!("Transaction already spent (nullifier reuse)"));
        }
        
        // Verify privacy proof
        tx.verify_privacy_proof()?;
        
        // Add to pool
        let tx_id = tx.compute_id();
        self.pending.insert(tx_id, tx);
        
        Ok(())
    }
    
    /// Mark a transaction as executed (add nullifier to used set)
    pub fn mark_executed(&mut self, tx: &PrivateTransaction) {
        self.used_nullifiers.insert(tx.metadata.nullifier);
    }
    
    /// Get pending transactions
    pub fn get_pending(&self) -> Vec<&PrivateTransaction> {
        self.pending.values().collect()
    }
}

/// Privacy statistics and metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacyStats {
    /// Total transactions processed
    pub total_transactions: u64,
    /// Fully private transactions
    pub fully_private_count: u64,
    /// Address-only private transactions
    pub address_private_count: u64,
    /// Public transactions
    pub public_count: u64,
    /// Selective disclosure requests
    pub disclosure_requests: u64,
    /// Average privacy level (0-100)
    pub average_privacy_score: f64,
}

impl PrivacyStats {
    /// Calculate privacy score for a transaction
    pub fn privacy_score(level: PrivacyLevel) -> u8 {
        match level {
            PrivacyLevel::Public => 0,
            PrivacyLevel::AddressPrivate => 50,
            PrivacyLevel::FullyPrivate => 100,
            PrivacyLevel::SelectiveDisclosure => 75,
        }
    }
    
    /// Update stats with a new transaction
    pub fn record_transaction(&mut self, level: PrivacyLevel) {
        self.total_transactions += 1;
        
        match level {
            PrivacyLevel::Public => self.public_count += 1,
            PrivacyLevel::AddressPrivate => self.address_private_count += 1,
            PrivacyLevel::FullyPrivate => self.fully_private_count += 1,
            PrivacyLevel::SelectiveDisclosure => {
                self.fully_private_count += 1;
                self.disclosure_requests += 1;
            }
        }
        
        // Recalculate average
        let total_score = 
            (self.fully_private_count * 100) +
            (self.address_private_count * 50) +
            (self.public_count * 0);
        
        self.average_privacy_score = 
            total_score as f64 / self.total_transactions as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_privacy_stats() {
        let mut stats = PrivacyStats::default();
        
        stats.record_transaction(PrivacyLevel::Public);
        assert_eq!(stats.public_count, 1);
        assert_eq!(stats.average_privacy_score, 0.0);
        
        stats.record_transaction(PrivacyLevel::FullyPrivate);
        assert_eq!(stats.fully_private_count, 1);
        assert_eq!(stats.average_privacy_score, 50.0);
        
        stats.record_transaction(PrivacyLevel::FullyPrivate);
        assert_eq!(stats.average_privacy_score, 66.66666666666667);
    }
}
