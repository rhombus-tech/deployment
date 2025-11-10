use ethereum_types::{H160, H256, U256};
use std::fmt;
use serde::{Serialize, Deserialize};

/// Ethereum compatible address
pub type Address = H160;

/// Raw byte data
pub type Bytes = Vec<u8>;

/// Representation of a block height
pub type BlockHeight = u64;

/// Gas measurement for computation
pub type Gas = U256;

/// Storage key in the state trie
pub type StorageKey = H256;

/// Storage value in the state trie
pub type StorageValue = H256;

/// Transaction ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionId(pub H256);

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

/// State root hash
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct StateRoot(pub H256);

impl fmt::Display for StateRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

/// Hash of a transaction sequence
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SequenceHash(pub H256);

impl fmt::Display for SequenceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0.as_bytes()))
    }
}

/// Priority level for transaction execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Medium
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// No verification, use with caution
    None,
    /// Basic syntax and format checks
    Basic,
    /// Standard security checks
    Standard,
    /// Comprehensive security verification
    Comprehensive,
    /// Custom verification rules
    Custom(u8),
}

impl VerificationLevel {
    /// Convert verification level to u32 for serialization
    pub fn to_u32(&self) -> u32 {
        match self {
            VerificationLevel::None => 0,
            VerificationLevel::Basic => 1,
            VerificationLevel::Standard => 2,
            VerificationLevel::Comprehensive => 3,
            VerificationLevel::Custom(level) => 100 + (*level as u32),
        }
    }
}
