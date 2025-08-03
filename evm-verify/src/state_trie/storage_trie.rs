// evm-verify/src/state_trie/storage_trie.rs
// Contract Storage Trie Implementation
//
// Implements per-contract storage tries as defined in Ethereum Yellow Paper.
// Each contract has its own storage trie for state variables.

use ethers::types::{H256, U256, Address, Bytes};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use tiny_keccak::{Keccak, Hasher};

use super::mpt::MerklePatriciaTrie;

/// Storage slot representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StorageSlot(pub U256);

impl StorageSlot {
    /// Create storage slot from U256
    pub fn new(slot: U256) -> Self {
        Self(slot)
    }
    
    /// Create storage slot from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(U256::from_big_endian(bytes))
    }
    
    /// Get slot as bytes (32 bytes, big-endian)
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.0.to_big_endian(&mut bytes);
        bytes
    }
    
    /// Get slot as key for trie (keccak256 of slot)
    pub fn as_trie_key(&self) -> [u8; 32] {
        let slot_bytes = self.as_bytes();
        let mut keccak = Keccak::v256();
        let mut output = [0u8; 32];
        keccak.update(&slot_bytes);
        keccak.finalize(&mut output);
        output
    }
}

/// Storage value representation
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageValue(pub U256);

impl StorageValue {
    /// Create storage value from U256
    pub fn new(value: U256) -> Self {
        Self(value)
    }
    
    /// Create storage value from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(U256::from_big_endian(bytes))
    }
    
    /// Get value as bytes (32 bytes, big-endian)
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.0.to_big_endian(&mut bytes);
        bytes
    }
    
    /// Check if value is zero
    pub fn is_zero(&self) -> bool {
        self.0 == U256::zero()
    }
    
    /// Get compressed representation (removes leading zeros for efficiency)
    pub fn compressed_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        
        let bytes = self.as_bytes();
        let mut start = 0;
        
        // Find first non-zero byte
        while start < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        
        if start == bytes.len() {
            vec![0]
        } else {
            bytes[start..].to_vec()
        }
    }
    
    /// Create from compressed bytes
    pub fn from_compressed_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() || (bytes.len() == 1 && bytes[0] == 0) {
            return Self(U256::zero());
        }
        
        let mut full_bytes = [0u8; 32];
        let start = 32 - bytes.len();
        full_bytes[start..].copy_from_slice(bytes);
        
        Self(U256::from_big_endian(&full_bytes))
    }
}

/// Contract storage trie
pub struct StorageTrie {
    /// Contract address
    contract_address: Address,
    
    /// Underlying MPT
    trie: MerklePatriciaTrie,
    
    /// Storage cache for performance
    storage_cache: HashMap<StorageSlot, StorageValue>,
    
    /// Dirty storage slots (for efficient commits)
    dirty_slots: HashMap<StorageSlot, StorageValue>,
    
    /// Statistics
    pub stats: StorageTrieStats,
}

#[derive(Debug, Default)]
pub struct StorageTrieStats {
    pub total_slots: usize,
    pub non_zero_slots: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub trie_operations: usize,
}

impl StorageTrie {
    /// Create new storage trie for contract
    pub fn new(contract_address: Address) -> Self {
        Self {
            contract_address,
            trie: MerklePatriciaTrie::new(),
            storage_cache: HashMap::new(),
            dirty_slots: HashMap::new(),
            stats: StorageTrieStats::default(),
        }
    }
    
    /// Get storage value for slot
    pub async fn get_storage(&mut self, slot: StorageSlot) -> Result<StorageValue> {
        // Check cache first
        if let Some(cached) = self.storage_cache.get(&slot) {
            self.stats.cache_hits += 1;
            return Ok(cached.clone());
        }
        
        self.stats.cache_misses += 1;
        
        // Get from trie
        let key = slot.as_trie_key();
        if let Some(data) = self.trie.get(&key).await? {
            let value = StorageValue::from_compressed_bytes(&data);
            self.storage_cache.insert(slot.clone(), value.clone());
            Ok(value)
        } else {
            // Return zero value for non-existent slots
            let zero_value = StorageValue::new(U256::zero());
            self.storage_cache.insert(slot, zero_value.clone());
            Ok(zero_value)
        }
    }
    
    /// Set storage value for slot
    pub async fn set_storage(&mut self, slot: StorageSlot, value: StorageValue) -> Result<()> {
        // Update cache and mark as dirty
        self.storage_cache.insert(slot.clone(), value.clone());
        self.dirty_slots.insert(slot, value.clone());
        
        // Update stats
        if !value.is_zero() {
            self.stats.non_zero_slots += 1;
        }
        self.stats.total_slots += 1;
        
        Ok(())
    }
    
    /// Batch set storage values
    pub async fn batch_set_storage(&mut self, updates: HashMap<StorageSlot, StorageValue>) -> Result<()> {
        for (slot, value) in updates {
            self.set_storage(slot, value).await?;
        }
        Ok(())
    }
    
    /// Remove storage slot (set to zero)
    pub async fn remove_storage(&mut self, slot: StorageSlot) -> Result<()> {
        self.set_storage(slot, StorageValue::new(U256::zero())).await
    }
    
    /// Commit all dirty slots to trie
    pub async fn commit(&mut self) -> Result<()> {
        for (slot, value) in self.dirty_slots.drain() {
            let key = slot.as_trie_key();
            self.stats.trie_operations += 1;
            
            if value.is_zero() {
                // Remove zero values from trie
                self.trie.remove(&key).await?;
            } else {
                // Store non-zero values
                let data = Bytes::from(value.compressed_bytes());
                self.trie.insert(&key, data).await?;
            }
        }
        Ok(())
    }
    
    /// Compute storage root
    pub async fn compute_root(&mut self) -> Result<H256> {
        // Commit dirty slots first
        self.commit().await?;
        
        // Return trie root
        Ok(self.trie.root())
    }
    
    /// Generate storage proof for slot
    pub async fn generate_proof(&self, slot: StorageSlot) -> Result<Vec<Bytes>> {
        let key = slot.as_trie_key();
        self.trie.generate_proof(&key).await
    }
    
    /// Verify storage proof
    pub fn verify_proof(
        root: H256,
        slot: StorageSlot,
        value: &StorageValue,
        proof: &[Bytes]
    ) -> Result<bool> {
        let key = slot.as_trie_key();
        let data = if value.is_zero() {
            Bytes::new() // Empty for zero values
        } else {
            Bytes::from(value.compressed_bytes())
        };
        MerklePatriciaTrie::verify_proof(root, &key, &data, proof)
    }
    
    /// Get all non-zero storage slots
    pub async fn get_all_storage(&mut self) -> Result<HashMap<StorageSlot, StorageValue>> {
        // Commit to ensure consistency
        self.commit().await?;
        
        let mut result = HashMap::new();
        
        // Add cached values
        for (slot, value) in &self.storage_cache {
            if !value.is_zero() {
                result.insert(slot.clone(), value.clone());
            }
        }
        
        Ok(result)
    }
    
    /// Clear caches (for memory management)
    pub fn clear_cache(&mut self) {
        self.storage_cache.clear();
    }
    
    /// Get contract address
    pub fn contract_address(&self) -> Address {
        self.contract_address
    }
    
    /// Get storage statistics
    pub fn get_stats(&self) -> &StorageTrieStats {
        &self.stats
    }
    
    /// Check if storage is empty
    pub fn is_empty(&self) -> bool {
        self.storage_cache.values().all(|v| v.is_zero())
    }
    
    /// Get dirty slot count
    pub fn dirty_slot_count(&self) -> usize {
        self.dirty_slots.len()
    }
    
    /// Check if slot exists (has non-zero value)
    pub async fn has_storage(&mut self, slot: StorageSlot) -> Result<bool> {
        let value = self.get_storage(slot).await?;
        Ok(!value.is_zero())
    }
    
    /// Get storage changes (dirty slots)
    pub fn get_storage_changes(&self) -> &HashMap<StorageSlot, StorageValue> {
        &self.dirty_slots
    }
    
    /// Revert uncommitted changes
    pub fn revert_changes(&mut self) {
        // Remove dirty values from cache
        for slot in self.dirty_slots.keys() {
            self.storage_cache.remove(slot);
        }
        self.dirty_slots.clear();
    }
}

/// Storage proof structure
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// Contract address
    pub contract_address: Address,
    
    /// Storage slot
    pub slot: StorageSlot,
    
    /// Storage value
    pub value: StorageValue,
    
    /// Merkle proof
    pub proof: Vec<Bytes>,
    
    /// Storage root
    pub storage_root: H256,
}

impl StorageProof {
    /// Create new storage proof
    pub fn new(
        contract_address: Address,
        slot: StorageSlot,
        value: StorageValue,
        proof: Vec<Bytes>,
        storage_root: H256
    ) -> Self {
        Self {
            contract_address,
            slot,
            value,
            proof,
            storage_root,
        }
    }
    
    /// Verify this proof
    pub fn verify(&self) -> Result<bool> {
        StorageTrie::verify_proof(
            self.storage_root,
            self.slot.clone(),
            &self.value,
            &self.proof
        )
    }
}

/// Storage manager for multiple contracts
pub struct StorageManager {
    /// Storage tries per contract
    storage_tries: HashMap<Address, StorageTrie>,
    
    /// Global storage statistics
    pub stats: StorageManagerStats,
}

#[derive(Debug, Default)]
pub struct StorageManagerStats {
    pub total_contracts: usize,
    pub total_storage_slots: usize,
    pub active_contracts: usize,
}

impl StorageManager {
    /// Create new storage manager
    pub fn new() -> Self {
        Self {
            storage_tries: HashMap::new(),
            stats: StorageManagerStats::default(),
        }
    }
    
    /// Get or create storage trie for contract
    pub fn get_or_create_storage(&mut self, contract_address: Address) -> &mut StorageTrie {
        if !self.storage_tries.contains_key(&contract_address) {
            self.storage_tries.insert(contract_address, StorageTrie::new(contract_address));
            self.stats.total_contracts += 1;
        }
        
        self.storage_tries.get_mut(&contract_address).unwrap()
    }
    
    /// Get storage trie for contract (read-only)
    pub async fn get_storage_trie(&self, contract_address: Address) -> Result<&StorageTrie> {
        self.storage_tries.get(&contract_address)
            .ok_or_else(|| anyhow::anyhow!("Storage trie not found for contract {}", contract_address))
    }
    
    /// Get storage value
    pub async fn get_storage(&mut self, contract_address: Address, slot: StorageSlot) -> Result<StorageValue> {
        let storage_trie = self.get_or_create_storage(contract_address);
        storage_trie.get_storage(slot).await
    }
    
    /// Set storage value
    pub async fn set_storage(&mut self, contract_address: Address, slot: StorageSlot, value: StorageValue) -> Result<()> {
        let storage_trie = self.get_or_create_storage(contract_address);
        storage_trie.set_storage(slot, value).await?;
        self.stats.total_storage_slots += 1;
        Ok(())
    }
    
    /// Commit all storage tries
    pub async fn commit_all(&mut self) -> Result<()> {
        for storage_trie in self.storage_tries.values_mut() {
            storage_trie.commit().await?;
        }
        Ok(())
    }
    
    /// Compute storage root for contract
    pub async fn compute_storage_root(&mut self, contract_address: Address) -> Result<H256> {
        if let Some(storage_trie) = self.storage_tries.get_mut(&contract_address) {
            storage_trie.compute_root().await
        } else {
            // Empty storage root for contracts without storage
            Ok(H256::zero())
        }
    }
    
    /// Generate storage proof
    pub async fn generate_storage_proof(
        &self,
        contract_address: Address,
        slot: StorageSlot
    ) -> Result<StorageProof> {
        if let Some(storage_trie) = self.storage_tries.get(&contract_address) {
            let value = storage_trie.storage_cache.get(&slot).cloned()
                .unwrap_or_else(|| StorageValue::new(U256::zero()));
            let proof = storage_trie.generate_proof(slot.clone()).await?;
            let storage_root = storage_trie.trie.root();
            
            Ok(StorageProof::new(contract_address, slot, value, proof, storage_root))
        } else {
            // Generate proof for empty storage
            let value = StorageValue::new(U256::zero());
            let proof = Vec::new();
            let storage_root = H256::zero();
            
            Ok(StorageProof::new(contract_address, slot, value, proof, storage_root))
        }
    }
    
    /// Clear all caches
    pub fn clear_caches(&mut self) {
        for storage_trie in self.storage_tries.values_mut() {
            storage_trie.clear_cache();
        }
    }
    
    /// Get total contracts with storage
    pub fn total_contracts(&self) -> usize {
        self.storage_tries.len()
    }
    
    /// Remove contract storage (for self-destruct)
    pub fn remove_contract_storage(&mut self, contract_address: Address) {
        self.storage_tries.remove(&contract_address);
    }
    
    /// Get storage statistics
    pub fn get_stats(&self) -> &StorageManagerStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_storage_slot_operations() {
        let slot = StorageSlot::new(U256::from(42));
        let bytes = slot.as_bytes();
        let key = slot.as_trie_key();
        
        assert_eq!(bytes[31], 42); // Last byte should be 42
        assert_ne!(key, bytes); // Trie key should be different (hashed)
    }
    
    #[tokio::test]
    async fn test_storage_value_compression() {
        let value = StorageValue::new(U256::from(1000));
        let compressed = value.compressed_bytes();
        let decompressed = StorageValue::from_compressed_bytes(&compressed);
        
        assert_eq!(value, decompressed);
        assert!(compressed.len() < 32); // Should be compressed
    }
    
    #[tokio::test]
    async fn test_storage_trie_operations() {
        let contract = Address::random();
        let mut storage = StorageTrie::new(contract);
        
        let slot = StorageSlot::new(U256::from(1));
        let value = StorageValue::new(U256::from(42));
        
        // Set and get storage
        storage.set_storage(slot.clone(), value.clone()).await.unwrap();
        let retrieved = storage.get_storage(slot.clone()).await.unwrap();
        assert_eq!(retrieved, value);
        
        // Check root computation
        let root1 = storage.compute_root().await.unwrap();
        
        // Add another slot
        let slot2 = StorageSlot::new(U256::from(2));
        let value2 = StorageValue::new(U256::from(100));
        storage.set_storage(slot2, value2).await.unwrap();
        
        let root2 = storage.compute_root().await.unwrap();
        assert_ne!(root1, root2); // Roots should be different
    }
    
    #[tokio::test]
    async fn test_storage_manager() {
        let mut manager = StorageManager::new();
        let contract1 = Address::random();
        let contract2 = Address::random();
        
        let slot = StorageSlot::new(U256::from(1));
        let value1 = StorageValue::new(U256::from(100));
        let value2 = StorageValue::new(U256::from(200));
        
        // Set storage for different contracts
        manager.set_storage(contract1, slot.clone(), value1.clone()).await.unwrap();
        manager.set_storage(contract2, slot.clone(), value2.clone()).await.unwrap();
        
        // Get storage for different contracts
        let retrieved1 = manager.get_storage(contract1, slot.clone()).await.unwrap();
        let retrieved2 = manager.get_storage(contract2, slot.clone()).await.unwrap();
        
        assert_eq!(retrieved1, value1);
        assert_eq!(retrieved2, value2);
        assert_eq!(manager.total_contracts(), 2);
    }
    
    #[tokio::test]
    async fn test_zero_value_handling() {
        let contract = Address::random();
        let mut storage = StorageTrie::new(contract);
        
        let slot = StorageSlot::new(U256::from(1));
        let zero_value = StorageValue::new(U256::zero());
        let non_zero_value = StorageValue::new(U256::from(42));
        
        // Set non-zero value
        storage.set_storage(slot.clone(), non_zero_value.clone()).await.unwrap();
        let root1 = storage.compute_root().await.unwrap();
        
        // Set to zero (should remove)
        storage.set_storage(slot.clone(), zero_value.clone()).await.unwrap();
        let root2 = storage.compute_root().await.unwrap();
        
        // Verify zero value
        let retrieved = storage.get_storage(slot).await.unwrap();
        assert!(retrieved.is_zero());
        
        // Root should be different after zeroing
        assert_ne!(root1, root2);
    }
}
