// evm-verify/src/state_trie/proof.rs
// Merkle Proof Generation and Verification
//
// Implements state and storage proof generation/verification as required
// for Ethereum Foundation compliance and light client support.

use ethers::types::{H256, U256, Address, Bytes, Block, TransactionReceipt};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use super::{
    mpt::MerklePatriciaTrie,
    account_state::{AccountState, AccountProof, AccountTrie},
    storage_trie::{StorageSlot, StorageValue, StorageProof, StorageTrie},
};

/// Complete state proof for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// Block number
    pub block_number: u64,
    
    /// Transaction index in block
    pub transaction_index: usize,
    
    /// Pre-state root
    pub pre_state_root: H256,
    
    /// Post-state root
    pub post_state_root: H256,
    
    /// Account proofs (before and after)
    pub account_proofs: Vec<AccountStateProof>,
    
    /// Storage proofs (before and after)
    pub storage_proofs: Vec<StorageStateProof>,
    
    /// Gas used
    pub gas_used: u64,
    
    /// Transaction hash
    pub transaction_hash: H256,
}

/// Account state proof (before and after transaction)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStateProof {
    /// Account address
    pub address: Address,
    
    /// Pre-transaction account state
    pub pre_state: AccountState,
    
    /// Post-transaction account state
    pub post_state: AccountState,
    
    /// Pre-state merkle proof
    pub pre_proof: Vec<Bytes>,
    
    /// Post-state merkle proof
    pub post_proof: Vec<Bytes>,
}

/// Storage state proof (before and after transaction)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStateProof {
    /// Contract address
    pub contract_address: Address,
    
    /// Storage slot
    pub slot: StorageSlot,
    
    /// Pre-transaction storage value
    pub pre_value: StorageValue,
    
    /// Post-transaction storage value
    pub post_value: StorageValue,
    
    /// Pre-state merkle proof
    pub pre_proof: Vec<Bytes>,
    
    /// Post-state merkle proof
    pub post_proof: Vec<Bytes>,
    
    /// Storage root (pre and post)
    pub pre_storage_root: H256,
    pub post_storage_root: H256,
}

/// State proof generator
pub struct StateProofGenerator {
    /// Pre-transaction account trie
    pre_account_trie: AccountTrie,
    
    /// Post-transaction account trie
    post_account_trie: AccountTrie,
    
    /// Storage managers (pre and post)
    pre_storage_manager: HashMap<Address, StorageTrie>,
    post_storage_manager: HashMap<Address, StorageTrie>,
    
    /// Affected accounts
    affected_accounts: Vec<Address>,
    
    /// Affected storage slots
    affected_storage: HashMap<Address, Vec<StorageSlot>>,
}

impl StateProofGenerator {
    /// Create new state proof generator
    pub fn new() -> Self {
        Self {
            pre_account_trie: AccountTrie::new(),
            post_account_trie: AccountTrie::new(),
            pre_storage_manager: HashMap::new(),
            post_storage_manager: HashMap::new(),
            affected_accounts: Vec::new(),
            affected_storage: HashMap::new(),
        }
    }
    
    /// Initialize pre-state
    pub async fn set_pre_state(
        &mut self,
        account_trie: AccountTrie,
        storage_manager: HashMap<Address, StorageTrie>
    ) -> Result<()> {
        self.pre_account_trie = account_trie;
        self.pre_storage_manager = storage_manager;
        Ok(())
    }
    
    /// Initialize post-state
    pub async fn set_post_state(
        &mut self,
        account_trie: AccountTrie,
        storage_manager: HashMap<Address, StorageTrie>
    ) -> Result<()> {
        self.post_account_trie = account_trie;
        self.post_storage_manager = storage_manager;
        Ok(())
    }
    
    /// Mark account as affected by transaction
    pub fn mark_account_affected(&mut self, address: Address) {
        if !self.affected_accounts.contains(&address) {
            self.affected_accounts.push(address);
        }
    }
    
    /// Mark storage slot as affected by transaction
    pub fn mark_storage_affected(&mut self, contract: Address, slot: StorageSlot) {
        self.affected_storage.entry(contract)
            .or_insert_with(Vec::new)
            .push(slot);
    }
    
    /// Generate complete state proof
    pub async fn generate_proof(
        &mut self,
        block_number: u64,
        transaction_index: usize,
        transaction_hash: H256,
        gas_used: u64
    ) -> Result<StateProof> {
        // Compute state roots
        let pre_state_root = self.pre_account_trie.compute_root().await?;
        let post_state_root = self.post_account_trie.compute_root().await?;
        
        // Generate account proofs
        let mut account_proofs = Vec::new();
        let affected_accounts = self.affected_accounts.clone();
        for address in affected_accounts {
            let account_proof = self.generate_account_proof(address).await?;
            account_proofs.push(account_proof);
        }
        
        // Generate storage proofs
        let mut storage_proofs = Vec::new();
        let affected_storage = self.affected_storage.clone();
        for (contract, slots) in affected_storage {
            for slot in slots {
                let storage_proof = self.generate_storage_proof(contract, slot).await?;
                storage_proofs.push(storage_proof);
            }
        }
        
        Ok(StateProof {
            block_number,
            transaction_index,
            pre_state_root,
            post_state_root,
            account_proofs,
            storage_proofs,
            gas_used,
            transaction_hash,
        })
    }
    
    /// Generate account state proof
    async fn generate_account_proof(&mut self, address: Address) -> Result<AccountStateProof> {
        // Get pre and post account states
        let pre_state = self.pre_account_trie.get_account(address).await?;
        let post_state = self.post_account_trie.get_account(address).await?;
        
        // Generate merkle proofs
        let pre_proof = self.pre_account_trie.generate_proof(address).await?;
        let post_proof = self.post_account_trie.generate_proof(address).await?;
        
        Ok(AccountStateProof {
            address,
            pre_state,
            post_state,
            pre_proof,
            post_proof,
        })
    }
    
    /// Generate storage state proof
    async fn generate_storage_proof(
        &mut self,
        contract: Address,
        slot: StorageSlot
    ) -> Result<StorageStateProof> {
        // Get storage tries
        let pre_storage = self.pre_storage_manager.get_mut(&contract)
            .ok_or_else(|| anyhow!("Pre-storage trie not found for contract: {}", contract))?;
        let post_storage = self.post_storage_manager.get_mut(&contract)
            .ok_or_else(|| anyhow!("Post-storage trie not found for contract: {}", contract))?;
        
        // Get pre and post storage values
        let pre_value = pre_storage.get_storage(slot.clone()).await?;
        let post_value = post_storage.get_storage(slot.clone()).await?;
        
        // Generate merkle proofs
        let pre_proof = pre_storage.generate_proof(slot.clone()).await?;
        let post_proof = post_storage.generate_proof(slot.clone()).await?;
        
        // Get storage roots
        let pre_storage_root = pre_storage.compute_root().await?;
        let post_storage_root = post_storage.compute_root().await?;
        
        Ok(StorageStateProof {
            contract_address: contract,
            slot,
            pre_value,
            post_value,
            pre_proof,
            post_proof,
            pre_storage_root,
            post_storage_root,
        })
    }
    
    /// Verify complete state proof
    pub fn verify_proof(&self, proof: &StateProof) -> Result<bool> {
        // Verify all account proofs
        for account_proof in &proof.account_proofs {
            if !self.verify_account_proof(account_proof, &proof.pre_state_root, &proof.post_state_root)? {
                return Ok(false);
            }
        }
        
        // Verify all storage proofs
        for storage_proof in &proof.storage_proofs {
            if !self.verify_storage_proof(storage_proof)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Verify account state proof
    fn verify_account_proof(
        &self,
        proof: &AccountStateProof,
        pre_state_root: &H256,
        post_state_root: &H256
    ) -> Result<bool> {
        // Verify pre-state proof
        let pre_valid = AccountTrie::verify_proof(
            *pre_state_root,
            proof.address,
            &proof.pre_state,
            &proof.pre_proof
        )?;
        
        if !pre_valid {
            return Ok(false);
        }
        
        // Verify post-state proof
        let post_valid = AccountTrie::verify_proof(
            *post_state_root,
            proof.address,
            &proof.post_state,
            &proof.post_proof
        )?;
        
        Ok(post_valid)
    }
    
    /// Verify storage state proof
    fn verify_storage_proof(&self, proof: &StorageStateProof) -> Result<bool> {
        // Verify pre-storage proof
        let pre_valid = StorageTrie::verify_proof(
            proof.pre_storage_root,
            proof.slot.clone(),
            &proof.pre_value,
            &proof.pre_proof
        )?;
        
        if !pre_valid {
            return Ok(false);
        }
        
        // Verify post-storage proof
        let post_valid = StorageTrie::verify_proof(
            proof.post_storage_root,
            proof.slot.clone(),
            &proof.post_value,
            &proof.post_proof
        )?;
        
        Ok(post_valid)
    }
    
    /// Reset generator for new transaction
    pub fn reset(&mut self) {
        self.affected_accounts.clear();
        self.affected_storage.clear();
    }
}

/// Light client proof verification
pub struct LightClientProofVerifier;

impl LightClientProofVerifier {
    /// Verify state proof against known block header
    pub fn verify_against_block_header(
        proof: &StateProof,
        block_header_state_root: H256
    ) -> Result<bool> {
        // The post-state root should match the block header state root
        if proof.post_state_root != block_header_state_root {
            return Ok(false);
        }
        
        // Additional verification logic would go here
        // For now, just check the basic consistency
        Ok(true)
    }
    
    /// Verify individual account existence
    pub fn verify_account_existence(
        state_root: H256,
        address: Address,
        account: &AccountState,
        proof: &[Bytes]
    ) -> Result<bool> {
        AccountTrie::verify_proof(state_root, address, account, proof)
    }
    
    /// Verify individual storage value
    pub fn verify_storage_value(
        storage_root: H256,
        slot: StorageSlot,
        value: &StorageValue,
        proof: &[Bytes]
    ) -> Result<bool> {
        StorageTrie::verify_proof(storage_root, slot, value, proof)
    }
    
    /// Batch verify multiple account proofs
    pub fn batch_verify_accounts(
        state_root: H256,
        proofs: &[(Address, AccountState, Vec<Bytes>)]
    ) -> Result<Vec<bool>> {
        let mut results = Vec::new();
        
        for (address, account, proof) in proofs {
            let valid = Self::verify_account_existence(state_root, *address, account, proof)?;
            results.push(valid);
        }
        
        Ok(results)
    }
    
    /// Batch verify multiple storage proofs
    pub fn batch_verify_storage(
        storage_root: H256,
        proofs: &[(StorageSlot, StorageValue, Vec<Bytes>)]
    ) -> Result<Vec<bool>> {
        let mut results = Vec::new();
        
        for (slot, value, proof) in proofs {
            let valid = Self::verify_storage_value(storage_root, slot.clone(), value, proof)?;
            results.push(valid);
        }
        
        Ok(results)
    }
}

/// State proof utilities
pub struct StateProofUtils;

impl StateProofUtils {
    /// Serialize state proof to JSON
    pub fn serialize_proof(proof: &StateProof) -> Result<String> {
        serde_json::to_string_pretty(proof)
            .map_err(|e| anyhow!("Failed to serialize proof: {}", e))
    }
    
    /// Deserialize state proof from JSON
    pub fn deserialize_proof(json: &str) -> Result<StateProof> {
        serde_json::from_str(json)
            .map_err(|e| anyhow!("Failed to deserialize proof: {}", e))
    }
    
    /// Calculate proof size in bytes
    pub fn proof_size(proof: &StateProof) -> usize {
        let mut size = 0;
        
        // Account proofs
        for account_proof in &proof.account_proofs {
            size += account_proof.pre_proof.iter().map(|p| p.len()).sum::<usize>();
            size += account_proof.post_proof.iter().map(|p| p.len()).sum::<usize>();
        }
        
        // Storage proofs
        for storage_proof in &proof.storage_proofs {
            size += storage_proof.pre_proof.iter().map(|p| p.len()).sum::<usize>();
            size += storage_proof.post_proof.iter().map(|p| p.len()).sum::<usize>();
        }
        
        size
    }
    
    /// Validate proof structure
    pub fn validate_proof_structure(proof: &StateProof) -> Result<()> {
        // Basic structural validation
        if proof.pre_state_root == H256::zero() {
            return Err(anyhow!("Invalid pre-state root"));
        }
        
        if proof.post_state_root == H256::zero() {
            return Err(anyhow!("Invalid post-state root"));
        }
        
        if proof.transaction_hash == H256::zero() {
            return Err(anyhow!("Invalid transaction hash"));
        }
        
        // Validate account proofs
        for account_proof in &proof.account_proofs {
            if account_proof.pre_proof.is_empty() && !account_proof.pre_state.is_empty() {
                return Err(anyhow!("Missing pre-proof for non-empty account"));
            }
            
            if account_proof.post_proof.is_empty() && !account_proof.post_state.is_empty() {
                return Err(anyhow!("Missing post-proof for non-empty account"));
            }
        }
        
        // Validate storage proofs
        for storage_proof in &proof.storage_proofs {
            if storage_proof.pre_storage_root == H256::zero() && !storage_proof.pre_value.is_zero() {
                return Err(anyhow!("Invalid pre-storage root for non-zero value"));
            }
            
            if storage_proof.post_storage_root == H256::zero() && !storage_proof.post_value.is_zero() {
                return Err(anyhow!("Invalid post-storage root for non-zero value"));
            }
        }
        
        Ok(())
    }
    
    /// Extract affected addresses from proof
    pub fn extract_affected_addresses(proof: &StateProof) -> Vec<Address> {
        let mut addresses = Vec::new();
        
        // From account proofs
        for account_proof in &proof.account_proofs {
            if !addresses.contains(&account_proof.address) {
                addresses.push(account_proof.address);
            }
        }
        
        // From storage proofs
        for storage_proof in &proof.storage_proofs {
            if !addresses.contains(&storage_proof.contract_address) {
                addresses.push(storage_proof.contract_address);
            }
        }
        
        addresses
    }
    
    /// Compare two proofs for differences
    pub fn compare_proofs(proof1: &StateProof, proof2: &StateProof) -> Vec<String> {
        let mut differences = Vec::new();
        
        if proof1.pre_state_root != proof2.pre_state_root {
            differences.push("Pre-state roots differ".to_string());
        }
        
        if proof1.post_state_root != proof2.post_state_root {
            differences.push("Post-state roots differ".to_string());
        }
        
        if proof1.account_proofs.len() != proof2.account_proofs.len() {
            differences.push("Different number of account proofs".to_string());
        }
        
        if proof1.storage_proofs.len() != proof2.storage_proofs.len() {
            differences.push("Different number of storage proofs".to_string());
        }
        
        differences
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_state_proof_generation() {
        let mut generator = StateProofGenerator::new();
        
        // Setup mock state
        let address = Address::random();
        generator.mark_account_affected(address);
        
        let proof = generator.generate_proof(
            1000,
            0,
            H256::random(),
            21000
        ).await.unwrap();
        
        assert_eq!(proof.block_number, 1000);
        assert_eq!(proof.transaction_index, 0);
        assert_eq!(proof.gas_used, 21000);
    }
    
    #[test]
    fn test_light_client_verification() {
        let state_root = H256::random();
        let address = Address::random();
        let account = AccountState::new();
        let proof = vec![Bytes::from(b"mock_proof".to_vec())];
        
        // This would normally verify against real data
        let result = LightClientProofVerifier::verify_account_existence(
            state_root,
            address,
            &account,
            &proof
        );
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_proof_serialization() {
        let proof = StateProof {
            block_number: 1000,
            transaction_index: 0,
            pre_state_root: H256::random(),
            post_state_root: H256::random(),
            account_proofs: vec![],
            storage_proofs: vec![],
            gas_used: 21000,
            transaction_hash: H256::random(),
        };
        
        let serialized = StateProofUtils::serialize_proof(&proof).unwrap();
        let deserialized = StateProofUtils::deserialize_proof(&serialized).unwrap();
        
        assert_eq!(proof.block_number, deserialized.block_number);
        assert_eq!(proof.transaction_index, deserialized.transaction_index);
        assert_eq!(proof.gas_used, deserialized.gas_used);
    }
    
    #[test]
    fn test_proof_validation() {
        let mut proof = StateProof {
            block_number: 1000,
            transaction_index: 0,
            pre_state_root: H256::zero(), // Invalid
            post_state_root: H256::random(),
            account_proofs: vec![],
            storage_proofs: vec![],
            gas_used: 21000,
            transaction_hash: H256::random(),
        };
        
        // Should fail validation
        assert!(StateProofUtils::validate_proof_structure(&proof).is_err());
        
        // Fix and retry
        proof.pre_state_root = H256::random();
        assert!(StateProofUtils::validate_proof_structure(&proof).is_ok());
    }
    
    #[test]
    fn test_proof_size_calculation() {
        let proof = StateProof {
            block_number: 1000,
            transaction_index: 0,
            pre_state_root: H256::random(),
            post_state_root: H256::random(),
            account_proofs: vec![
                AccountStateProof {
                    address: Address::random(),
                    pre_state: AccountState::new(),
                    post_state: AccountState::new(),
                    pre_proof: vec![Bytes::from(b"test1".to_vec()), Bytes::from(b"test2".to_vec())],
                    post_proof: vec![Bytes::from(b"test3".to_vec())],
                }
            ],
            storage_proofs: vec![],
            gas_used: 21000,
            transaction_hash: H256::random(),
        };
        
        let size = StateProofUtils::proof_size(&proof);
        assert_eq!(size, 15); // "test1" + "test2" + "test3" = 5 + 5 + 5 = 15
    }
}
