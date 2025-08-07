// evm-verify/src/state_trie/account_state.rs
// Ethereum Account State Trie Implementation
//
// Implements the account state structure as defined in the Ethereum Yellow Paper.
// Each account has: nonce, balance, storageRoot, codeHash.

use ethers::types::{H256, U256, Address, Bytes};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use super::mpt::MerklePatriciaTrie;

/// Ethereum account state structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountState {
    /// Account nonce (number of transactions sent)
    pub nonce: U256,
    
    /// Account balance in wei
    pub balance: U256,
    
    /// Root hash of the account's storage trie
    pub storage_root: H256,
    
    /// Hash of the account's bytecode
    pub code_hash: H256,
}

impl AccountState {
    /// Create new empty account
    pub fn new() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: H256::zero(),
            code_hash: Self::empty_code_hash(),
        }
    }
    
    /// Create account with balance
    pub fn with_balance(balance: U256) -> Self {
        Self {
            nonce: U256::zero(),
            balance,
            storage_root: H256::zero(),
            code_hash: Self::empty_code_hash(),
        }
    }
    
    /// Create contract account
    pub fn contract(code_hash: H256, storage_root: H256) -> Self {
        Self {
            nonce: U256::one(), // Contracts start with nonce 1
            balance: U256::zero(),
            storage_root,
            code_hash,
        }
    }
    
    /// Get empty code hash using official EF keccak256
    pub fn empty_code_hash() -> H256 {
        use keccak_hash::keccak;
        let hash = keccak(&[]);
        H256::from_slice(hash.as_bytes())
    }
    
    /// Check if account is empty (as per EIP-161)
    pub fn is_empty(&self) -> bool {
        self.nonce == U256::zero() &&
        self.balance == U256::zero() &&
        self.code_hash == Self::empty_code_hash()
    }
    
    /// RLP encode account state (EF compliant)
    pub fn rlp_encode(&self) -> Vec<u8> {
        use rlp::RlpStream;
        
        // Convert to minimal byte representation (remove leading zeros)
        let nonce_bytes = if self.nonce.is_zero() {
            Vec::new()
        } else {
            let mut bytes = [0u8; 32];
            self.nonce.to_big_endian(&mut bytes);
            // Remove leading zeros
            bytes.iter().skip_while(|&&x| x == 0).cloned().collect()
        };
        
        let balance_bytes = if self.balance.is_zero() {
            Vec::new()
        } else {
            let mut bytes = [0u8; 32];
            self.balance.to_big_endian(&mut bytes);
            // Remove leading zeros
            bytes.iter().skip_while(|&&x| x == 0).cloned().collect()
        };
        
        // RLP encode as list: [nonce, balance, storage_root, code_hash]
        let mut stream = RlpStream::new_list(4);
        stream.append(&nonce_bytes);
        stream.append(&balance_bytes);
        stream.append(&self.storage_root.as_bytes().to_vec());
        stream.append(&self.code_hash.as_bytes().to_vec());
        
        stream.out().to_vec()
    }
    
    /// RLP decode account state (EF compliant)
    pub fn rlp_decode(data: &[u8]) -> Result<Self> {
        
        
        let rlp = rlp::Rlp::new(data);
        if rlp.item_count()? != 4 {
            return Err(anyhow!("Invalid account RLP: expected 4 items"));
        }
        
        // Decode nonce (handle empty for zero)
        let nonce_bytes: Vec<u8> = rlp.val_at(0)?;
        let nonce = if nonce_bytes.is_empty() {
            U256::zero()
        } else {
            U256::from_big_endian(&nonce_bytes)
        };
        
        // Decode balance (handle empty for zero)
        let balance_bytes: Vec<u8> = rlp.val_at(1)?;
        let balance = if balance_bytes.is_empty() {
            U256::zero()
        } else {
            U256::from_big_endian(&balance_bytes)
        };
        
        // Decode storage root
        let storage_root_bytes: Vec<u8> = rlp.val_at(2)?;
        if storage_root_bytes.len() != 32 {
            return Err(anyhow!("Invalid storage root length"));
        }
        let storage_root = H256::from_slice(&storage_root_bytes);
        
        // Decode code hash
        let code_hash_bytes: Vec<u8> = rlp.val_at(3)?;
        if code_hash_bytes.len() != 32 {
            return Err(anyhow!("Invalid code hash length"));
        }
        let code_hash = H256::from_slice(&code_hash_bytes);
        
        Ok(Self {
            nonce,
            balance,
            storage_root,
            code_hash,
        })
    }
}

impl Default for AccountState {
    fn default() -> Self {
        Self::new()
    }
}

/// Account state trie manager
pub struct AccountTrie {
    /// Underlying MPT
    trie: MerklePatriciaTrie,
    
    /// Account cache for performance
    account_cache: HashMap<Address, AccountState>,
    
    /// Modified accounts (for efficient commits)
    dirty_accounts: HashMap<Address, AccountState>,
    
    /// Statistics
    pub stats: AccountTrieStats,
}

#[derive(Debug, Default)]
pub struct AccountTrieStats {
    pub total_accounts: usize,
    pub contract_accounts: usize,
    pub empty_accounts: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
}

impl AccountTrie {
    /// Create new account trie
    pub fn new() -> Self {
        Self {
            trie: MerklePatriciaTrie::new(),
            account_cache: HashMap::new(),
            dirty_accounts: HashMap::new(),
            stats: AccountTrieStats::default(),
        }
    }
    
    /// Get account state
    pub async fn get_account(&mut self, address: Address) -> Result<AccountState> {
        // Check cache first
        if let Some(cached) = self.account_cache.get(&address) {
            self.stats.cache_hits += 1;
            return Ok(cached.clone());
        }
        
        self.stats.cache_misses += 1;
        
        // Get from trie
        let key = address.as_bytes();
        if let Some(data) = self.trie.get(key).await? {
            let account = AccountState::rlp_decode(&data)?;
            self.account_cache.insert(address, account.clone());
            Ok(account)
        } else {
            // Return empty account
            let empty = AccountState::new();
            self.account_cache.insert(address, empty.clone());
            Ok(empty)
        }
    }
    
    /// Set account state
    pub async fn set_account(&mut self, address: Address, account: AccountState) -> Result<()> {
        // Update stats first
        if account.is_empty() {
            self.stats.empty_accounts += 1;
        } else if account.code_hash != AccountState::empty_code_hash() {
            self.stats.contract_accounts += 1;
        }
        
        // Update cache and mark as dirty
        self.account_cache.insert(address, account.clone());
        self.dirty_accounts.insert(address, account);
        
        Ok(())
    }
    
    /// Increment account nonce
    pub fn increment_nonce(&mut self, address: Address) -> Result<()> {
        if let Some(account) = self.account_cache.get_mut(&address) {
            account.nonce += U256::one();
            self.dirty_accounts.insert(address, account.clone());
        } else {
            // Create new account with nonce 1
            let mut account = AccountState::new();
            account.nonce = U256::one();
            self.account_cache.insert(address, account.clone());
            self.dirty_accounts.insert(address, account);
        }
        Ok(())
    }
    
    /// Credit account balance
    pub fn credit_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if let Some(account) = self.account_cache.get_mut(&address) {
            account.balance += amount;
            self.dirty_accounts.insert(address, account.clone());
        } else {
            // Create new account with balance
            let account = AccountState::with_balance(amount);
            self.account_cache.insert(address, account.clone());
            self.dirty_accounts.insert(address, account);
        }
        Ok(())
    }
    
    /// Debit account balance
    pub fn debit_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if let Some(account) = self.account_cache.get_mut(&address) {
            if account.balance < amount {
                return Err(anyhow!("Insufficient balance"));
            }
            account.balance -= amount;
            self.dirty_accounts.insert(address, account.clone());
        } else {
            return Err(anyhow!("Account not found for debit"));
        }
        Ok(())
    }
    
    /// Update account storage root
    pub fn update_account_storage_root(&mut self, address: Address, storage_root: H256) -> Result<()> {
        if let Some(account) = self.account_cache.get_mut(&address) {
            account.storage_root = storage_root;
            self.dirty_accounts.insert(address, account.clone());
        } else {
            // Create contract account
            let account = AccountState::contract(AccountState::empty_code_hash(), storage_root);
            self.account_cache.insert(address, account.clone());
            self.dirty_accounts.insert(address, account);
        }
        Ok(())
    }
    
    /// Set account code hash
    pub fn set_code_hash(&mut self, address: Address, code_hash: H256) -> Result<()> {
        if let Some(account) = self.account_cache.get_mut(&address) {
            account.code_hash = code_hash;
            account.nonce = U256::one(); // Contracts start with nonce 1
            self.dirty_accounts.insert(address, account.clone());
        } else {
            let account = AccountState::contract(code_hash, H256::zero());
            self.account_cache.insert(address, account.clone());
            self.dirty_accounts.insert(address, account);
        }
        Ok(())
    }
    
    /// Commit all dirty accounts to trie
    pub async fn commit(&mut self) -> Result<()> {
        for (address, account) in self.dirty_accounts.drain() {
            let key = address.as_bytes();
            
            if account.is_empty() {
                // Remove empty accounts
                self.trie.remove(key).await?;
            } else {
                // Store account
                let data = Bytes::from(account.rlp_encode());
                self.trie.insert(key, data).await?;
            }
        }
        Ok(())
    }
    
    /// Compute account trie root
    pub async fn compute_root(&mut self) -> Result<H256> {
        // Commit dirty accounts first
        self.commit().await?;
        
        // Return trie root
        Ok(self.trie.root())
    }
    
    /// Generate merkle proof for account
    pub async fn generate_proof(&self, address: Address) -> Result<Vec<Bytes>> {
        let key = address.as_bytes();
        self.trie.generate_proof(key).await
    }
    
    /// Verify account proof
    pub fn verify_proof(
        root: H256,
        address: Address,
        account: &AccountState,
        proof: &[Bytes]
    ) -> Result<bool> {
        let key = address.as_bytes();
        let value = Bytes::from(account.rlp_encode());
        MerklePatriciaTrie::verify_proof(root, key, &value, proof)
    }
    
    /// Get account trie statistics
    pub fn get_stats(&self) -> &AccountTrieStats {
        &self.stats
    }
    
    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.account_cache.clear();
        self.dirty_accounts.clear();
    }
    
    /// Set account storage root
    pub async fn set_storage_root(
        &mut self, 
        address: Address, 
        storage_root: H256
    ) -> Result<()> {
        // Ensure account exists in cache
        if !self.account_cache.contains_key(&address) {
            let account = match self.trie.get(address.as_bytes()).await? {
                Some(bytes) => AccountState::rlp_decode(&bytes)?,
                None => AccountState::default(),
            };
            self.account_cache.insert(address, account);
        }
        
        // Update the account
        if let Some(account) = self.account_cache.get_mut(&address) {
            account.storage_root = storage_root;
            self.dirty_accounts.insert(address, account.clone());
        }
        Ok(())
    }

    
    /// Helper to get or create account mutably
    #[allow(dead_code)]
    async fn get_or_create_account_mut(&mut self, address: &Address) -> Result<&mut AccountState> {
        if !self.account_cache.contains_key(&address) {
            // Load from trie or create new
            let account = match self.trie.get(address.as_bytes()).await? {
                Some(bytes) => AccountState::rlp_decode(&bytes)?,
                None => AccountState::default(),
            };
            self.account_cache.insert(address.clone(), account);
        }
        Ok(self.account_cache.get_mut(&address).unwrap())
    }


    
    /// Get total accounts
    pub fn total_accounts(&self) -> usize {
        self.account_cache.len()
    }
    
    /// Check if address has account
    pub fn has_account(&self, address: Address) -> bool {
        if let Some(account) = self.account_cache.get(&address) {
            !account.is_empty()
        } else {
            false
        }
    }
    
    /// Get account balance
    pub async fn get_balance(&mut self, address: Address) -> Result<U256> {
        let account = self.get_account(address).await?;
        Ok(account.balance)
    }
    
    /// Get account nonce
    pub async fn get_nonce(&mut self, address: Address) -> Result<U256> {
        let account = self.get_account(address).await?;
        Ok(account.nonce)
    }
    
    /// Get account code hash
    pub async fn get_code_hash(&mut self, address: Address) -> Result<H256> {
        let account = self.get_account(address).await?;
        Ok(account.code_hash)
    }
    
    /// Get account storage root
    pub async fn get_storage_root(&mut self, address: Address) -> Result<H256> {
        let account = self.get_account(address).await?;
        Ok(account.storage_root)
    }
}

/// Account proof structure
#[derive(Debug, Clone)]
pub struct AccountProof {
    /// Account address
    pub address: Address,
    
    /// Account state
    pub account: AccountState,
    
    /// Merkle proof
    pub proof: Vec<Bytes>,
    
    /// State root
    pub state_root: H256,
}

impl AccountProof {
    /// Create new account proof
    pub fn new(
        address: Address,
        account: AccountState,
        proof: Vec<Bytes>,
        state_root: H256
    ) -> Self {
        Self {
            address,
            account,
            proof,
            state_root,
        }
    }
    
    /// Verify this proof
    pub fn verify(&self) -> Result<bool> {
        AccountTrie::verify_proof(
            self.state_root,
            self.address,
            &self.account,
            &self.proof
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_account_creation() {
        let account = AccountState::new();
        assert_eq!(account.nonce, U256::zero());
        assert_eq!(account.balance, U256::zero());
        assert!(account.is_empty());
    }
    
    #[tokio::test]
    async fn test_account_trie_operations() {
        let mut trie = AccountTrie::new();
        let address = Address::random();
        
        // Set account
        let account = AccountState::with_balance(U256::from(1000));
        trie.set_account(address, account.clone()).await.unwrap();
        
        // Get account
        let retrieved = trie.get_account(address).await.unwrap();
        assert_eq!(retrieved.balance, U256::from(1000));
        
        // Increment nonce
        trie.increment_nonce(address).unwrap();
        let updated = trie.get_account(address).await.unwrap();
        assert_eq!(updated.nonce, U256::one());
    }
    
    #[tokio::test]
    async fn test_balance_operations() {
        let mut trie = AccountTrie::new();
        let address = Address::random();
        
        // Credit balance
        trie.credit_balance(address, U256::from(500)).unwrap();
        trie.credit_balance(address, U256::from(300)).unwrap();
        
        let account = trie.get_account(address).await.unwrap();
        assert_eq!(account.balance, U256::from(800));
        
        // Debit balance
        trie.debit_balance(address, U256::from(200)).unwrap();
        let account = trie.get_account(address).await.unwrap();
        assert_eq!(account.balance, U256::from(600));
    }
    
    #[tokio::test]
    async fn test_account_rlp_encoding() {
        let account = AccountState {
            nonce: U256::from(42),
            balance: U256::from(1000000),
            storage_root: H256::random(),
            code_hash: H256::random(),
        };
        
        let encoded = account.rlp_encode();
        let decoded = AccountState::rlp_decode(&encoded).unwrap();
        
        assert_eq!(account, decoded);
    }
    
    #[tokio::test]
    async fn test_root_computation() {
        let mut trie = AccountTrie::new();
        
        // Add some accounts
        let addr1 = Address::random();
        let addr2 = Address::random();
        
        trie.set_account(addr1, AccountState::with_balance(U256::from(1000))).await.unwrap();
        trie.set_account(addr2, AccountState::with_balance(U256::from(2000))).await.unwrap();
        
        let root1 = trie.compute_root().await.unwrap();
        
        // Add another account
        let addr3 = Address::random();
        trie.set_account(addr3, AccountState::with_balance(U256::from(3000))).await.unwrap();
        
        let root2 = trie.compute_root().await.unwrap();
        
        // Roots should be different
        assert_ne!(root1, root2);
    }
}
