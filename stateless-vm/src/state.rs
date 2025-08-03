use crate::errors::{VMError, Result};
use crate::transaction::{Transaction, TransactionSequence};
use crate::types::{Address, Bytes, BlockHeight, StorageKey, StorageValue, StateRoot};
use async_trait::async_trait;
// We'll use a simpler approach without patricia-trie for now
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde_json;
use hex;
use ethereum_types::H256;

/// Represents a specific storage key and its access pattern
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateRequirement {
    /// Contract address the state belongs to
    pub address: Address,
    /// Specific storage key needed
    pub key: StorageKey,
    /// Block height at which the state must be valid
    pub block_height: BlockHeight,
    /// Whether this state is read-only or will be modified
    pub access_pattern: StateAccessPattern,
}

/// Type of access pattern for a state requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateAccessPattern {
    /// State will only be read, not modified
    ReadOnly,
    /// State will be modified during execution
    ReadWrite,
    /// State will be created during execution
    Create,
    /// State will be deleted during execution
    Delete,
}

/// Trait for providing state data
#[async_trait]
pub trait StateProvider: Send + Sync {
    /// Fetch state data for a specific requirement
    async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Bytes>;
    
    /// Check if this provider has the required state
    async fn has_state(&self, requirement: &StateRequirement) -> bool;
    
    /// Get the state root at a specific block height
    async fn state_root_at_height(&self, height: BlockHeight) -> Result<StateRoot>;
}

/// State data bundled with its proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundledState {
    /// The state requirement
    pub requirement: StateRequirement,
    /// The actual state data
    pub data: Bytes,
    /// Merkle proof verifying this state
    pub proof: Vec<Bytes>,
}

/// Core state bundling engine that manages state requirements and bundling
pub struct StateBundler {
    /// Available state providers in priority order
    providers: Vec<Arc<dyn StateProvider>>,
    /// Local cache of fetched state
    cache: HashMap<StateRequirement, Bytes>,
}

impl std::fmt::Debug for StateBundler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateBundler")
            .field("providers", &format!("[{} providers]", self.providers.len()))
            .field("cache", &format!("[{} cached items]", self.cache.len()))
            .finish()
    }
}

/// A simplified state provider that makes direct RPC calls to an EVM-compatible chain
#[derive(Debug)]
pub struct DirectRpcProvider {
    client: reqwest::Client,
    rpc_url: String,
}

impl DirectRpcProvider {
    pub fn new(client: reqwest::Client, rpc_url: String) -> Self {
        Self {
            client,
            rpc_url,
        }
    }
    
    async fn make_rpc_call<T: for<'de> Deserialize<'de>>(&self, method: &str, params: Vec<serde_json::Value>) -> Result<T> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        
        let response = self.client.post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| VMError::InvalidOperation {
                description: format!("RPC request failed: {}", e)
            })?;
        
        let response_json: serde_json::Value = response.json().await
            .map_err(|e| VMError::InvalidOperation {
                description: format!("Failed to parse RPC response: {}", e)
            })?;
        
        if let Some(error) = response_json.get("error") {
            return Err(VMError::InvalidOperation {
                description: format!("RPC error: {}", error)
            });
        }
        
        let result = response_json.get("result")
            .ok_or_else(|| VMError::InvalidOperation {
                description: "Missing 'result' in RPC response".into()
            })?;
        
        serde_json::from_value(result.clone())
            .map_err(|e| VMError::InvalidOperation {
                description: format!("Failed to deserialize RPC result: {}", e)
            })
    }
}

impl StateBundler {
    /// Create a new state bundler with the given providers
    pub fn new(providers: Vec<Arc<dyn StateProvider>>) -> Self {
        Self {
            providers,
            cache: HashMap::new(),
        }
    }
    
    /// Create a new StateBundler with a direct RPC provider for simplified operation
    /// This is useful when you don't need the full provider infrastructure
    pub fn new_simplified(http_client: reqwest::Client, rpc_url: &str) -> Self {
        // Create a direct RPC provider that implements the bare minimum
        let direct_provider = Arc::new(DirectRpcProvider::new(http_client, rpc_url.to_string()));
        
        StateBundler {
            providers: vec![direct_provider],
            cache: HashMap::new(),
        }
    }
    
    /// Analyze a transaction to determine its state requirements
    pub async fn analyze_transaction(&self, transaction: &Transaction) -> Result<Vec<StateRequirement>> {
        // Static analysis of the transaction to determine state requirements
        let mut requirements = Vec::new();
        
        // Add direct state requirements specified in the transaction
        for req in transaction.state_requirements() {
            requirements.push(req.clone());
        }
        
        // Analyze code execution to find implicit requirements
        if let Some(code) = transaction.code() {
            // Perform static analysis on the code to find storage accesses
            // This would involve sophisticated analysis of the EVM bytecode
            let code_requirements = self.analyze_bytecode(
                transaction.to(), 
                code, 
                transaction.block_height()
            ).await?;
            
            requirements.extend(code_requirements);
        }
        
        // Deduplicate requirements
        let mut unique_reqs = HashSet::new();
        let mut result = Vec::new();
        
        for req in requirements {
            if unique_reqs.insert((req.address, req.key, req.access_pattern)) {
                result.push(req);
            }
        }
        
        Ok(result)
    }
    
    /// Analyze a transaction sequence for all state requirements
    pub async fn analyze_sequence(&self, sequence: &TransactionSequence) -> Result<Vec<StateRequirement>> {
        let mut all_requirements = Vec::new();
        let mut modified_state = HashSet::new();
        
        // First pass: collect all requirements and track modifications
        for (i, tx) in sequence.transactions().iter().enumerate() {
            let mut tx_requirements = self.analyze_transaction(tx).await?;
            
            // Add step index to the requirements for tracking
            for req in &mut tx_requirements {
                // Check if this requirement depends on state modified by an earlier step
                let key = (req.address, req.key);
                if modified_state.contains(&key) {
                    // This is an inter-transaction dependency
                    // Mark it with special handling
                }
                
                // If this transaction modifies state, add it to the tracking set
                if req.access_pattern == StateAccessPattern::ReadWrite || 
                   req.access_pattern == StateAccessPattern::Create ||
                   req.access_pattern == StateAccessPattern::Delete {
                    modified_state.insert(key);
                }
            }
            
            all_requirements.extend(tx_requirements);
        }
        
        // Second pass: resolve dependencies between transactions
        self.resolve_dependencies(&mut all_requirements)?;
        
        Ok(all_requirements)
    }
    
    /// Fetch state for a specific requirement
    pub async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Bytes> {
        // Check cache first
        if let Some(data) = self.cache.get(requirement) {
            return Ok(data.clone());
        }
        
        // Try each provider in order
        for provider in &self.providers {
            if provider.has_state(requirement).await {
                match provider.fetch_state(requirement).await {
                    Ok(data) => {
                        // Cache the result
                        let mut cache = self.cache.clone();
                        cache.insert(requirement.clone(), data.clone());
                        
                        return Ok(data);
                    }
                    Err(_) => continue, // Try next provider
                }
            }
        }
        
        Err(VMError::MissingState {
            address: requirement.address,
            key: format!("{:?}", requirement.key),
            description: "State not available from any provider".into(),
        })
    }
    
    /// Analyze EVM bytecode to determine state access patterns
    async fn analyze_bytecode(&self, address: Address, code: &[u8], block_height: BlockHeight) -> Result<Vec<StateRequirement>> {
        // This would be a complex static analysis of EVM bytecode
        // For now, we'll implement a simplified version that looks for SLOAD and SSTORE opcodes
        
        const SLOAD: u8 = 0x54;
        const SSTORE: u8 = 0x55;
        
        let mut requirements = Vec::new();
        let mut i = 0;
        
        while i < code.len() {
            let opcode = code[i];
            
            match opcode {
                SLOAD => {
                    // This is a simplification - in reality, we'd need to analyze the stack
                    // to determine which storage key is being loaded
                    if i + 32 < code.len() {
                        let mut key_bytes = [0u8; 32];
                        key_bytes.copy_from_slice(&code[i+1..i+33]);
                        let key = StorageKey::from(key_bytes);
                        
                        requirements.push(StateRequirement {
                            address,
                            key,
                            block_height,
                            access_pattern: StateAccessPattern::ReadOnly,
                        });
                    }
                },
                SSTORE => {
                    // Similar simplification for SSTORE
                    if i + 32 < code.len() {
                        let mut key_bytes = [0u8; 32];
                        key_bytes.copy_from_slice(&code[i+1..i+33]);
                        let key = StorageKey::from(key_bytes);
                        
                        requirements.push(StateRequirement {
                            address,
                            key,
                            block_height,
                            access_pattern: StateAccessPattern::ReadWrite,
                        });
                    }
                },
                _ => {},
            }
            
            i += 1;
        }
        
        Ok(requirements)
    }
    
    /// Resolve dependencies between state requirements
    fn resolve_dependencies(&self, requirements: &mut Vec<StateRequirement>) -> Result<()> {
        // Build a dependency graph
        let mut dependencies = HashMap::new();
        let mut modified_by = HashMap::new();
        
        for (i, req) in requirements.iter().enumerate() {
            let key = (req.address, req.key);
            
            // Track which step modifies each state
            if req.access_pattern != StateAccessPattern::ReadOnly {
                modified_by.insert(key, i);
            }
        }
        
        // Check for dependency cycles
        // This is a simplified cycle detection - a real implementation would be more robust
        for &idx in modified_by.values() {
            if self.has_cycle(&dependencies, idx) {
                return Err(VMError::DependencyCycle);
            }
        }
        
        Ok(())
    }
    
    /// Check for cycles in the dependency graph (simplified)
    fn has_cycle(&self, dependencies: &HashMap<usize, Vec<usize>>, start: usize) -> bool {
        // Simplified implementation for now
        false
    }
}

#[async_trait]
impl StateProvider for DirectRpcProvider {
    /// Fetch state data using direct RPC calls
    async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Bytes> {
        // For storage requirements, use eth_getStorageAt
        // For account requirements, use eth_getCode or eth_getBalance
        
        // This is a simplified implementation that only handles storage state
        let address_str = format!("0x{:x}", requirement.address);
        let key_str = format!("0x{:x}", requirement.key);
        
        let params = vec![
            serde_json::Value::String(address_str),
            serde_json::Value::String(key_str),
            serde_json::Value::String("latest".into()), // Use latest block
        ];
        
        let hex_value: String = self.make_rpc_call("eth_getStorageAt", params).await?;
        
        // Convert hex string to bytes
        let bytes = hex::decode(hex_value.trim_start_matches("0x"))
            .map_err(|e| VMError::InvalidOperation {
                description: format!("Failed to decode hex value: {}", e)
            })?;
        
        Ok(Bytes::from(bytes))
    }
    
    /// Check if this provider has the required state
    async fn has_state(&self, _requirement: &StateRequirement) -> bool {
        // For a direct RPC provider, we assume it always has the state
        // since we can always query the blockchain
        true
    }
    
    /// Get the state root at a specific block height
    async fn state_root_at_height(&self, height: BlockHeight) -> Result<StateRoot> {
        // Convert height to hex string
        let block_param = if height == 0 {
            "latest".to_string()
        } else {
            format!("0x{:x}", height)
        };
        
        // Get block by number
        let params = vec![
            serde_json::Value::String(block_param),
            serde_json::Value::Bool(false), // Don't include transactions
        ];
        
        let block: serde_json::Value = self.make_rpc_call("eth_getBlockByNumber", params).await?;
        
        // Extract state root
        let state_root = block.get("stateRoot")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VMError::InvalidOperation {
                description: "Missing 'stateRoot' in block".into()
            })?;
        
        // Convert hex string to StateRoot
        let bytes = hex::decode(state_root.trim_start_matches("0x"))
            .map_err(|e| VMError::InvalidOperation {
                description: format!("Failed to decode state root: {}", e)
            })?;
        
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        
        Ok(StateRoot(H256::from_slice(&root)))
    }
}

#[async_trait]
impl StateProvider for StateBundler {
    /// Fetch state data for a specific requirement
    async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Bytes> {
        // Check cache first
        if let Some(data) = self.cache.get(requirement) {
            return Ok(data.clone());
        }
        
        // Try each provider in order
        for provider in &self.providers {
            if let Ok(data) = provider.fetch_state(requirement).await {
                return Ok(data);
            }
        }
        
        Err(VMError::MissingState {
            address: requirement.address,
            key: format!("{:?}", requirement.key),
            description: "State not found in any provider".into()
        })
    }
    
    /// Check if this provider has the required state
    async fn has_state(&self, requirement: &StateRequirement) -> bool {
        // Check cache first
        if self.cache.contains_key(requirement) {
            return true;
        }
        
        // Try each provider in order
        for provider in &self.providers {
            if provider.has_state(requirement).await {
                return true;
            }
        }
        
        false
    }
    
    /// Get the state root at a specific block height
    async fn state_root_at_height(&self, height: BlockHeight) -> Result<StateRoot> {
        // Try each provider in order
        for provider in &self.providers {
            if let Ok(root) = provider.state_root_at_height(height).await {
                return Ok(root);
            }
        }
        
        Err(VMError::InvalidOperation {
            description: format!("Missing state root for block height {}", height)
        })
    }
}
