// Chain-specific configurations and utilities
//
// This module provides configurations and utilities for different EVM-compatible chains.

use std::collections::HashMap;
use anyhow::Result;
use ethers::types::U256;

/// Chain configuration
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: u64,
    
    /// Chain name
    pub name: String,
    
    /// Average block time in seconds
    pub block_time: u64,
    
    /// Gas limit for blocks
    pub block_gas_limit: U256,
    
    /// Native currency symbol
    pub currency_symbol: String,
    
    /// Chain-specific security considerations
    pub security_considerations: Vec<String>,
}

impl ChainConfig {
    /// Create a new chain configuration
    pub fn new(
        chain_id: u64,
        name: String,
        block_time: u64,
        block_gas_limit: U256,
        currency_symbol: String,
        security_considerations: Vec<String>,
    ) -> Self {
        Self {
            chain_id,
            name,
            block_time,
            block_gas_limit,
            currency_symbol,
            security_considerations,
        }
    }
    
    /// Get Ethereum Mainnet configuration
    pub fn ethereum() -> Self {
        Self::new(
            1,
            "Ethereum Mainnet".to_string(),
            12,
            U256::from(30_000_000),
            "ETH".to_string(),
            vec![
                "Front-running is common due to public mempool".to_string(),
                "Block timestamps can be manipulated by miners within a small window".to_string(),
                "Gas prices can fluctuate significantly".to_string(),
            ],
        )
    }
    
    /// Get Polygon configuration
    pub fn polygon() -> Self {
        Self::new(
            137,
            "Polygon".to_string(),
            2,
            U256::from(20_000_000),
            "MATIC".to_string(),
            vec![
                "Faster block times may increase the risk of chain reorganizations".to_string(),
                "Lower gas costs may lead to different optimization patterns".to_string(),
            ],
        )
    }
    
    /// Get Binance Smart Chain configuration
    pub fn bsc() -> Self {
        Self::new(
            56,
            "Binance Smart Chain".to_string(),
            3,
            U256::from(30_000_000),
            "BNB".to_string(),
            vec![
                "More centralized validator set may affect security assumptions".to_string(),
                "Lower gas costs may lead to different optimization patterns".to_string(),
            ],
        )
    }
    
    /// Get Arbitrum configuration
    pub fn arbitrum() -> Self {
        Self::new(
            42161,
            "Arbitrum".to_string(),
            1,
            U256::from(30_000_000),
            "ETH".to_string(),
            vec![
                "L2-specific considerations for cross-chain messaging".to_string(),
                "Different gas model than Ethereum mainnet".to_string(),
            ],
        )
    }
    
    /// Get Optimism configuration
    pub fn optimism() -> Self {
        Self::new(
            10,
            "Optimism".to_string(),
            1,
            U256::from(30_000_000),
            "ETH".to_string(),
            vec![
                "L2-specific considerations for cross-chain messaging".to_string(),
                "Different gas model than Ethereum mainnet".to_string(),
            ],
        )
    }
    
    /// Get Avalanche C-Chain configuration
    pub fn avalanche() -> Self {
        Self::new(
            43114,
            "Avalanche C-Chain".to_string(),
            2,
            U256::from(8_000_000),
            "AVAX".to_string(),
            vec![
                "Faster finality may affect certain timing assumptions".to_string(),
                "Different gas costs than Ethereum mainnet".to_string(),
            ],
        )
    }
}

/// Chain registry for looking up chain configurations
pub struct ChainRegistry {
    /// Map of chain ID to chain configuration
    configs: HashMap<u64, ChainConfig>,
}

impl ChainRegistry {
    /// Create a new chain registry with default configurations
    pub fn new() -> Self {
        let mut configs = HashMap::new();
        
        // Add default chain configurations
        configs.insert(1, ChainConfig::ethereum());
        configs.insert(137, ChainConfig::polygon());
        configs.insert(56, ChainConfig::bsc());
        configs.insert(42161, ChainConfig::arbitrum());
        configs.insert(10, ChainConfig::optimism());
        configs.insert(43114, ChainConfig::avalanche());
        
        Self { configs }
    }
    
    /// Get chain configuration by chain ID
    pub fn get_config(&self, chain_id: u64) -> Option<&ChainConfig> {
        self.configs.get(&chain_id)
    }
    
    /// Add or update a chain configuration
    pub fn add_config(&mut self, config: ChainConfig) {
        self.configs.insert(config.chain_id, config);
    }
    
    /// Get security considerations for a chain
    pub fn get_security_considerations(&self, chain_id: u64) -> Vec<String> {
        match self.get_config(chain_id) {
            Some(config) => config.security_considerations.clone(),
            None => vec!["Unknown chain, using default security considerations".to_string()],
        }
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        Self::new()
    }
}
