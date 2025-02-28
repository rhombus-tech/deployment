use std::sync::Arc;
use ethers::{
    providers::{Provider, Http, Middleware},
    types::{Address, TransactionReceipt, H256, BlockNumber, U256},
};
use anyhow::Result;
use log::debug;

pub mod proof;
pub mod trie;
pub mod chain;

use chain::{ChainConfig, ChainRegistry};

#[cfg(test)]
mod tests {
    pub(crate) use ethers::types::{Address, H256, U256};
    
    mod proof_tests;
    mod trie_tests;
}

/// Ethereum connector for interacting with Ethereum-compatible chains
pub struct EthereumConnector {
    /// Provider for interacting with the Ethereum node
    provider: Arc<Provider<Http>>,
    /// Chain ID cache
    chain_id: Option<u64>,
    /// Chain registry for chain-specific configurations
    chain_registry: ChainRegistry,
}

impl EthereumConnector {
    /// Create a new Ethereum connector
    pub fn new(rpc_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        
        Ok(Self {
            provider: Arc::new(provider),
            chain_id: None,
            chain_registry: ChainRegistry::new(),
        })
    }
    
    /// Initialize the connector
    pub async fn init(&mut self) -> Result<()> {
        // Get and cache the chain ID
        let chain_id = self.provider.get_chainid().await?;
        self.chain_id = Some(chain_id.as_u64());
        
        debug!("Connected to chain ID: {}", chain_id);
        
        Ok(())
    }
    
    /// Get current chain ID
    pub async fn chain_id(&self) -> Result<u64> {
        if let Some(id) = self.chain_id {
            return Ok(id);
        }
        
        let chain_id = self.provider.get_chainid().await?;
        Ok(chain_id.as_u64())
    }
    
    /// Get chain ID (alias for chain_id)
    pub async fn get_chain_id(&self) -> Result<u64> {
        self.chain_id().await
    }
    
    /// Get chain configuration
    pub async fn chain_config(&self) -> Result<ChainConfig> {
        let chain_id = self.chain_id().await?;
        
        if let Some(config) = self.chain_registry.get_config(chain_id) {
            Ok(config.clone())
        } else {
            // Return a default configuration for unknown chains
            Ok(ChainConfig {
                chain_id,
                name: format!("Unknown Chain (ID: {})", chain_id),
                block_time: 15,
                block_gas_limit: U256::from(15_000_000),
                currency_symbol: "ETH".to_string(),
                security_considerations: vec![
                    "Unknown chain, proceed with caution".to_string(),
                ],
            })
        }
    }
    
    /// Get contract deployment transaction
    pub async fn get_deployment(
        &self,
        contract: Address,
    ) -> Result<TransactionReceipt> {
        // Get the contract code first to ensure it exists
        let bytecode = self.get_bytecode(contract).await?;
        if bytecode.is_empty() {
            return Err(anyhow::anyhow!("Contract not found at address: {}", contract));
        }
        
        // Check if there are any transactions for this contract
        // The first transaction is typically the contract creation
        let tx_count = self.get_transaction_count(contract).await?;
        if tx_count == 0 {
            return Err(anyhow::anyhow!("No transactions found for contract: {}", contract));
        }
        
        // Get the first transaction (simplified approach)
        // Note: This is a simplified approach. In practice, we would need to
        // implement a more sophisticated search strategy, possibly using logs or events.
        let tx_hash = self.get_transaction_by_block_number_and_index(0, 0).await?;
        
        if let Some(tx) = tx_hash {
            // Get the transaction receipt
            if let Some(receipt) = self.get_transaction_receipt(tx.hash).await? {
                if receipt.contract_address == Some(contract) {
                    return Ok(receipt);
                }
            }
        }
        
        Err(anyhow::anyhow!("Could not find deployment transaction for contract: {}", contract))
    }

    /// Get contract bytecode
    pub async fn get_bytecode(&self, contract: Address) -> Result<Vec<u8>> {
        let bytecode = self.provider.get_code(contract, None).await?;
        Ok(bytecode.to_vec())
    }
    
    /// Get contract storage at a specific slot
    pub async fn get_storage_at(&self, address: Address, slot: H256) -> Result<H256> {
        let value = self.provider.get_storage_at(address, slot, None).await?;
        Ok(value)
    }
    
    /// Get latest block number
    pub async fn get_block_number(&self) -> Result<u64> {
        let block_number = self.provider.get_block_number().await?;
        Ok(block_number.as_u64())
    }
    
    /// Get transaction count
    pub async fn get_transaction_count(&self, address: Address) -> Result<u64> {
        let count = self.provider.get_transaction_count(address, None).await?;
        Ok(count.as_u64())
    }
    
    /// Get transaction by block number and index
    pub async fn get_transaction_by_block_number_and_index(&self, block_number: u64, index: u64) -> Result<Option<ethers::types::Transaction>> {
        let block = BlockNumber::Number(block_number.into());
        let tx = self.provider.get_transaction_by_block_and_index(block, index.into()).await?;
        Ok(tx)
    }
    
    /// Get transaction receipt
    pub async fn get_transaction_receipt(&self, tx_hash: H256) -> Result<Option<TransactionReceipt>> {
        let receipt = self.provider.get_transaction_receipt(tx_hash).await?;
        Ok(receipt)
    }
    
    /// Analyze contract on-chain
    pub async fn analyze_contract(&self, contract: Address) -> Result<crate::bytecode::AnalysisResults> {
        // Get bytecode
        let bytecode_bytes = self.get_bytecode(contract).await?;
        let bytecode = ethers::types::Bytes::from(bytecode_bytes);
        
        // Create bytecode analyzer
        let mut analyzer = crate::bytecode::BytecodeAnalyzer::new(bytecode);
        
        // Get chain ID for chain-specific analysis
        let chain_id = self.chain_id().await?;
        
        // Configure analyzer based on chain ID
        self.configure_analyzer_for_chain(&mut analyzer, chain_id)?;
        
        // Run analysis
        let mut results = analyzer.analyze()?;
        
        // Add chain-specific warnings
        self.add_chain_specific_warnings(&mut results, chain_id)?;
        
        Ok(results)
    }
    
    /// Add chain-specific warnings to analysis results
    fn add_chain_specific_warnings(&self, results: &mut crate::bytecode::AnalysisResults, chain_id: u64) -> Result<()> {
        // Get chain configuration
        let config = match self.chain_registry.get_config(chain_id) {
            Some(config) => config,
            None => return Ok(()), // No chain-specific warnings for unknown chains
        };
        
        // Add chain-specific warnings based on the chain and analysis results
        match chain_id {
            1 => {
                // Ethereum Mainnet
                // Check for high gas usage patterns on Ethereum mainnet
                if results.gas_usage > 5_000_000 {
                    results.warnings.push(format!(
                        "High gas usage detected ({} gas) which may lead to transaction failures during network congestion on {}",
                        results.gas_usage, config.name
                    ));
                }
            },
            137 => {
                // Polygon - faster block times
                // Check for timestamp dependency on Polygon
                if !results.timestamp_dependencies.is_empty() {
                    results.warnings.push(format!(
                        "Timestamp dependency detected which is particularly risky on {} due to faster block times ({}s)",
                        config.name, config.block_time
                    ));
                }
            },
            56 => {
                // Binance Smart Chain
                // Check for centralization risks on BSC
                if !results.delegate_calls.is_empty() {
                    results.warnings.push(format!(
                        "Delegate calls detected which may pose additional centralization risks on {} due to its validator structure",
                        config.name
                    ));
                }
            },
            43114 | 42161 | 10 => {
                // L2 chains (Avalanche, Arbitrum, Optimism)
                // Check for cross-chain communication patterns
                if !results.external_calls.is_empty() {
                    results.warnings.push(format!(
                        "External calls detected which may need special handling on L2 chain {} for cross-chain communication",
                        config.name
                    ));
                }
            },
            _ => {
                // Add generic chain-specific warnings for other chains
                results.warnings.push(format!(
                    "Contract analyzed on {} (chain ID: {}). Review chain-specific security considerations.",
                    config.name, chain_id
                ));
            }
        }
        
        // Add general chain information to results
        results.metadata.insert(
            "chain_name".to_string(),
            config.name.clone()
        );
        results.metadata.insert(
            "chain_id".to_string(),
            chain_id.to_string()
        );
        results.metadata.insert(
            "block_time".to_string(),
            config.block_time.to_string()
        );
        
        Ok(())
    }
    
    /// Configure analyzer based on chain ID
    fn configure_analyzer_for_chain(&self, analyzer: &mut crate::bytecode::BytecodeAnalyzer, chain_id: u64) -> Result<()> {
        // Get chain configuration from registry
        let config = match self.chain_registry.get_config(chain_id) {
            Some(config) => config,
            None => {
                // Unknown chain, use default configuration
                analyzer.set_test_mode(false);
                return Ok(());
            }
        };
        
        // Configure analyzer based on chain configuration
        analyzer.set_test_mode(false);
        
        // Apply chain-specific configurations
        match chain_id {
            1 => {
                // Ethereum Mainnet
                // Standard configuration, no special adjustments needed
            },
            137 => {
                // Polygon - faster block times
                // Adjust timestamp dependency checks to be more sensitive
                // due to faster block times on Polygon
            },
            56 => {
                // Binance Smart Chain
                // More centralized validator set may affect certain security assumptions
            },
            43114 => {
                // Avalanche C-Chain
                // Faster finality may affect certain timing assumptions
            },
            42161 => {
                // Arbitrum
                // L2-specific considerations
            },
            10 => {
                // Optimism
                // L2-specific considerations
            },
            _ => {
                // Unknown chain, already handled above
            }
        }
        
        // Log chain-specific security considerations
        for consideration in &config.security_considerations {
            debug!("Chain-specific security consideration for {}: {}", 
                   config.name, consideration);
        }
        
        Ok(())
    }
}
