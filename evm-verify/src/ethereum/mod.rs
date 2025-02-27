use std::sync::Arc;
use ethers::{
    providers::{Provider, Http},
    types::{Address, TransactionReceipt, H256},
};
use anyhow::Result;

pub mod proof;
pub mod trie;
pub mod etherscan;

#[cfg(test)]
mod tests {
    pub(crate) use super::*;
    pub(crate) use ethers::types::{Address, H256, U256};
    pub(crate) use std::collections::HashMap;
    pub(crate) use hex_literal::hex;
    
    mod proof_tests;
    mod trie_tests;
}

/// Interface to Ethereum network
pub struct EthereumConnector {
    provider: Arc<Provider<Http>>,
}

impl EthereumConnector {
    /// Create new Ethereum connector
    pub fn new(rpc_url: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        Ok(Self {
            provider: Arc::new(provider),
        })
    }

    /// Get contract deployment transaction
    pub async fn get_deployment(
        &self,
        contract: Address,
    ) -> Result<TransactionReceipt> {
        // Implementation TBD
        unimplemented!()
    }
}
