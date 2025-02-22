use anyhow::Result;
use ethers::{
    providers::{Http, Provider},
    types::{Address, TransactionReceipt},
};
use std::sync::Arc;

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
