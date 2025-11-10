use ethers::types::{H160, Bytes};
use ethers::providers::{Provider, Http, Middleware};
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use tokio::sync::RwLock;

/// Fetches and caches contract bytecode from RPC nodes
#[derive(Debug, Clone)]
pub struct RPCBytecodeFetcher {
    provider: Arc<Provider<Http>>,
    cache: Arc<RwLock<HashMap<H160, Vec<u8>>>>,
    rpc_url: String,
}

impl RPCBytecodeFetcher {
    /// Create a new bytecode fetcher with RPC endpoint
    pub fn new(rpc_url: String) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url.as_str())
            .map_err(|e| anyhow!("Failed to create provider: {}", e))?;
        
        Ok(Self {
            provider: Arc::new(provider),
            cache: Arc::new(RwLock::new(HashMap::new())),
            rpc_url,
        })
    }

    /// Fetch bytecode for a contract address
    pub async fn get_bytecode(&self, address: H160) -> Result<Vec<u8>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(bytecode) = cache.get(&address) {
                return Ok(bytecode.clone());
            }
        }

        // Fetch from RPC
        let code = self.provider
            .get_code(address, None)
            .await
            .map_err(|e| anyhow!("Failed to fetch bytecode for {:?}: {}", address, e))?;

        let bytecode = code.to_vec();

        // Cache it
        {
            let mut cache = self.cache.write().await;
            cache.insert(address, bytecode.clone());
        }

        Ok(bytecode)
    }

    /// Fetch bytecode for multiple contracts in parallel
    pub async fn get_bytecodes(&self, addresses: &[H160]) -> Result<HashMap<H160, Vec<u8>>> {
        let mut results = HashMap::new();
        
        // Fetch all in parallel
        let futures: Vec<_> = addresses
            .iter()
            .map(|addr| self.get_bytecode(*addr))
            .collect();

        let bytecodes = futures::future::join_all(futures).await;

        for (addr, result) in addresses.iter().zip(bytecodes) {
            match result {
                Ok(bytecode) => {
                    results.insert(*addr, bytecode);
                }
                Err(e) => {
                    eprintln!("Failed to fetch bytecode for {:?}: {}", addr, e);
                }
            }
        }

        Ok(results)
    }

    /// Check if contract exists (has bytecode)
    pub async fn contract_exists(&self, address: H160) -> Result<bool> {
        let bytecode = self.get_bytecode(address).await?;
        Ok(!bytecode.is_empty())
    }

    /// Get cache size
    pub async fn cache_size(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Pre-warm cache with known addresses
    pub async fn warm_cache(&self, addresses: Vec<H160>) -> Result<()> {
        let _ = self.get_bytecodes(&addresses).await?;
        Ok(())
    }
}

impl Default for RPCBytecodeFetcher {
    fn default() -> Self {
        // Default to localhost
        Self::new("http://127.0.0.1:8545".to_string())
            .expect("Failed to create default fetcher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetcher_creation() {
        let fetcher = RPCBytecodeFetcher::new("http://localhost:8545".to_string());
        assert!(fetcher.is_ok());
    }

    #[tokio::test]
    async fn test_cache() {
        let fetcher = RPCBytecodeFetcher::default();
        assert_eq!(fetcher.cache_size().await, 0);
    }
}
