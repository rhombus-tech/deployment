// Proving-Specific Optimizations for FRAC RPC
// Optimizes data fetching patterns specific to ZK proof generation

use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info};

use crate::cache::CacheLayer;
use crate::config::ProvingConfig;
use crate::nodes::NodePool;

/// Optimizes RPC calls for proving workloads
/// - Batches related queries
/// - Prefetches likely-needed data
/// - Provides structured data format for provers
pub struct ProvingOptimizer {
    cache: Arc<CacheLayer>,
    config: ProvingConfig,
}

impl ProvingOptimizer {
    pub fn new(cache: Arc<CacheLayer>, config: ProvingConfig) -> Self {
        Self { cache, config }
    }

    /// Get all data needed to prove a single block (optimized single query)
    pub async fn get_proving_data(
        &self,
        block_number: u64,
        primary_pool: &Arc<NodePool>,
        fallback_pool: &Arc<NodePool>,
    ) -> Result<Value> {
        debug!("Fetching proving data for block {}", block_number);

        // Check cache first
        let cache_key = json!({
            "method": "frac_getProvingData",
            "params": [block_number]
        });

        if let Some(cached) = self.cache.get(&cache_key).await? {
            debug!("Proving data cache hit for block {}", block_number);
            return Ok(cached);
        }

        // Fetch all data in parallel
        let (block_data, receipts_data) = tokio::try_join!(
            self.fetch_block_with_transactions(block_number, primary_pool, fallback_pool),
            self.fetch_block_receipts(block_number, primary_pool, fallback_pool)
        )?;

        // Construct proving-optimized response
        let proving_data = json!({
            "block_number": block_number,
            "block_header": {
                "parent_hash": block_data["parentHash"],
                "state_root": block_data["stateRoot"],
                "transactions_root": block_data["transactionsRoot"],
                "receipts_root": block_data["receiptsRoot"],
                "timestamp": block_data["timestamp"],
                "gas_used": block_data["gasUsed"],
                "gas_limit": block_data["gasLimit"],
            },
            "transactions": block_data["transactions"],
            "receipts": receipts_data,
            "proving_metadata": {
                "tx_count": block_data["transactions"].as_array().map(|v| v.len()).unwrap_or(0),
                "total_gas_used": block_data["gasUsed"],
                "cached": false,
            }
        });

        // Cache for other provers
        self.cache.set(&cache_key, &proving_data).await?;

        info!("Proving data fetched and cached for block {}", block_number);
        Ok(proving_data)
    }

    /// Get proving data for multiple blocks (batched and optimized)
    pub async fn get_batch_proving_data(
        &self,
        block_numbers: Vec<u64>,
        primary_pool: &Arc<NodePool>,
        fallback_pool: &Arc<NodePool>,
    ) -> Result<Value> {
        if block_numbers.len() > self.config.batch_size {
            return Err(anyhow::anyhow!(
                "Batch size {} exceeds maximum {}",
                block_numbers.len(),
                self.config.batch_size
            ));
        }

        info!("Fetching batch proving data for {} blocks", block_numbers.len());

        // Fetch all blocks in parallel
        let mut tasks = Vec::new();
        for block_num in &block_numbers {
            let block_num = *block_num;
            let primary = primary_pool.clone();
            let fallback = fallback_pool.clone();
            let cache = self.cache.clone();
            let optimizer = Arc::new(Self::new(cache, self.config.clone()));

            tasks.push(tokio::spawn(async move {
                optimizer.get_proving_data(block_num, &primary, &fallback).await
            }));
        }

        // Wait for all to complete
        let results = futures::future::join_all(tasks).await;

        // Collect results
        let mut proving_data_batch = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(Ok(data)) => proving_data_batch.push(data),
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!(
                        "Failed to fetch block {}: {}",
                        block_numbers[i],
                        e
                    ))
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Task failed for block {}: {}",
                        block_numbers[i],
                        e
                    ))
                }
            }
        }

        Ok(json!({
            "blocks": proving_data_batch,
            "batch_size": block_numbers.len(),
        }))
    }

    async fn fetch_block_with_transactions(
        &self,
        block_number: u64,
        primary_pool: &Arc<NodePool>,
        fallback_pool: &Arc<NodePool>,
    ) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{:x}", block_number), true], // true = full tx objects
            "id": 1
        });

        match primary_pool.execute(&request).await {
            Ok(response) => Ok(response["result"].clone()),
            Err(_) => {
                let response = fallback_pool.execute(&request).await?;
                Ok(response["result"].clone())
            }
        }
    }

    async fn fetch_block_receipts(
        &self,
        block_number: u64,
        primary_pool: &Arc<NodePool>,
        fallback_pool: &Arc<NodePool>,
    ) -> Result<Value> {
        // First get the block to know transaction hashes
        let block = self.fetch_block_with_transactions(block_number, primary_pool, fallback_pool).await?;
        
        let transactions = block["transactions"].as_array().ok_or_else(|| {
            anyhow::anyhow!("Block has no transactions array")
        })?;

        // Fetch all receipts in parallel
        let mut receipt_tasks: Vec<tokio::task::JoinHandle<Result<Value>>> = Vec::new();
        for tx in transactions {
            let tx_hash = tx["hash"].as_str().unwrap_or("").to_string();
            let primary = primary_pool.clone();
            let fallback = fallback_pool.clone();

            receipt_tasks.push(tokio::spawn(async move {
                let request = json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1
                });

                match primary.execute(&request).await {
                    Ok(response) => Ok(response["result"].clone()),
                    Err(_) => {
                        let response = fallback.execute(&request).await?;
                        Ok(response["result"].clone())
                    }
                }
            }));
        }

        let receipts: Vec<Value> = futures::future::join_all(receipt_tasks)
            .await
            .into_iter()
            .filter_map(|r| match r {
                Ok(Ok(val)) => Some(val),
                _ => None,
            })
            .collect();

        Ok(json!(receipts))
    }
}
