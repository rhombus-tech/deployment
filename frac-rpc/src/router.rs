use crate::cache::CacheLayer;
use crate::config::{FracRPCConfig, NodeConfig};
use crate::nodes::NodePool;
use crate::proving_optimizer::ProvingOptimizer;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub struct RPCRouter {
    primary_pool: Arc<NodePool>,
    fallback_pool: Arc<NodePool>,
    cache: Arc<CacheLayer>,
    proving_optimizer: Arc<ProvingOptimizer>,
    config: FracRPCConfig,
    stats: Arc<RwLock<RouterStats>>,
}

#[derive(Default, Clone, Debug)]
pub struct RouterStats {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub primary_requests: u64,
    pub fallback_requests: u64,
    pub errors: u64,
    pub avg_latency_ms: f64,
}

impl RPCRouter {
    pub async fn new(config: FracRPCConfig) -> Result<Self> {
        info!("Initializing RPC Router...");

        // Initialize cache layer
        let cache = Arc::new(CacheLayer::new(&config.cache).await?);
        info!("✅ Cache layer initialized");

        // Initialize node pools
        let primary_pool = Arc::new(NodePool::new(
            config.nodes.primary.clone(),
            config.nodes.request_timeout_secs,
        ).await?);
        info!("✅ Primary node pool initialized ({} nodes)", config.nodes.primary.len());

        let fallback_pool = Arc::new(NodePool::new(
            config.nodes.fallback.clone(),
            config.nodes.request_timeout_secs,
        ).await?);
        info!("✅ Fallback node pool initialized ({} nodes)", config.nodes.fallback.len());

        // Initialize proving optimizer
        let proving_optimizer = Arc::new(ProvingOptimizer::new(
            cache.clone(),
            config.proving.clone(),
        ));
        info!("✅ Proving optimizer initialized");

        Ok(Self {
            primary_pool,
            fallback_pool,
            cache,
            proving_optimizer,
            config,
            stats: Arc::new(RwLock::new(RouterStats::default())),
        })
    }

    /// Route a JSON-RPC request through the intelligent routing system
    pub async fn route_request(&self, request: Value) -> Result<Value> {
        let start = std::time::Instant::now();
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        drop(stats);

        // Extract method for caching decision
        let method = request["method"].as_str().unwrap_or("");
        let is_cacheable = self.is_cacheable_method(method);

        // Try cache first for cacheable requests
        if is_cacheable {
            if let Some(cached) = self.cache.get(&request).await? {
                debug!("Cache hit for method: {}", method);
                let mut stats = self.stats.write().await;
                stats.cache_hits += 1;
                return Ok(cached);
            } else {
                let mut stats = self.stats.write().await;
                stats.cache_misses += 1;
            }
        }

        // Try primary pool first
        match self.primary_pool.execute(&request).await {
            Ok(response) => {
                let mut stats = self.stats.write().await;
                stats.primary_requests += 1;
                stats.avg_latency_ms = self.update_avg_latency(
                    stats.avg_latency_ms,
                    stats.total_requests,
                    start.elapsed().as_millis() as f64,
                );
                drop(stats);

                // Cache successful response
                if is_cacheable {
                    let _ = self.cache.set(&request, &response).await;
                }

                return Ok(response);
            }
            Err(e) => {
                warn!("Primary pool failed: {}, trying fallback", e);
            }
        }

        // Fallback to secondary pool
        match self.fallback_pool.execute(&request).await {
            Ok(response) => {
                let mut stats = self.stats.write().await;
                stats.fallback_requests += 1;
                stats.avg_latency_ms = self.update_avg_latency(
                    stats.avg_latency_ms,
                    stats.total_requests,
                    start.elapsed().as_millis() as f64,
                );
                drop(stats);

                // Cache successful response
                if is_cacheable {
                    let _ = self.cache.set(&request, &response).await;
                }

                return Ok(response);
            }
            Err(e) => {
                let mut stats = self.stats.write().await;
                stats.errors += 1;
                return Err(anyhow!("All node pools failed: {}", e));
            }
        }
    }

    /// Get proving-optimized data for a single block
    pub async fn get_proving_data(&self, block_number: u64) -> Result<Value> {
        self.proving_optimizer.get_proving_data(
            block_number,
            &self.primary_pool,
            &self.fallback_pool,
        ).await
    }

    /// Get proving data for multiple blocks (batched and optimized)
    pub async fn get_batch_proving_data(&self, block_numbers: Vec<u64>) -> Result<Value> {
        self.proving_optimizer.get_batch_proving_data(
            block_numbers,
            &self.primary_pool,
            &self.fallback_pool,
        ).await
    }

    /// Health check all nodes
    pub async fn health_check(&self) -> Result<()> {
        let primary_health = self.primary_pool.health_check().await;
        let fallback_health = self.fallback_pool.health_check().await;

        if primary_health.is_err() && fallback_health.is_err() {
            return Err(anyhow!("All nodes unhealthy"));
        }

        Ok(())
    }

    /// Get router statistics
    pub async fn get_stats(&self) -> Value {
        let stats = self.stats.read().await;
        let cache_hit_rate = if stats.total_requests > 0 {
            (stats.cache_hits as f64 / stats.total_requests as f64) * 100.0
        } else {
            0.0
        };

        serde_json::json!({
            "total_requests": stats.total_requests,
            "cache_hits": stats.cache_hits,
            "cache_misses": stats.cache_misses,
            "cache_hit_rate_percent": cache_hit_rate,
            "primary_requests": stats.primary_requests,
            "fallback_requests": stats.fallback_requests,
            "errors": stats.errors,
            "avg_latency_ms": stats.avg_latency_ms,
            "primary_pool": self.primary_pool.get_stats().await,
            "fallback_pool": self.fallback_pool.get_stats().await,
        })
    }

    fn is_cacheable_method(&self, method: &str) -> bool {
        matches!(
            method,
            "eth_getBlockByNumber" |
            "eth_getBlockByHash" |
            "eth_getTransactionByHash" |
            "eth_getTransactionReceipt" |
            "eth_getBlockTransactionCountByNumber" |
            "eth_getBlockTransactionCountByHash" |
            "eth_getUncleByBlockNumberAndIndex" |
            "eth_getUncleByBlockHashAndIndex" |
            "eth_getCode" |
            "eth_getStorageAt"
        )
    }

    fn update_avg_latency(&self, current_avg: f64, total: u64, new_latency: f64) -> f64 {
        (current_avg * (total as f64 - 1.0) + new_latency) / total as f64
    }
}
