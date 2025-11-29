use anyhow::{anyhow, Result};
use ethers::providers::{Http, Middleware, Provider};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::NodeConfig;

/// Manages a pool of Ethereum nodes with load balancing and health checking
pub struct NodePool {
    nodes: Vec<NodeConnection>,
    current_index: Arc<RwLock<usize>>,
    timeout_secs: u64,
}

struct NodeConnection {
    config: NodeConfig,
    provider: Provider<Http>,
    health: Arc<RwLock<NodeHealth>>,
}

#[derive(Clone, Debug)]
struct NodeHealth {
    is_healthy: bool,
    last_check: u64,
    error_count: u32,
    success_count: u32,
    avg_latency_ms: f64,
}

impl Default for NodeHealth {
    fn default() -> Self {
        Self {
            is_healthy: true,
            last_check: 0,
            error_count: 0,
            success_count: 0,
            avg_latency_ms: 0.0,
        }
    }
}

impl NodePool {
    pub async fn new(nodes: Vec<NodeConfig>, timeout_secs: u64) -> Result<Self> {
        let mut connections = Vec::new();

        for node_config in nodes {
            match Provider::<Http>::try_from(&node_config.url) {
                Ok(provider) => {
                    connections.push(NodeConnection {
                        config: node_config.clone(),
                        provider,
                        health: Arc::new(RwLock::new(NodeHealth::default())),
                    });
                    info!("✅ Connected to node: {}", node_config.name);
                }
                Err(e) => {
                    warn!("Failed to connect to {}: {}", node_config.name, e);
                }
            }
        }

        if connections.is_empty() {
            return Err(anyhow!("No nodes could be connected"));
        }

        Ok(Self {
            nodes: connections,
            current_index: Arc::new(RwLock::new(0)),
            timeout_secs,
        })
    }

    /// Execute an RPC request with load balancing and automatic failover
    pub async fn execute(&self, request: &Value) -> Result<Value> {
        let max_attempts = self.nodes.len();
        let mut last_error = None;

        for _ in 0..max_attempts {
            // Get next healthy node using weighted round-robin
            let node = self.get_next_healthy_node().await?;
            let start = std::time::Instant::now();

            // Execute request
            match self.execute_on_node(node, request).await {
                Ok(response) => {
                    // Update health stats
                    let latency = start.elapsed().as_millis() as f64;
                    self.record_success(node, latency).await;
                    return Ok(response);
                }
                Err(e) => {
                    warn!("Node {} failed: {}", node.config.name, e);
                    self.record_failure(node).await;
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All nodes failed")))
    }

    /// Health check all nodes
    pub async fn health_check(&self) -> Result<()> {
        for node in &self.nodes {
            match self.check_node_health(node).await {
                Ok(_) => {
                    let mut health = node.health.write().await;
                    health.is_healthy = true;
                }
                Err(e) => {
                    warn!("Health check failed for {}: {}", node.config.name, e);
                    let mut health = node.health.write().await;
                    health.is_healthy = false;
                }
            }
        }

        // At least one node must be healthy
        let any_healthy = self.nodes.iter().any(|n| {
            let health = tokio::runtime::Handle::current().block_on(n.health.read());
            health.is_healthy
        });

        if !any_healthy {
            return Err(anyhow!("No healthy nodes available"));
        }

        Ok(())
    }

    /// Get pool statistics
    pub async fn get_stats(&self) -> Value {
        let mut node_stats = Vec::new();

        for node in &self.nodes {
            let health = node.health.read().await;
            node_stats.push(serde_json::json!({
                "name": node.config.name,
                "url": node.config.url,
                "is_healthy": health.is_healthy,
                "error_count": health.error_count,
                "success_count": health.success_count,
                "avg_latency_ms": health.avg_latency_ms,
                "total_requests": health.success_count + health.error_count,
            }));
        }

        serde_json::json!({
            "total_nodes": self.nodes.len(),
            "nodes": node_stats,
        })
    }

    async fn get_next_healthy_node(&self) -> Result<&NodeConnection> {
        let mut index = self.current_index.write().await;
        
        // Try to find a healthy node using weighted round-robin
        for _ in 0..self.nodes.len() {
            *index = (*index + 1) % self.nodes.len();
            let node = &self.nodes[*index];
            
            let health = node.health.read().await;
            if health.is_healthy {
                return Ok(node);
            }
        }

        // If no healthy nodes, return first node anyway (last resort)
        Ok(&self.nodes[0])
    }

    async fn execute_on_node(&self, node: &NodeConnection, request: &Value) -> Result<Value> {
        // Parse JSON-RPC request
        let method = request["method"].as_str().ok_or_else(|| anyhow!("Missing method"))?;
        let params = &request["params"];

        // Execute based on method type
        match method {
            "eth_blockNumber" => {
                let block_number = node.provider.get_block_number().await?;
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": format!("0x{:x}", block_number.as_u64()),
                    "id": request["id"]
                }))
            }
            "eth_getBlockByNumber" => {
                let block_param = params[0].as_str().unwrap_or("latest");
                let block_num = self.parse_block_number(block_param)?;
                
                let block = node.provider.get_block(block_num).await?;
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": block,
                    "id": request["id"]
                }))
            }
            _ => {
                // Forward other methods as-is
                let response: Value = node.provider.request(method, params.clone()).await?;
                Ok(serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": response,
                    "id": request["id"]
                }))
            }
        }
    }

    async fn check_node_health(&self, node: &NodeConnection) -> Result<()> {
        // Simple health check: get latest block number
        let _ = node.provider.get_block_number().await?;
        Ok(())
    }

    async fn record_success(&self, node: &NodeConnection, latency_ms: f64) {
        let mut health = node.health.write().await;
        health.success_count += 1;
        health.is_healthy = true;
        
        // Update rolling average latency
        let total_requests = (health.success_count + health.error_count) as f64;
        health.avg_latency_ms = 
            (health.avg_latency_ms * (total_requests - 1.0) + latency_ms) / total_requests;
    }

    async fn record_failure(&self, node: &NodeConnection) {
        let mut health = node.health.write().await;
        health.error_count += 1;
        
        // Mark unhealthy if error rate is too high
        let total_requests = health.success_count + health.error_count;
        if total_requests > 10 {
            let error_rate = health.error_count as f64 / total_requests as f64;
            if error_rate > 0.5 {
                health.is_healthy = false;
                warn!("Node {} marked unhealthy (error rate: {:.1}%)", 
                    node.config.name, error_rate * 100.0);
            }
        }
    }

    fn parse_block_number(&self, param: &str) -> Result<u64> {
        match param {
            "latest" | "pending" => Ok(u64::MAX), // Will be replaced by provider
            _ if param.starts_with("0x") => {
                u64::from_str_radix(&param[2..], 16)
                    .map_err(|e| anyhow!("Invalid hex block number: {}", e))
            }
            _ => param.parse::<u64>()
                .map_err(|e| anyhow!("Invalid block number: {}", e)),
        }
    }
}
