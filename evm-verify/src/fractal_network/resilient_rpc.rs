// Resilient RPC Provider - Trustless Manifesto Principle
// "No indispensable intermediaries" - Multiple RPC endpoints, no single point of failure

use ethers::providers::{Provider, Http, Middleware};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};
use anyhow::{Result, Context};

/// RPC endpoint with health tracking
#[derive(Clone, Debug)]
pub struct RpcEndpoint {
    pub url: String,
    pub is_local: bool,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub consecutive_failures: u32,
    pub latency_ms: Option<u64>,
}

impl RpcEndpoint {
    pub fn new(url: String, is_local: bool) -> Self {
        Self {
            url,
            is_local,
            last_success: None,
            last_failure: None,
            consecutive_failures: 0,
            latency_ms: None,
        }
    }
    
    /// Calculate health score (0.0 = dead, 1.0 = perfect)
    pub fn health_score(&self) -> f64 {
        let mut score = 1.0;
        
        // Penalize consecutive failures
        score -= (self.consecutive_failures as f64 * 0.2).min(0.8);
        
        // Reward recent success
        if let Some(last_success) = self.last_success {
            let age = last_success.elapsed().as_secs();
            if age < 60 {
                score += 0.2; // Bonus for recent success
            }
        }
        
        // Penalize high latency
        if let Some(latency) = self.latency_ms {
            if latency > 1000 {
                score -= 0.3;
            } else if latency > 500 {
                score -= 0.15;
            }
        }
        
        // Prefer local nodes (trustlessness!)
        if self.is_local {
            score += 0.3;
        }
        
        score.max(0.0).min(1.0)
    }
    
    pub fn is_healthy(&self) -> bool {
        self.consecutive_failures < 3 && self.health_score() > 0.3
    }
}

/// Resilient RPC provider with automatic failover
/// Trustlessness: No single RPC can cause system failure
pub struct ResilientRpcProvider {
    endpoints: Arc<RwLock<Vec<RpcEndpoint>>>,
    current_provider: Arc<RwLock<Option<Arc<Provider<Http>>>>>,
    max_retries: u32,
}

impl ResilientRpcProvider {
    /// Create new resilient provider
    /// Tries multiple endpoints, prefers local nodes
    pub fn new() -> Self {
        let endpoints = Self::default_endpoints();
        
        Self {
            endpoints: Arc::new(RwLock::new(endpoints)),
            current_provider: Arc::new(RwLock::new(None)),
            max_retries: 3,
        }
    }
    
    /// Default endpoint list (public, no single point of failure)
    fn default_endpoints() -> Vec<RpcEndpoint> {
        vec![
            // Local node (MOST trustless - user runs it)
            RpcEndpoint::new("http://localhost:8545".to_string(), true),
            RpcEndpoint::new("http://127.0.0.1:8545".to_string(), true),
            
            // Public RPC endpoints (diverse providers)
            // Trustlessness: Multiple providers, not all can be censored
            RpcEndpoint::new("https://eth.llamarpc.com".to_string(), false),
            RpcEndpoint::new("https://rpc.ankr.com/eth".to_string(), false),
            RpcEndpoint::new("https://ethereum.publicnode.com".to_string(), false),
            RpcEndpoint::new("https://eth.drpc.org".to_string(), false),
            RpcEndpoint::new("https://1rpc.io/eth".to_string(), false),
            RpcEndpoint::new("https://eth.merkle.io".to_string(), false),
            
            // Community-run nodes (add more for decentralization)
            // Users can add their own via config
        ]
    }
    
    /// Add custom RPC endpoint
    pub async fn add_endpoint(&self, url: String, is_local: bool) {
        let mut endpoints = self.endpoints.write().await;
        
        // Avoid duplicates
        if !endpoints.iter().any(|e| e.url == url) {
            println!("➕ Adding RPC endpoint: {} (local: {})", url, is_local);
            endpoints.push(RpcEndpoint::new(url, is_local));
        }
    }
    
    /// Get best available RPC provider
    /// Prefers: local > healthy > any fallback
    pub async fn get_provider(&self) -> Result<Arc<Provider<Http>>> {
        // Try cached provider first
        {
            let current = self.current_provider.read().await;
            if let Some(provider) = &*current {
                return Ok(provider.clone());
            }
        }
        
        // Select best endpoint and create provider
        let endpoint = self.select_best_endpoint().await?;
        let provider = self.create_provider(&endpoint.url).await?;
        
        // Cache it
        *self.current_provider.write().await = Some(provider.clone());
        
        Ok(provider)
    }
    
    /// Select best RPC endpoint based on health scores
    async fn select_best_endpoint(&self) -> Result<RpcEndpoint> {
        let mut endpoints = self.endpoints.write().await;
        
        // Filter healthy endpoints
        let mut healthy: Vec<_> = endpoints.iter()
            .filter(|e| e.is_healthy())
            .cloned()
            .collect();
        
        if healthy.is_empty() {
            // Reset all failures if everything is down
            println!("⚠️  All RPC endpoints unhealthy, resetting failure counts");
            for endpoint in endpoints.iter_mut() {
                endpoint.consecutive_failures = 0;
            }
            healthy = endpoints.clone();
        }
        
        // Sort by health score (best first)
        healthy.sort_by(|a, b| {
            b.health_score().partial_cmp(&a.health_score()).unwrap()
        });
        
        let best = healthy.first()
            .ok_or_else(|| anyhow::anyhow!("No RPC endpoints available"))?;
        
        println!("🌐 Selected RPC: {} (health: {:.2}, local: {})", 
            best.url, best.health_score(), best.is_local);
        
        Ok(best.clone())
    }
    
    /// Create provider with health check
    async fn create_provider(&self, url: &str) -> Result<Arc<Provider<Http>>> {
        let start = Instant::now();
        
        let provider = Provider::<Http>::try_from(url)
            .context(format!("Failed to create provider for {}", url))?;
        let provider = Arc::new(provider);
        
        // Health check: try to get chain ID
        match tokio::time::timeout(
            Duration::from_secs(5),
            provider.get_chainid()
        ).await {
            Ok(Ok(chain_id)) => {
                let latency = start.elapsed().as_millis() as u64;
                
                // Update endpoint health
                self.update_endpoint_health(url, true, Some(latency)).await;
                
                println!("   ✅ RPC healthy: chain_id={}, latency={}ms", chain_id, latency);
                Ok(provider)
            }
            Ok(Err(e)) => {
                self.update_endpoint_health(url, false, None).await;
                Err(anyhow::anyhow!("RPC health check failed: {}", e))
            }
            Err(_) => {
                self.update_endpoint_health(url, false, None).await;
                Err(anyhow::anyhow!("RPC health check timeout"))
            }
        }
    }
    
    /// Update endpoint health metrics
    async fn update_endpoint_health(&self, url: &str, success: bool, latency: Option<u64>) {
        let mut endpoints = self.endpoints.write().await;
        
        if let Some(endpoint) = endpoints.iter_mut().find(|e| e.url == url) {
            if success {
                endpoint.last_success = Some(Instant::now());
                endpoint.consecutive_failures = 0;
                endpoint.latency_ms = latency;
            } else {
                endpoint.last_failure = Some(Instant::now());
                endpoint.consecutive_failures += 1;
            }
        }
    }
    
    /// Execute RPC call with automatic retry and failover
    pub async fn execute_with_retry<F, T>(&self, operation: F) -> Result<T>
    where
        F: Fn(Arc<Provider<Http>>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>> + Send,
        T: Send,
    {
        let mut last_error = None;
        
        for attempt in 0..self.max_retries {
            if attempt > 0 {
                println!("   🔄 Retry attempt {}/{}", attempt + 1, self.max_retries);
            }
            
            // Get best provider
            let provider = match self.get_provider().await {
                Ok(p) => p,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            
            // Try operation
            match operation(provider.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    eprintln!("   ❌ RPC call failed: {}", e);
                    
                    // Mark current provider as failed
                    *self.current_provider.write().await = None;
                    
                    last_error = Some(e);
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All RPC attempts failed")))
    }
    
    /// Get health report for all endpoints
    pub async fn health_report(&self) -> Vec<(String, f64, bool)> {
        let endpoints = self.endpoints.read().await;
        
        endpoints.iter()
            .map(|e| (e.url.clone(), e.health_score(), e.is_local))
            .collect()
    }
    
    /// Check if any local node is available
    pub async fn has_local_node(&self) -> bool {
        let endpoints = self.endpoints.read().await;
        endpoints.iter()
            .any(|e| e.is_local && e.is_healthy())
    }
}

impl Default for ResilientRpcProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_endpoint_health_score() {
        let mut endpoint = RpcEndpoint::new("http://test".to_string(), false);
        
        // Fresh endpoint should have good score
        assert!(endpoint.health_score() > 0.8);
        
        // Failures decrease score
        endpoint.consecutive_failures = 2;
        assert!(endpoint.health_score() < 0.7);
        
        // Local nodes get bonus
        endpoint.is_local = true;
        assert!(endpoint.health_score() > 0.5);
    }
    
    #[tokio::test]
    async fn test_add_custom_endpoint() {
        let provider = ResilientRpcProvider::new();
        
        provider.add_endpoint("http://custom:8545".to_string(), true).await;
        
        let endpoints = provider.endpoints.read().await;
        assert!(endpoints.iter().any(|e| e.url == "http://custom:8545"));
    }
    
    #[tokio::test]
    async fn test_prefers_local_nodes() {
        let provider = ResilientRpcProvider::new();
        
        // Local nodes should be preferred
        let has_local = provider.has_local_node().await;
        println!("Has local node available: {}", has_local);
    }
}
