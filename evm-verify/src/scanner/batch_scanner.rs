//! Batch contract scanner with priority queue and caching

use std::sync::Arc;
use std::collections::{HashMap, BinaryHeap, HashSet};
use tokio::sync::{RwLock, Semaphore};
use serde::{Deserialize, Serialize};
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{H160, Bytes};

use crate::analysis::comprehensive_analyzer::{ComprehensiveSecurityAnalyzer, ComprehensiveAnalysisResult};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 1,       // Historical contracts
    Medium = 2,    // Active contracts
    High = 3,      // High TVL (>$10M)
    Critical = 4,  // Active exploits
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub address: String,
    pub priority: Priority,
    pub tvl: Option<f64>,
    pub requested_at: u64,
}

impl Ord for ScanRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
            .then_with(|| other.requested_at.cmp(&self.requested_at))
    }
}

impl PartialOrd for ScanRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ScanRequest {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Eq for ScanRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResult {
    pub result: ComprehensiveAnalysisResult,
    pub cached_at: u64,
    pub bytecode_hash: String,
}

pub struct BatchScanner {
    queue: Arc<RwLock<BinaryHeap<ScanRequest>>>,
    cache: Arc<RwLock<HashMap<String, CachedResult>>>,
    in_progress: Arc<RwLock<HashSet<String>>>,
    eth_provider: Arc<Provider<Http>>,
    semaphore: Arc<Semaphore>,
    cache_ttl: u64,
}

impl BatchScanner {
    pub async fn new(rpc_url: &str, max_concurrent: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        
        Ok(Self {
            queue: Arc::new(RwLock::new(BinaryHeap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            in_progress: Arc::new(RwLock::new(HashSet::new())),
            eth_provider: Arc::new(provider),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            cache_ttl: 86400, // 24 hours
        })
    }
    
    /// Add contract to scan queue
    pub async fn queue_scan(&self, address: String, priority: Priority, tvl: Option<f64>) {
        // Check if already in progress
        {
            let in_progress = self.in_progress.read().await;
            if in_progress.contains(&address) {
                return;
            }
        }
        
        // Check cache
        if let Some(cached) = self.get_cached(&address).await {
            let age = current_timestamp() - cached.cached_at;
            if age < self.cache_ttl {
                return; // Fresh cache, skip
            }
        }
        
        let request = ScanRequest {
            address,
            priority,
            tvl,
            requested_at: current_timestamp(),
        };
        
        self.queue.write().await.push(request);
    }
    
    /// Batch queue multiple contracts
    pub async fn queue_batch(&self, addresses: Vec<(String, Priority, Option<f64>)>) {
        for (address, priority, tvl) in addresses {
            self.queue_scan(address, priority, tvl).await;
        }
    }
    
    /// Process next batch of scans (up to max_concurrent)
    pub async fn process_batch(&self, batch_size: usize) -> Vec<(String, Result<ComprehensiveAnalysisResult, String>)> {
        let mut handles = Vec::new();
        
        // Grab batch of requests
        let requests: Vec<ScanRequest> = {
            let mut queue = self.queue.write().await;
            (0..batch_size.min(queue.len()))
                .filter_map(|_| queue.pop())
                .collect()
        };
        
        // Mark as in progress
        {
            let mut in_progress = self.in_progress.write().await;
            for req in &requests {
                in_progress.insert(req.address.clone());
            }
        }
        
        // Scan in parallel
        for request in requests {
            let scanner = self.clone_for_worker();
            let permit = self.semaphore.clone().acquire_owned().await.unwrap();
            
            let handle = tokio::spawn(async move {
                let result = scanner.scan_single(&request.address).await;
                drop(permit);
                (request.address.clone(), result)
            });
            
            handles.push(handle);
        }
        
        // Wait for all to complete
        let mut results = Vec::new();
        for handle in handles {
            if let Ok(result) = handle.await {
                // Remove from in_progress
                self.in_progress.write().await.remove(&result.0);
                results.push(result);
            }
        }
        
        results
    }
    
    /// Scan single contract (internal)
    async fn scan_single(&self, address: &str) -> Result<ComprehensiveAnalysisResult, String> {
        // Fetch bytecode
        let addr = address.parse::<H160>()
            .map_err(|e| format!("Invalid address: {}", e))?;
        
        let bytecode: Bytes = self.eth_provider.get_code(addr, None).await
            .map_err(|e| format!("RPC error: {}", e))?;
        
        if bytecode.is_empty() {
            return Err("No bytecode found".to_string());
        }
        
        // Calculate hash for dedup
        let hash_value = bytecode.len() as u64 
            ^ (bytecode.first().copied().unwrap_or(0) as u64) << 8
            ^ (bytecode.last().copied().unwrap_or(0) as u64) << 16;
        let bytecode_hash = format!("0x{:016x}", hash_value);
        
        // Run analysis
        let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.to_vec());
        let result = analyzer.analyze();
        
        // Cache result
        let cached = CachedResult {
            result: result.clone(),
            cached_at: current_timestamp(),
            bytecode_hash,
        };
        
        self.cache.write().await.insert(address.to_string(), cached);
        
        Ok(result)
    }
    
    /// Get cached result
    pub async fn get_cached(&self, address: &str) -> Option<CachedResult> {
        self.cache.read().await.get(address).cloned()
    }
    
    /// Get queue size
    pub async fn queue_size(&self) -> usize {
        self.queue.read().await.len()
    }
    
    /// Get in-progress count
    pub async fn in_progress_count(&self) -> usize {
        self.in_progress.read().await.len()
    }
    
    /// Clone for worker (shares resources)
    fn clone_for_worker(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            cache: Arc::clone(&self.cache),
            in_progress: Arc::clone(&self.in_progress),
            eth_provider: Arc::clone(&self.eth_provider),
            semaphore: Arc::clone(&self.semaphore),
            cache_ttl: self.cache_ttl,
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_priority_queue() {
        let scanner = BatchScanner::new("https://eth.llamarpc.com", 10).await.unwrap();
        
        scanner.queue_scan("0xlow".to_string(), Priority::Low, None).await;
        scanner.queue_scan("0xhigh".to_string(), Priority::High, Some(1000000.0)).await;
        scanner.queue_scan("0xmedium".to_string(), Priority::Medium, None).await;
        
        assert_eq!(scanner.queue_size().await, 3);
        
        // High priority should be first
        let queue = scanner.queue.read().await;
        let next = queue.peek().unwrap();
        assert_eq!(next.priority, Priority::High);
    }
}
