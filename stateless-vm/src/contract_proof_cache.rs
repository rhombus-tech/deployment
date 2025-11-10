// Contract Proof Cache - Production-Grade Implementation
//
// Caches expensive PCC analysis results and proving keys per contract bytecode.
// This enables <100ms proving for already-analyzed contracts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use ethereum_types::H256;
use sha3::{Digest, Keccak256};
use serde::{Serialize, Deserialize};

#[cfg(feature = "evm-verify")]
use ark_bn254::Bn254;
#[cfg(feature = "evm-verify")]
use ark_groth16::{ProvingKey, VerifyingKey};

use crate::errors::{VMError, Result};

/// Maximum cache size (number of contracts)
const DEFAULT_MAX_CACHE_SIZE: usize = 10_000;

/// Cache entry TTL in seconds (24 hours)
const DEFAULT_CACHE_TTL_SECONDS: u64 = 86_400;

/// LRU eviction threshold (evict when cache is this full)
const LRU_EVICTION_THRESHOLD: f64 = 0.95;

/// Global contract proof cache with LRU eviction
pub struct ContractProofCache {
    /// Main cache storage
    cache: Arc<RwLock<HashMap<H256, CachedContractProof>>>,
    
    /// Maximum number of cached contracts
    max_size: usize,
    
    /// Time-to-live for cache entries (seconds)
    ttl_seconds: u64,
    
    /// Cache statistics
    stats: Arc<RwLock<CacheStatistics>>,
    
    /// Enable disk persistence
    enable_persistence: bool,
    
    /// Persistence directory
    persistence_dir: Option<std::path::PathBuf>,
}

/// Cached contract analysis result with proving keys
#[derive(Clone)]
pub struct CachedContractProof {
    /// Bytecode hash (cache key)
    pub bytecode_hash: H256,
    
    /// Is the contract safe?
    pub is_safe: bool,
    
    /// Number of vulnerabilities detected
    pub vulnerability_count: usize,
    
    /// Proving key (expensive to generate - ~100ms)
    #[cfg(feature = "evm-verify")]
    pub proving_key: Arc<ProvingKey<Bn254>>,
    
    /// Verifying key (for on-chain verification)
    #[cfg(feature = "evm-verify")]
    pub verifying_key: Arc<VerifyingKey<Bn254>>,
    
    /// Placeholder when evm-verify not enabled
    #[cfg(not(feature = "evm-verify"))]
    pub proving_key: Arc<Vec<u8>>,
    
    #[cfg(not(feature = "evm-verify"))]
    pub verifying_key: Arc<Vec<u8>>,
    
    /// Critical vulnerability types found (for quick rejection)
    pub critical_issues: Vec<VulnerabilityType>,
    
    /// When this entry was created
    pub analyzed_at: u64,
    
    /// Last access timestamp (for LRU eviction)
    pub last_accessed: u64,
    
    /// Number of times this entry was accessed
    pub access_count: u64,
    
    /// Original bytecode size (for metrics)
    pub bytecode_size: usize,
    
    /// Analysis duration in milliseconds
    pub analysis_duration_ms: u64,
}

/// Types of critical vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityType {
    Reentrancy,
    PrivilegeEscalation,
    IntegerOverflow,
    UncheckedCall,
    AccessControl,
    FlashLoan,
    PriceManipulation,
    MEVVulnerability,
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct CacheStatistics {
    /// Total cache hits
    pub hits: u64,
    
    /// Total cache misses
    pub misses: u64,
    
    /// Total entries evicted
    pub evictions: u64,
    
    /// Total analysis time saved (ms)
    pub time_saved_ms: u64,
    
    /// Current cache size
    pub current_size: usize,
    
    /// Total contracts analyzed
    pub total_analyzed: u64,
    
    /// Total unsafe contracts found
    pub unsafe_contracts: u64,
}

impl ContractProofCache {
    /// Create a new contract proof cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            ttl_seconds: DEFAULT_CACHE_TTL_SECONDS,
            stats: Arc::new(RwLock::new(CacheStatistics::default())),
            enable_persistence: false,
            persistence_dir: None,
        }
    }
    
    /// Create with default settings
    pub fn default() -> Self {
        Self::new(DEFAULT_MAX_CACHE_SIZE)
    }
    
    /// Enable disk persistence for cache
    pub fn with_persistence(mut self, dir: std::path::PathBuf) -> Self {
        self.enable_persistence = true;
        self.persistence_dir = Some(dir);
        self
    }
    
    /// Set custom TTL
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }
    
    /// Get contract proof from cache (fast path)
    pub fn get(&self, bytecode_hash: &H256) -> Option<CachedContractProof> {
        let now = current_timestamp();
        let mut cache = self.cache.write();
        
        if let Some(cached) = cache.get_mut(bytecode_hash) {
            // Check TTL
            if now - cached.analyzed_at > self.ttl_seconds {
                // Expired - remove and return None
                cache.remove(bytecode_hash);
                
                let mut stats = self.stats.write();
                stats.misses += 1;
                stats.current_size = cache.len();
                
                return None;
            }
            
            // Update LRU tracking
            cached.last_accessed = now;
            cached.access_count += 1;
            
            // Update stats
            let mut stats = self.stats.write();
            stats.hits += 1;
            stats.time_saved_ms += cached.analysis_duration_ms;
            
            tracing::debug!(
                "Cache HIT for contract {:?} (accessed {} times, saved {}ms)",
                bytecode_hash,
                cached.access_count,
                cached.analysis_duration_ms
            );
            
            return Some(cached.clone());
        }
        
        // Cache miss
        let mut stats = self.stats.write();
        stats.misses += 1;
        
        tracing::debug!("Cache MISS for contract {:?}", bytecode_hash);
        
        None
    }
    
    /// Insert contract proof into cache
    pub fn insert(&self, proof: CachedContractProof) -> Result<()> {
        let mut cache = self.cache.write();
        
        // Check if we need to evict
        if cache.len() >= self.max_size {
            self.evict_lru(&mut cache)?;
        }
        
        // Update statistics
        let mut stats = self.stats.write();
        stats.total_analyzed += 1;
        stats.current_size = cache.len() + 1;
        
        if !proof.is_safe {
            stats.unsafe_contracts += 1;
        }
        
        tracing::info!(
            "Cached contract {:?} (safe: {}, vulns: {}, analysis: {}ms)",
            proof.bytecode_hash,
            proof.is_safe,
            proof.vulnerability_count,
            proof.analysis_duration_ms
        );
        
        // Persist to disk if enabled
        if self.enable_persistence {
            if let Err(e) = self.persist_to_disk(&proof) {
                tracing::warn!("Failed to persist cache entry: {}", e);
            }
        }
        
        cache.insert(proof.bytecode_hash, proof);
        
        Ok(())
    }
    
    /// Evict least recently used entries
    fn evict_lru(&self, cache: &mut HashMap<H256, CachedContractProof>) -> Result<()> {
        // Calculate how many to evict (evict 10% when threshold hit)
        let evict_count = (self.max_size as f64 * 0.1) as usize;
        
        // Find LRU entries
        let mut entries: Vec<_> = cache.iter()
            .map(|(hash, proof)| (*hash, proof.last_accessed, proof.access_count))
            .collect();
        
        // Sort by last_accessed (oldest first), then by access_count (least accessed first)
        entries.sort_by_key(|(_, last_accessed, access_count)| (*last_accessed, *access_count));
        
        // Evict the oldest/least used
        let to_evict: Vec<H256> = entries.iter()
            .take(evict_count)
            .map(|(hash, _, _)| *hash)
            .collect();
        
        tracing::info!(
            "Evicting {} LRU entries (cache size: {}/{})",
            to_evict.len(),
            cache.len(),
            self.max_size
        );
        
        for hash in to_evict {
            cache.remove(&hash);
            
            // Update stats
            let mut stats = self.stats.write();
            stats.evictions += 1;
        }
        
        Ok(())
    }
    
    /// Check if contract is already cached
    pub fn contains(&self, bytecode_hash: &H256) -> bool {
        let cache = self.cache.read();
        cache.contains_key(bytecode_hash)
    }
    
    /// Clear entire cache
    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();
        
        let mut stats = self.stats.write();
        stats.current_size = 0;
        
        tracing::info!("Cache cleared");
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> CacheStatistics {
        self.stats.read().clone()
    }
    
    /// Get cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let stats = self.stats.read();
        let total = stats.hits + stats.misses;
        if total == 0 {
            0.0
        } else {
            stats.hits as f64 / total as f64
        }
    }
    
    /// Persist cache entry to disk (optional)
    fn persist_to_disk(&self, _proof: &CachedContractProof) -> Result<()> {
        // TODO: Implement disk persistence
        // For now, just return Ok
        // In production, serialize to disk for crash recovery
        Ok(())
    }
    
    /// Load cache from disk (optional)
    pub fn load_from_disk(&self) -> Result<usize> {
        // TODO: Implement disk loading
        // For now, return 0
        Ok(0)
    }
    
    /// Print cache statistics summary
    pub fn print_stats(&self) {
        let stats = self.stats.read();
        let hit_rate = if stats.hits + stats.misses > 0 {
            (stats.hits as f64 / (stats.hits + stats.misses) as f64) * 100.0
        } else {
            0.0
        };
        
        println!("\n╔═══════════════════════════════════════════════════════╗");
        println!("║           CONTRACT PROOF CACHE STATISTICS            ║");
        println!("╠═══════════════════════════════════════════════════════╣");
        println!("║ Cache Size: {}/{:<40} ║", stats.current_size, self.max_size);
        println!("║ Hit Rate: {:.2}%{:<43} ║", hit_rate, "");
        println!("║ Hits: {:<47} ║", stats.hits);
        println!("║ Misses: {:<45} ║", stats.misses);
        println!("║ Evictions: {:<42} ║", stats.evictions);
        println!("║ Total Analyzed: {:<37} ║", stats.total_analyzed);
        println!("║ Unsafe Contracts: {:<35} ║", stats.unsafe_contracts);
        println!("║ Time Saved: {:.2}s{:<37} ║", stats.time_saved_ms as f64 / 1000.0, "");
        println!("╚═══════════════════════════════════════════════════════╝\n");
    }
}

impl CachedContractProof {
    /// Check if entry is expired
    pub fn is_expired(&self, ttl_seconds: u64) -> bool {
        let now = current_timestamp();
        now - self.analyzed_at > ttl_seconds
    }
    
    /// Has critical vulnerabilities
    pub fn has_critical_vulnerabilities(&self) -> bool {
        !self.critical_issues.is_empty()
    }
}

/// Hash bytecode to get cache key
pub fn hash_bytecode(bytecode: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(bytecode);
    H256::from_slice(&hasher.finalize()[..])
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_creation() {
        let cache = ContractProofCache::new(100);
        assert_eq!(cache.max_size, 100);
        assert_eq!(cache.ttl_seconds, DEFAULT_CACHE_TTL_SECONDS);
    }
    
    #[test]
    fn test_cache_miss() {
        let cache = ContractProofCache::new(100);
        let hash = H256::random();
        assert!(cache.get(&hash).is_none());
        
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }
    
    #[test]
    fn test_bytecode_hashing() {
        let bytecode1 = vec![0x60, 0x80, 0x60, 0x40];
        let bytecode2 = vec![0x60, 0x80, 0x60, 0x40];
        let bytecode3 = vec![0x60, 0x80, 0x60, 0x41];
        
        let hash1 = hash_bytecode(&bytecode1);
        let hash2 = hash_bytecode(&bytecode2);
        let hash3 = hash_bytecode(&bytecode3);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_hit_rate_calculation() {
        let cache = ContractProofCache::new(100);
        
        // All misses
        for _ in 0..10 {
            cache.get(&H256::random());
        }
        assert_eq!(cache.hit_rate(), 0.0);
    }
    
    #[test]
    fn test_cache_statistics() {
        let cache = ContractProofCache::new(100);
        let stats = cache.stats();
        
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.current_size, 0);
    }
}
