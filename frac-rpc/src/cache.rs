use anyhow::Result;
use dashmap::DashMap;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::config::CacheConfig;
use crate::postgres_cache::PostgresCache;

/// 4-Tier Cache Architecture:
/// L1: In-memory (DashMap) - Ultra-fast, limited capacity (<1ms)
/// L2: Redis - Fast, distributed, recent blocks (<10ms)
/// L3: PostgreSQL - Historical blocks, large capacity (<100ms)
/// L4: Node direct - Fallback to actual Ethereum node (>100ms)
pub struct CacheLayer {
    // L1: In-memory cache (hot data)
    memory_cache: Arc<DashMap<String, CachedValue>>,
    
    // L2: Redis cache (distributed)
    redis: ConnectionManager,
    
    // L3: PostgreSQL cache (historical)
    postgres: Option<Arc<PostgresCache>>,
    
    config: CacheConfig,
}

#[derive(Clone, Debug)]
struct CachedValue {
    data: Value,
    expires_at: u64,
}

impl CacheLayer {
    pub async fn new(config: &CacheConfig) -> Result<Self> {
        let client = redis::Client::open(config.redis_url.as_str())?;
        let redis = ConnectionManager::new(client).await?;
        
        // Try to initialize PostgreSQL L3 cache (optional)
        let postgres = if let Ok(pg_url) = std::env::var("POSTGRES_URL") {
            match PostgresCache::new(&pg_url).await {
                Ok(pg) => {
                    debug!("PostgreSQL L3 cache initialized");
                    Some(Arc::new(pg))
                }
                Err(e) => {
                    warn!("Failed to initialize PostgreSQL cache: {}, continuing without L3", e);
                    None
                }
            }
        } else {
            debug!("POSTGRES_URL not set, skipping L3 cache");
            None
        };
        
        Ok(Self {
            memory_cache: Arc::new(DashMap::new()),
            redis,
            postgres,
            config: config.clone(),
        })
    }

    /// Get value from cache (L1 → L2 → miss)
    pub async fn get(&self, request: &Value) -> Result<Option<Value>> {
        let cache_key = self.generate_cache_key(request);

        // L1: Check memory cache
        if let Some(entry) = self.memory_cache.get(&cache_key) {
            if entry.expires_at > self.current_timestamp() {
                debug!("L1 cache hit: {}", cache_key);
                return Ok(Some(entry.data.clone()));
            } else {
                // Expired, remove it
                self.memory_cache.remove(&cache_key);
            }
        }

        // L2: Check Redis cache
        match self.redis.clone().get::<_, Option<String>>(&cache_key).await {
            Ok(Some(cached_json)) => {
                if let Ok(value) = serde_json::from_str::<Value>(&cached_json) {
                    debug!("L2 (Redis) cache hit: {}", cache_key);
                    
                    // Promote to L1 cache
                    self.memory_cache.insert(
                        cache_key.clone(),
                        CachedValue {
                            data: value.clone(),
                            expires_at: self.current_timestamp() + self.config.ttl_secs,
                        },
                    );
                    
                    return Ok(Some(value));
                }
            }
            Ok(None) => {
                debug!("L2 (Redis) cache miss: {}", cache_key);
            }
            Err(e) => {
                warn!("Redis error: {}", e);
            }
        }

        // L3: Check PostgreSQL cache (if available and for block-specific queries)
        if let Some(pg) = &self.postgres {
            if let Some(block_number) = self.extract_block_number(request) {
                match pg.get_block(block_number).await {
                    Ok(Some(block_data)) => {
                        debug!("L3 (PostgreSQL) cache hit for block: {}", block_number);
                        
                        // Promote to L1 and L2 caches
                        self.memory_cache.insert(
                            cache_key.clone(),
                            CachedValue {
                                data: block_data.clone(),
                                expires_at: self.current_timestamp() + self.config.ttl_secs,
                            },
                        );
                        
                        if let Ok(json_str) = serde_json::to_string(&block_data) {
                            let _ = self.redis.clone().set_ex::<_, _, ()>(
                                cache_key,
                                json_str,
                                self.config.ttl_secs,
                            ).await;
                        }
                        
                        return Ok(Some(block_data));
                    }
                    Ok(None) => {
                        debug!("L3 (PostgreSQL) cache miss for block: {}", block_number);
                    }
                    Err(e) => {
                        warn!("PostgreSQL cache error: {}", e);
                    }
                }
            }
        }

        Ok(None)
    }

    /// Set value in cache (L1 + L2)
    pub async fn set(&self, request: &Value, response: &Value) -> Result<()> {
        let cache_key = self.generate_cache_key(request);
        let expires_at = self.current_timestamp() + self.config.ttl_secs;

        // L1: Set in memory cache
        self.memory_cache.insert(
            cache_key.clone(),
            CachedValue {
                data: response.clone(),
                expires_at,
            },
        );

        // L2: Set in Redis with TTL
        let json_str = serde_json::to_string(response)?;
        
        // Optionally compress for Redis storage
        let stored_value = if self.config.enable_compression {
            self.compress(&json_str)?
        } else {
            json_str
        };

        let mut conn = self.redis.clone();
        let _: () = conn
            .set_ex(&cache_key, stored_value, self.config.ttl_secs)
            .await?;

        debug!("Cached: {}", cache_key);
        Ok(())
    }

    /// Invalidate cache entry
    pub async fn invalidate(&self, request: &Value) -> Result<()> {
        let cache_key = self.generate_cache_key(request);
        
        // Remove from L1
        self.memory_cache.remove(&cache_key);
        
        // Remove from L2
        let mut conn = self.redis.clone();
        let _: () = conn.del(&cache_key).await?;
        
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let memory_entries = self.memory_cache.len();
        
        // Get Redis info
        let redis_info = self.get_redis_info().await.unwrap_or_default();
        
        CacheStats {
            l1_entries: memory_entries,
            l2_entries: redis_info.keys,
            memory_usage_mb: redis_info.memory_mb,
        }
    }

    /// Cleanup expired entries from L1 cache
    pub async fn cleanup_expired(&self) {
        let now = self.current_timestamp();
        self.memory_cache.retain(|_, v| v.expires_at > now);
    }

    fn generate_cache_key(&self, request: &Value) -> String {
        // Create a deterministic cache key from the request
        // Include method and params
        let method = request["method"].as_str().unwrap_or("");
        let params = request["params"].to_string();
        format!("frac:rpc:{}:{}", method, Self::hash_params(&params))
    }

    fn hash_params(params: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        params.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn compress(&self, data: &str) -> Result<String> {
        // Simple compression using base64 encoding (replace with actual compression if needed)
        Ok(base64::encode(data))
    }

    async fn get_redis_info(&self) -> Result<RedisInfo> {
        let mut conn = self.redis.clone();
        let info: String = redis::cmd("INFO")
            .query_async(&mut conn)
            .await?;
        
        // Parse Redis INFO output (simplified)
        Ok(RedisInfo {
            keys: 0, // Would parse from INFO
            memory_mb: 0, // Would parse from INFO
        })
    }

    /// Extract block number from RPC request (for PostgreSQL caching)
    fn extract_block_number(&self, request: &Value) -> Option<u64> {
        let method = request["method"].as_str()?;
        let params = request["params"].as_array()?;

        match method {
            "eth_getBlockByNumber" | "eth_getBlockTransactionCountByNumber" => {
                if let Some(block_param) = params.get(0).and_then(|v| v.as_str()) {
                    // Parse hex block number
                    if block_param.starts_with("0x") {
                        return u64::from_str_radix(&block_param[2..], 16).ok();
                    }
                    // Parse decimal block number
                    return block_param.parse::<u64>().ok();
                }
            }
            _ => {}
        }

        None
    }
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub l1_entries: usize,
    pub l2_entries: usize,
    pub memory_usage_mb: usize,
}

#[derive(Debug, Default)]
struct RedisInfo {
    keys: usize,
    memory_mb: usize,
}
