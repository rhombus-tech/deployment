// evm-verify/src/middleware/rate_limiter.rs

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::time::{interval, sleep};
use tracing::{debug, warn, error};
use warp::{Filter, Rejection, Reply};
use serde::{Deserialize, Serialize};

/// Rate limiting configuration for different endpoint types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Critical endpoints (proving, analysis)
    pub critical_endpoints: EndpointLimits,
    
    /// Public endpoints (status, health)
    pub public_endpoints: EndpointLimits,
    
    /// Demo endpoints  
    pub demo_endpoints: EndpointLimits,
    
    /// Global limits per IP
    pub global_limits: EndpointLimits,
    
    /// Enable adaptive rate limiting
    pub adaptive_enabled: bool,
    
    /// Cleanup interval for expired entries
    pub cleanup_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointLimits {
    /// Requests per minute
    pub requests_per_minute: u32,
    
    /// Burst limit (short-term spikes)
    pub burst_limit: u32,
    
    /// Concurrent requests per IP
    pub concurrent_limit: u32,
    
    /// Request size limit in bytes
    pub max_request_size: u64,
}

/// Rate limiting bucket for token bucket algorithm
#[derive(Debug, Clone)]
struct RateLimitBucket {
    tokens: u32,
    last_refill: Instant,
    requests_this_minute: u32,
    minute_start: Instant,
    concurrent_requests: u32,
}

/// Advanced rate limiter with multiple algorithms
pub struct AdvancedRateLimiter {
    config: RateLimitConfig,
    buckets: Arc<RwLock<HashMap<String, RateLimitBucket>>>,
    blocked_ips: Arc<RwLock<HashMap<IpAddr, Instant>>>,
    suspicious_patterns: Arc<RwLock<HashMap<IpAddr, SuspiciousActivity>>>,
}

#[derive(Debug, Clone)]
struct SuspiciousActivity {
    rapid_requests: u32,
    different_user_agents: u32,
    last_activity: Instant,
    blocked_until: Option<Instant>,
}

/// Rate limiting error types
#[derive(Debug)]
pub enum RateLimitError {
    TooManyRequests,
    ConcurrentLimitExceeded,
    RequestTooLarge,
    SuspiciousActivity,
    IPBlocked,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            critical_endpoints: EndpointLimits {
                requests_per_minute: 50,    // Conservative for proving
                burst_limit: 10,
                concurrent_limit: 5,
                max_request_size: 1024 * 1024, // 1MB
            },
            public_endpoints: EndpointLimits {
                requests_per_minute: 200,
                burst_limit: 50,
                concurrent_limit: 20,
                max_request_size: 64 * 1024, // 64KB
            },
            demo_endpoints: EndpointLimits {
                requests_per_minute: 30,
                burst_limit: 10,
                concurrent_limit: 3,
                max_request_size: 512 * 1024, // 512KB
            },
            global_limits: EndpointLimits {
                requests_per_minute: 300,
                burst_limit: 100,
                concurrent_limit: 50,
                max_request_size: 2 * 1024 * 1024, // 2MB
            },
            adaptive_enabled: true,
            cleanup_interval_seconds: 300, // 5 minutes
        }
    }
}

impl AdvancedRateLimiter {
    /// Create new rate limiter with configuration
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = Self {
            config,
            buckets: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            suspicious_patterns: Arc::new(RwLock::new(HashMap::new())),
        };

        // Start background cleanup task
        limiter.start_cleanup_task();
        
        limiter
    }

    /// Check if request is allowed for specific endpoint type
    pub async fn check_request(
        &self,
        ip: IpAddr,
        endpoint_type: &str,
        user_agent: Option<&str>,
        request_size: u64,
    ) -> Result<(), RateLimitError> {
        // Check if IP is blocked
        if self.is_ip_blocked(ip).await {
            return Err(RateLimitError::IPBlocked);
        }

        // Check for suspicious patterns
        if self.detect_suspicious_activity(ip, user_agent).await {
            return Err(RateLimitError::SuspiciousActivity);
        }

        // Get endpoint limits
        let limits = self.get_endpoint_limits(endpoint_type);
        
        // Check request size
        if request_size > limits.max_request_size {
            return Err(RateLimitError::RequestTooLarge);
        }

        // Check rate limits
        let bucket_key = format!("{}:{}", ip, endpoint_type);
        
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.entry(bucket_key).or_insert_with(|| RateLimitBucket {
            tokens: limits.burst_limit,
            last_refill: Instant::now(),
            requests_this_minute: 0,
            minute_start: Instant::now(),
            concurrent_requests: 0,
        });

        // Refill tokens (token bucket algorithm)
        self.refill_bucket(bucket, &limits);

        // Check concurrent requests
        if bucket.concurrent_requests >= limits.concurrent_limit {
            return Err(RateLimitError::ConcurrentLimitExceeded);
        }

        // Check rate limit
        if bucket.tokens == 0 || bucket.requests_this_minute >= limits.requests_per_minute {
            warn!("Rate limit exceeded for IP {} on endpoint {}", ip, endpoint_type);
            return Err(RateLimitError::TooManyRequests);
        }

        // Consume token and increment counters
        bucket.tokens -= 1;
        bucket.requests_this_minute += 1;
        bucket.concurrent_requests += 1;

        debug!("Rate limit check passed for IP {} on endpoint {}", ip, endpoint_type);
        Ok(())
    }

    /// Mark request as completed (decrease concurrent counter)
    pub async fn complete_request(&self, ip: IpAddr, endpoint_type: &str) {
        let bucket_key = format!("{}:{}", ip, endpoint_type);
        
        if let Ok(mut buckets) = self.buckets.write() {
            if let Some(bucket) = buckets.get_mut(&bucket_key) {
                bucket.concurrent_requests = bucket.concurrent_requests.saturating_sub(1);
            }
        }
    }

    /// Get endpoint limits based on type
    fn get_endpoint_limits(&self, endpoint_type: &str) -> &EndpointLimits {
        match endpoint_type {
            "critical" => &self.config.critical_endpoints,
            "demo" => &self.config.demo_endpoints,
            "public" => &self.config.public_endpoints,
            _ => &self.config.global_limits,
        }
    }

    /// Refill token bucket based on time elapsed
    fn refill_bucket(&self, bucket: &mut RateLimitBucket, limits: &EndpointLimits) {
        let now = Instant::now();
        
        // Reset minute counter if needed
        if now.duration_since(bucket.minute_start) >= Duration::from_secs(60) {
            bucket.requests_this_minute = 0;
            bucket.minute_start = now;
        }

        // Refill tokens based on time elapsed
        let time_since_refill = now.duration_since(bucket.last_refill);
        let tokens_to_add = (time_since_refill.as_secs() as u32 * limits.requests_per_minute) / 60;
        
        if tokens_to_add > 0 {
            bucket.tokens = (bucket.tokens + tokens_to_add).min(limits.burst_limit);
            bucket.last_refill = now;
        }
    }

    /// Check if IP is currently blocked
    async fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        if let Ok(blocked_ips) = self.blocked_ips.read() {
            if let Some(blocked_until) = blocked_ips.get(&ip) {
                return Instant::now() < *blocked_until;
            }
        }
        false
    }

    /// Detect suspicious activity patterns
    async fn detect_suspicious_activity(&self, ip: IpAddr, user_agent: Option<&str>) -> bool {
        if !self.config.adaptive_enabled {
            return false;
        }

        let mut suspicious = self.suspicious_patterns.write().unwrap();
        let activity = suspicious.entry(ip).or_insert_with(|| SuspiciousActivity {
            rapid_requests: 0,
            different_user_agents: 0,
            last_activity: Instant::now(),
            blocked_until: None,
        });

        let now = Instant::now();
        
        // Check if still blocked
        if let Some(blocked_until) = activity.blocked_until {
            if now < blocked_until {
                return true;
            } else {
                activity.blocked_until = None;
            }
        }

        // Reset counters if enough time has passed
        if now.duration_since(activity.last_activity) > Duration::from_secs(60) {
            activity.rapid_requests = 0;
            activity.different_user_agents = 0;
        }

        // Increment rapid request counter
        if now.duration_since(activity.last_activity) < Duration::from_millis(100) {
            activity.rapid_requests += 1;
        }

        // Check user agent variation (bot detection)
        if let Some(ua) = user_agent {
            if ua.is_empty() || ua.contains("bot") || ua.contains("crawler") {
                activity.different_user_agents += 1;
            }
        }

        activity.last_activity = now;

        // Block if suspicious patterns detected
        let is_suspicious = activity.rapid_requests > 20 || activity.different_user_agents > 5;
        
        if is_suspicious {
            warn!("Suspicious activity detected for IP {}: rapid_requests={}, different_user_agents={}", 
                  ip, activity.rapid_requests, activity.different_user_agents);
            
            // Block for 10 minutes
            activity.blocked_until = Some(now + Duration::from_secs(600));
        }

        is_suspicious
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(&self) {
        let buckets = Arc::clone(&self.buckets);
        let blocked_ips = Arc::clone(&self.blocked_ips);
        let suspicious_patterns = Arc::clone(&self.suspicious_patterns);
        let cleanup_interval = self.config.cleanup_interval_seconds;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(cleanup_interval));
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                
                // Clean up expired buckets
                if let Ok(mut buckets) = buckets.write() {
                    buckets.retain(|_, bucket| {
                        now.duration_since(bucket.last_refill) < Duration::from_secs(300)
                    });
                }
                
                // Clean up expired blocked IPs
                if let Ok(mut blocked) = blocked_ips.write() {
                    blocked.retain(|_, blocked_until| now < *blocked_until);
                }
                
                // Clean up old suspicious activity
                if let Ok(mut suspicious) = suspicious_patterns.write() {
                    suspicious.retain(|_, activity| {
                        now.duration_since(activity.last_activity) < Duration::from_secs(3600)
                    });
                }
                
                debug!("Rate limiter cleanup completed");
            }
        });
    }

    /// Get comprehensive status summary for monitoring
    pub async fn get_status_summary(&self) -> serde_json::Value {
        let buckets = self.buckets.read().unwrap();
        let blocked_ips = self.blocked_ips.read().unwrap();
        let suspicious = self.suspicious_patterns.read().unwrap();
        
        let now = Instant::now();
        let active_buckets = buckets.len();
        let blocked_count = blocked_ips.iter()
            .filter(|(_, blocked_until)| now < **blocked_until)
            .count();
        let suspicious_count = suspicious.len();
        
        // Calculate total request counts from all buckets
        let total_requests: u64 = buckets.values()
            .map(|bucket| bucket.requests_this_minute as u64)
            .sum();
        
        serde_json::json!({
            "status": "active",
            "active_buckets": active_buckets,
            "blocked_ips": blocked_count,
            "suspicious_ips": suspicious_count,
            "total_requests_served": total_requests,
            "config": {
                "public_endpoints": {
                    "requests_per_minute": self.config.public_endpoints.requests_per_minute,
                    "burst_limit": self.config.public_endpoints.burst_limit,
                    "concurrent_limit": self.config.public_endpoints.concurrent_limit,
                    "max_request_size": self.config.public_endpoints.max_request_size
                },
                "critical_endpoints": {
                    "requests_per_minute": self.config.critical_endpoints.requests_per_minute,
                    "burst_limit": self.config.critical_endpoints.burst_limit,
                    "concurrent_limit": self.config.critical_endpoints.concurrent_limit,
                    "max_request_size": self.config.critical_endpoints.max_request_size
                },
                "global_limits": {
                    "requests_per_minute": self.config.global_limits.requests_per_minute,
                    "burst_limit": self.config.global_limits.burst_limit,
                    "concurrent_limit": self.config.global_limits.concurrent_limit,
                    "max_request_size": self.config.global_limits.max_request_size
                },
                "adaptive_enabled": self.config.adaptive_enabled,
                "cleanup_interval_seconds": self.config.cleanup_interval_seconds
            },
            "timestamp": chrono::Utc::now().to_rfc3339()
        })
    }

    /// Create Warp filter for rate limiting
    pub fn warp_filter(
        self: Arc<Self>,
        endpoint_type: &'static str,
    ) -> impl Filter<Extract = (), Error = Rejection> + Clone {
        warp::addr::remote()
            .and(warp::header::optional::<String>("user-agent"))
            .and(warp::header::optional::<u64>("content-length"))
            .and_then(move |addr: Option<std::net::SocketAddr>, user_agent: Option<String>, content_length: Option<u64>| {
                let limiter = Arc::clone(&self);
                async move {
                    let ip = addr.map(|a| a.ip()).unwrap_or(IpAddr::from([127, 0, 0, 1]));
                    let size = content_length.unwrap_or(0);
                    let ua = user_agent.as_deref();
                    
                    match limiter.check_request(ip, endpoint_type, ua, size).await {
                        Ok(()) => Ok(()),
                        Err(RateLimitError::TooManyRequests) => {
                            Err(warp::reject::custom(RateLimitRejection::TooManyRequests))
                        }
                        Err(RateLimitError::SuspiciousActivity) => {
                            Err(warp::reject::custom(RateLimitRejection::SuspiciousActivity))
                        }
                        Err(RateLimitError::IPBlocked) => {
                            Err(warp::reject::custom(RateLimitRejection::IPBlocked))
                        }
                        Err(RateLimitError::ConcurrentLimitExceeded) => {
                            Err(warp::reject::custom(RateLimitRejection::ConcurrentLimitExceeded))
                        }
                        Err(RateLimitError::RequestTooLarge) => {
                            Err(warp::reject::custom(RateLimitRejection::RequestTooLarge))
                        }
                    }
                }
            })
            .untuple_one()
    }
}

/// Custom rejection types for rate limiting
#[derive(Debug)]
pub enum RateLimitRejection {
    TooManyRequests,
    SuspiciousActivity,
    IPBlocked,
    ConcurrentLimitExceeded,
    RequestTooLarge,
}

impl warp::reject::Reject for RateLimitRejection {}

/// Handle rate limit rejections
pub async fn handle_rate_limit_rejection(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    if let Some(rate_limit_err) = err.find::<RateLimitRejection>() {
        let (code, message) = match rate_limit_err {
            RateLimitRejection::TooManyRequests => (429, "Too Many Requests"),
            RateLimitRejection::SuspiciousActivity => (403, "Suspicious Activity Detected"),
            RateLimitRejection::IPBlocked => (403, "IP Address Blocked"),
            RateLimitRejection::ConcurrentLimitExceeded => (429, "Too Many Concurrent Requests"),
            RateLimitRejection::RequestTooLarge => (413, "Request Too Large"),
        };
        
        error!("Rate limit rejection: {}", message);
        
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": message,
                "code": code
            })),
            warp::http::StatusCode::from_u16(code).unwrap()
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": "Internal Server Error"
            })),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = RateLimitConfig::default();
        let limiter = AdvancedRateLimiter::new(config);
        let ip = IpAddr::from([127, 0, 0, 1]);

        // First request should pass
        assert!(limiter.check_request(ip, "critical", Some("test-agent"), 1024).await.is_ok());
        
        // Rapid requests should eventually be blocked
        for _ in 0..100 {
            let _ = limiter.check_request(ip, "critical", Some("test-agent"), 1024).await;
        }
        
        // Should be rate limited now
        assert!(limiter.check_request(ip, "critical", Some("test-agent"), 1024).await.is_err());
    }

    #[tokio::test]
    async fn test_suspicious_activity_detection() {
        let config = RateLimitConfig::default();
        let limiter = AdvancedRateLimiter::new(config);
        let ip = IpAddr::from([127, 0, 0, 1]);

        // Simulate bot behavior
        for _ in 0..25 {
            let _ = limiter.check_request(ip, "public", Some("bot-crawler"), 1024).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        // Should detect suspicious activity
        assert!(limiter.check_request(ip, "public", Some("bot-crawler"), 1024).await.is_err());
    }
}
