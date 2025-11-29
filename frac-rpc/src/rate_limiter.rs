// Rate Limiting & DDoS Protection
// Uses token bucket algorithm for fair rate limiting

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

const DEFAULT_RATE_LIMIT: u32 = 100; // requests per window
const DEFAULT_WINDOW_SECS: u64 = 60; // 1 minute window
const BURST_LIMIT: u32 = 20; // allow short bursts

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<DashMap<IpAddr, TokenBucket>>,
    requests_per_window: u32,
    window_duration: Duration,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    total_requests: u64,
}

impl RateLimiter {
    pub fn new(requests_per_window: Option<u32>, window_secs: Option<u64>) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            requests_per_window: requests_per_window.unwrap_or(DEFAULT_RATE_LIMIT),
            window_duration: Duration::from_secs(window_secs.unwrap_or(DEFAULT_WINDOW_SECS)),
        }
    }

    /// Check if request is allowed for given IP
    /// Returns Ok(()) if allowed, Err with retry-after duration if blocked
    pub fn check_rate_limit(&self, ip: IpAddr) -> Result<()> {
        let mut bucket = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.requests_per_window as f64,
            last_refill: Instant::now(),
            total_requests: 0,
        });

        // Refill tokens based on time elapsed
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill);
        let refill_rate = self.requests_per_window as f64 / self.window_duration.as_secs_f64();
        let tokens_to_add = elapsed.as_secs_f64() * refill_rate;
        
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.requests_per_window as f64 + BURST_LIMIT as f64);
        bucket.last_refill = now;
        bucket.total_requests += 1;

        // Check if we have tokens available
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate retry-after time
            let tokens_needed = 1.0 - bucket.tokens;
            let retry_after = Duration::from_secs_f64(tokens_needed / refill_rate);
            
            warn!(
                "Rate limit exceeded for IP: {}, total_requests: {}, retry_after: {:?}",
                ip, bucket.total_requests, retry_after
            );
            
            Err(anyhow!(
                "Rate limit exceeded. Retry after {} seconds",
                retry_after.as_secs()
            ))
        }
    }

    /// Get stats for an IP
    pub fn get_ip_stats(&self, ip: IpAddr) -> Option<IpStats> {
        self.buckets.get(&ip).map(|bucket| IpStats {
            ip,
            available_tokens: bucket.tokens,
            total_requests: bucket.total_requests,
            last_request: bucket.last_refill,
        })
    }

    /// Get all rate limiter stats
    pub fn get_stats(&self) -> RateLimiterStats {
        let total_ips = self.buckets.len();
        let mut blocked_ips = 0;
        let mut total_requests = 0;

        for entry in self.buckets.iter() {
            total_requests += entry.total_requests;
            if entry.tokens < 1.0 {
                blocked_ips += 1;
            }
        }

        RateLimiterStats {
            total_ips: total_ips as u64,
            blocked_ips: blocked_ips as u64,
            total_requests,
            requests_per_window: self.requests_per_window,
            window_seconds: self.window_duration.as_secs(),
        }
    }

    /// Cleanup old entries (run periodically)
    pub fn cleanup_old_entries(&self, max_age: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < max_age
        });
    }
}

#[derive(Debug, Clone)]
pub struct IpStats {
    pub ip: IpAddr,
    pub available_tokens: f64,
    pub total_requests: u64,
    pub last_request: Instant,
}

#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub total_ips: u64,
    pub blocked_ips: u64,
    pub total_requests: u64,
    pub requests_per_window: u32,
    pub window_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(Some(10), Some(60));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 10 requests should succeed
        for _ in 0..10 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(Some(5), Some(60));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 5 should succeed
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }

        // 6th should fail
        assert!(limiter.check_rate_limit(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_refills() {
        let limiter = RateLimiter::new(Some(5), Some(1)); // 5 per second
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Use up tokens
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }

        // Should be blocked
        assert!(limiter.check_rate_limit(ip).is_err());

        // Wait for refill
        sleep(Duration::from_millis(500));

        // Should have ~2.5 tokens, so next request succeeds
        assert!(limiter.check_rate_limit(ip).is_ok());
    }

    #[test]
    fn test_rate_limiter_stats() {
        let limiter = RateLimiter::new(Some(10), Some(60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        limiter.check_rate_limit(ip1).ok();
        limiter.check_rate_limit(ip2).ok();

        let stats = limiter.get_stats();
        assert_eq!(stats.total_ips, 2);
        assert_eq!(stats.total_requests, 2);
    }
}
