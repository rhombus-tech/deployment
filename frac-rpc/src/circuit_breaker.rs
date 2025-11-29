// Circuit Breaker for Error Recovery and Resilience
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(30);
const DEFAULT_SUCCESS_THRESHOLD: u32 = 2;

#[derive(Clone, Debug, PartialEq)]
pub enum CircuitState {
    Closed,     // Normal operation
    Open,       // Failing, rejecting requests
    HalfOpen,   // Testing recovery
}

#[derive(Clone)]
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitBreakerState>>,
    config: CircuitBreakerConfig,
}

#[derive(Clone)]
struct CircuitBreakerConfig {
    failure_threshold: u32,
    timeout_duration: Duration,
    success_threshold: u32,
}

struct CircuitBreakerState {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

impl CircuitBreaker {
    pub fn new(
        failure_threshold: Option<u32>,
        timeout_secs: Option<u64>,
        success_threshold: Option<u32>,
    ) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitBreakerState {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
                last_state_change: Instant::now(),
            })),
            config: CircuitBreakerConfig {
                failure_threshold: failure_threshold.unwrap_or(DEFAULT_FAILURE_THRESHOLD),
                timeout_duration: Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_TIMEOUT_DURATION.as_secs())),
                success_threshold: success_threshold.unwrap_or(DEFAULT_SUCCESS_THRESHOLD),
            },
        }
    }

    /// Check if request should be allowed
    pub async fn allow_request(&self) -> Result<()> {
        let mut state = self.state.write().await;

        match state.state {
            CircuitState::Closed => {
                // Normal operation, allow request
                Ok(())
            }
            CircuitState::Open => {
                // Check if timeout has elapsed
                if let Some(last_failure) = state.last_failure_time {
                    if last_failure.elapsed() >= self.config.timeout_duration {
                        // Move to HalfOpen to test recovery
                        debug!("Circuit breaker moving to HalfOpen state");
                        state.state = CircuitState::HalfOpen;
                        state.success_count = 0;
                        state.last_state_change = Instant::now();
                        Ok(())
                    } else {
                        // Still in timeout period
                        Err(anyhow::anyhow!("Circuit breaker is OPEN"))
                    }
                } else {
                    Ok(())
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests to test recovery
                Ok(())
            }
        }
    }

    /// Record successful request
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;

        match state.state {
            CircuitState::Closed => {
                // Reset failure count on success
                state.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                state.success_count += 1;
                if state.success_count >= self.config.success_threshold {
                    // Recovery successful, close circuit
                    debug!("Circuit breaker recovered, moving to Closed state");
                    state.state = CircuitState::Closed;
                    state.failure_count = 0;
                    state.success_count = 0;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset if it does
                state.state = CircuitState::Closed;
                state.failure_count = 0;
                state.last_state_change = Instant::now();
            }
        }
    }

    /// Record failed request
    pub async fn record_failure(&self) {
        let mut state = self.state.write().await;

        match state.state {
            CircuitState::Closed => {
                state.failure_count += 1;
                state.last_failure_time = Some(Instant::now());

                if state.failure_count >= self.config.failure_threshold {
                    // Too many failures, open circuit
                    warn!(
                        "Circuit breaker opening after {} failures",
                        state.failure_count
                    );
                    state.state = CircuitState::Open;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                // Failed during recovery, reopen circuit
                warn!("Circuit breaker reopening after failed recovery attempt");
                state.state = CircuitState::Open;
                state.failure_count = 1;
                state.success_count = 0;
                state.last_failure_time = Some(Instant::now());
                state.last_state_change = Instant::now();
            }
            CircuitState::Open => {
                // Already open, just update failure time
                state.last_failure_time = Some(Instant::now());
            }
        }
    }

    /// Get current state
    pub async fn get_state(&self) -> CircuitState {
        self.state.read().await.state.clone()
    }

    /// Get stats
    pub async fn get_stats(&self) -> CircuitBreakerStats {
        let state = self.state.read().await;
        CircuitBreakerStats {
            state: state.state.clone(),
            failure_count: state.failure_count,
            success_count: state.success_count,
            time_in_current_state: state.last_state_change.elapsed(),
        }
    }

    /// Force reset to closed state
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        debug!("Circuit breaker manually reset");
        state.state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.last_failure_time = None;
        state.last_state_change = Instant::now();
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub time_in_current_state: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let cb = CircuitBreaker::new(Some(3), Some(1), Some(2));

        // First 3 failures should open circuit
        for _ in 0..3 {
            cb.record_failure().await;
        }

        let state = cb.get_state().await;
        assert_eq!(state, CircuitState::Open);

        // Should reject requests when open
        assert!(cb.allow_request().await.is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker_recovers() {
        let cb = CircuitBreaker::new(Some(3), Some(1), Some(2));

        // Open the circuit
        for _ in 0..3 {
            cb.record_failure().await;
        }

        // Wait for timeout
        sleep(Duration::from_secs(2)).await;

        // Should allow request in HalfOpen
        assert!(cb.allow_request().await.is_ok());

        // Record successful recoveries
        cb.record_success().await;
        cb.record_success().await;

        // Should be closed now
        let state = cb.get_state().await;
        assert_eq!(state, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_stats() {
        let cb = CircuitBreaker::new(Some(5), Some(10), Some(2));

        cb.record_failure().await;
        cb.record_failure().await;

        let stats = cb.get_stats().await;
        assert_eq!(stats.failure_count, 2);
        assert_eq!(stats.state, CircuitState::Closed);
    }
}
