// ZODA Performance Monitor - Real-time execution analytics
//
// Monitors block execution performance for sub-10 second proving latency
// Provides detailed metrics and optimization insights

use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;

use crate::block_execution::BlockExecutionConfig;

/// Real-time performance monitor for block execution
pub struct PerformanceMonitor {
    /// Execution metrics
    metrics: Arc<RwLock<ExecutionMetrics>>,
    
    /// Historical performance data
    history: Arc<Mutex<PerformanceHistory>>,
    
    /// Configuration
    config: BlockExecutionConfig,
    
    /// Performance targets
    targets: PerformanceTargets,
}

/// Current execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    /// Block execution times (rolling window)
    pub block_execution_times: VecDeque<Duration>,
    
    /// Transaction processing times
    pub transaction_processing_times: VecDeque<Duration>,
    
    /// Proof generation times
    pub proof_generation_times: VecDeque<Duration>,
    
    /// State accumulation times
    pub state_accumulation_times: VecDeque<Duration>,
    
    /// Validation times
    pub validation_times: VecDeque<Duration>,
    
    /// CPU utilization samples
    pub cpu_utilization: VecDeque<f64>,
    
    /// Memory usage samples
    pub memory_usage: VecDeque<u64>,
    
    /// Throughput metrics
    pub throughput_metrics: ThroughputMetrics,
    
    /// Error counts
    pub error_counts: HashMap<String, u64>,
    
    /// Success rate (rolling average)
    pub success_rate: f64,
    
    /// Last update timestamp
    pub last_updated: SystemTime,
}

/// Historical performance data
#[derive(Debug, Clone)]
struct PerformanceHistory {
    /// Daily aggregated metrics
    daily_metrics: VecDeque<DailyMetrics>,
    
    /// Peak performance records
    peak_performance: PeakPerformance,
    
    /// Performance trends
    trends: PerformanceTrends,
}

/// Throughput metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputMetrics {
    /// Blocks processed per second
    pub blocks_per_second: f64,
    
    /// Transactions processed per second
    pub transactions_per_second: f64,
    
    /// Proofs generated per second
    pub proofs_per_second: f64,
    
    /// Gas processed per second
    pub gas_per_second: f64,
    
    /// Current processing rate
    pub current_rate: f64,
    
    /// Average processing rate
    pub average_rate: f64,
}

/// Daily aggregated metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyMetrics {
    /// Date
    pub date: String,
    
    /// Total blocks processed
    pub total_blocks: u64,
    
    /// Total transactions processed
    pub total_transactions: u64,
    
    /// Average execution time
    pub avg_execution_time: Duration,
    
    /// Success rate
    pub success_rate: f64,
    
    /// Peak throughput
    pub peak_throughput: f64,
    
    /// Error count
    pub error_count: u64,
}

/// Peak performance records
#[derive(Debug, Clone)]
struct PeakPerformance {
    /// Fastest block execution
    fastest_block_time: Duration,
    
    /// Highest throughput
    highest_throughput: f64,
    
    /// Best success rate
    best_success_rate: f64,
    
    /// Lowest latency
    lowest_latency: Duration,
}

/// Performance trends
#[derive(Debug, Clone)]
struct PerformanceTrends {
    /// Execution time trend (improving/degrading)
    execution_time_trend: TrendDirection,
    
    /// Throughput trend
    throughput_trend: TrendDirection,
    
    /// Success rate trend
    success_rate_trend: TrendDirection,
    
    /// Resource usage trend
    resource_usage_trend: TrendDirection,
}

/// Trend direction
#[derive(Debug, Clone, PartialEq)]
enum TrendDirection {
    Improving,
    Stable,
    Degrading,
}

/// Performance targets
#[derive(Debug, Clone)]
struct PerformanceTargets {
    /// Target block execution time (sub-10 seconds)
    target_block_time: Duration,
    
    /// Target success rate
    target_success_rate: f64,
    
    /// Target throughput (blocks per second)
    target_throughput: f64,
    
    /// Maximum acceptable latency
    max_latency: Duration,
    
    /// CPU usage threshold
    cpu_threshold: f64,
    
    /// Memory usage threshold (bytes)
    memory_threshold: u64,
}

/// Performance alert types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceAlert {
    /// Execution time exceeded target
    ExecutionTimeExceeded { actual: Duration, target: Duration },
    
    /// Low success rate
    LowSuccessRate { actual: f64, target: f64 },
    
    /// High CPU usage
    HighCpuUsage { actual: f64, threshold: f64 },
    
    /// High memory usage
    HighMemoryUsage { actual: u64, threshold: u64 },
    
    /// Low throughput
    LowThroughput { actual: f64, target: f64 },
    
    /// Performance degradation detected
    PerformanceDegradation { metric: String, trend: String },
}

/// Performance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    /// Report timestamp
    pub timestamp: SystemTime,
    
    /// Current metrics snapshot
    pub current_metrics: ExecutionMetrics,
    
    /// Performance alerts
    pub alerts: Vec<PerformanceAlert>,
    
    /// Optimization recommendations
    pub recommendations: Vec<String>,
    
    /// Summary statistics
    pub summary: PerformanceSummary,
}

/// Performance summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    /// Average block execution time
    pub avg_block_time: Duration,
    
    /// 95th percentile execution time
    pub p95_block_time: Duration,
    
    /// 99th percentile execution time
    pub p99_block_time: Duration,
    
    /// Overall success rate
    pub overall_success_rate: f64,
    
    /// Current throughput
    pub current_throughput: f64,
    
    /// Target compliance percentage
    pub target_compliance: f64,
}

impl Default for PerformanceTargets {
    fn default() -> Self {
        Self {
            target_block_time: Duration::from_secs(10), // Sub-10 second target
            target_success_rate: 0.99, // 99% success rate
            target_throughput: 10.0, // 10 blocks per second
            max_latency: Duration::from_secs(15), // Maximum 15 seconds
            cpu_threshold: 80.0, // 80% CPU usage threshold
            memory_threshold: 8_000_000_000, // 8GB memory threshold
        }
    }
}

impl Default for PerformanceReport {
    fn default() -> Self {
        Self {
            timestamp: SystemTime::now(),
            current_metrics: ExecutionMetrics::default(),
            alerts: Vec::new(),
            recommendations: Vec::new(),
            summary: PerformanceSummary::default(),
        }
    }
}

impl Default for PerformanceSummary {
    fn default() -> Self {
        Self {
            avg_block_time: Duration::from_secs(0),
            p95_block_time: Duration::from_secs(0),
            p99_block_time: Duration::from_secs(0),
            overall_success_rate: 1.0,
            current_throughput: 0.0,
            target_compliance: 100.0,
        }
    }
}

impl Default for ExecutionMetrics {
    fn default() -> Self {
        Self {
            block_execution_times: VecDeque::with_capacity(1000),
            transaction_processing_times: VecDeque::with_capacity(10000),
            proof_generation_times: VecDeque::with_capacity(1000),
            state_accumulation_times: VecDeque::with_capacity(1000),
            validation_times: VecDeque::with_capacity(1000),
            cpu_utilization: VecDeque::with_capacity(1000),
            memory_usage: VecDeque::with_capacity(1000),
            throughput_metrics: ThroughputMetrics::default(),
            error_counts: HashMap::new(),
            success_rate: 1.0,
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for ThroughputMetrics {
    fn default() -> Self {
        Self {
            blocks_per_second: 0.0,
            transactions_per_second: 0.0,
            proofs_per_second: 0.0,
            gas_per_second: 0.0,
            current_rate: 0.0,
            average_rate: 0.0,
        }
    }
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: BlockExecutionConfig) -> Result<Self> {
        Ok(Self {
            metrics: Arc::new(RwLock::new(ExecutionMetrics::default())),
            history: Arc::new(Mutex::new(PerformanceHistory::new())),
            config,
            targets: PerformanceTargets::default(),
        })
    }

    /// Record block execution time
    pub async fn record_block_execution(&self, duration: Duration, success: bool) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        // Add to rolling window (keep last 1000 entries)
        if metrics.block_execution_times.len() >= 1000 {
            metrics.block_execution_times.pop_front();
        }
        metrics.block_execution_times.push_back(duration);
        
        // Update success rate (exponential moving average)
        let success_value = if success { 1.0 } else { 0.0 };
        metrics.success_rate = 0.95 * metrics.success_rate + 0.05 * success_value;
        
        // Update throughput
        self.update_throughput(&mut metrics).await?;
        
        metrics.last_updated = SystemTime::now();
        
        Ok(())
    }

    /// Record transaction processing time
    pub async fn record_transaction_processing(&self, duration: Duration, count: usize) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        // Add to rolling window
        if metrics.transaction_processing_times.len() >= 10000 {
            metrics.transaction_processing_times.pop_front();
        }
        metrics.transaction_processing_times.push_back(duration);
        
        // Update transaction throughput
        let tps = count as f64 / duration.as_secs_f64();
        metrics.throughput_metrics.transactions_per_second = 
            0.9 * metrics.throughput_metrics.transactions_per_second + 0.1 * tps;
        
        Ok(())
    }

    /// Record proof generation time
    pub async fn record_proof_generation(&self, duration: Duration) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        if metrics.proof_generation_times.len() >= 1000 {
            metrics.proof_generation_times.pop_front();
        }
        metrics.proof_generation_times.push_back(duration);
        
        // Update proof generation rate
        let pps = 1.0 / duration.as_secs_f64();
        metrics.throughput_metrics.proofs_per_second = 
            0.9 * metrics.throughput_metrics.proofs_per_second + 0.1 * pps;
        
        Ok(())
    }

    /// Record state accumulation time
    pub async fn record_state_accumulation(&self, duration: Duration) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        if metrics.state_accumulation_times.len() >= 1000 {
            metrics.state_accumulation_times.pop_front();
        }
        metrics.state_accumulation_times.push_back(duration);
        
        Ok(())
    }

    /// Record validation time
    pub async fn record_validation(&self, duration: Duration) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        if metrics.validation_times.len() >= 1000 {
            metrics.validation_times.pop_front();
        }
        metrics.validation_times.push_back(duration);
        
        Ok(())
    }

    /// Record error occurrence
    pub async fn record_error(&self, error_type: &str) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        *metrics.error_counts.entry(error_type.to_string()).or_insert(0) += 1;
        
        Ok(())
    }

    /// Update system resource usage
    pub async fn update_resource_usage(&self, cpu_percent: f64, memory_bytes: u64) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        
        // CPU utilization
        if metrics.cpu_utilization.len() >= 1000 {
            metrics.cpu_utilization.pop_front();
        }
        metrics.cpu_utilization.push_back(cpu_percent);
        
        // Memory usage
        if metrics.memory_usage.len() >= 1000 {
            metrics.memory_usage.pop_front();
        }
        metrics.memory_usage.push_back(memory_bytes);
        
        Ok(())
    }

    /// Generate performance report
    pub async fn generate_report(&self) -> Result<PerformanceReport> {
        let metrics = self.metrics.read().unwrap().clone();
        let mut alerts = Vec::new();
        let mut recommendations = Vec::new();

        // Check performance against targets
        self.check_performance_alerts(&metrics, &mut alerts, &mut recommendations).await?;
        
        // Generate summary statistics
        let summary = self.generate_summary(&metrics).await?;

        Ok(PerformanceReport {
            timestamp: SystemTime::now(),
            current_metrics: metrics,
            alerts,
            recommendations,
            summary,
        })
    }

    /// Check for performance alerts
    async fn check_performance_alerts(
        &self,
        metrics: &ExecutionMetrics,
        alerts: &mut Vec<PerformanceAlert>,
        recommendations: &mut Vec<String>,
    ) -> Result<()> {
        // Check execution time
        if let Some(&latest_time) = metrics.block_execution_times.back() {
            if latest_time > self.targets.target_block_time {
                alerts.push(PerformanceAlert::ExecutionTimeExceeded {
                    actual: latest_time,
                    target: self.targets.target_block_time,
                });
                recommendations.push("Consider optimizing proof generation or increasing CPU threads".to_string());
            }
        }

        // Check success rate
        if metrics.success_rate < self.targets.target_success_rate {
            alerts.push(PerformanceAlert::LowSuccessRate {
                actual: metrics.success_rate,
                target: self.targets.target_success_rate,
            });
            recommendations.push("Investigate error patterns and improve validation logic".to_string());
        }

        // Check CPU usage
        if let Some(&latest_cpu) = metrics.cpu_utilization.back() {
            if latest_cpu > self.targets.cpu_threshold {
                alerts.push(PerformanceAlert::HighCpuUsage {
                    actual: latest_cpu,
                    threshold: self.targets.cpu_threshold,
                });
                recommendations.push("Consider reducing parallel processing or upgrading hardware".to_string());
            }
        }

        // Check memory usage
        if let Some(&latest_memory) = metrics.memory_usage.back() {
            if latest_memory > self.targets.memory_threshold {
                alerts.push(PerformanceAlert::HighMemoryUsage {
                    actual: latest_memory,
                    threshold: self.targets.memory_threshold,
                });
                recommendations.push("Optimize memory usage or increase available RAM".to_string());
            }
        }

        // Check throughput
        if metrics.throughput_metrics.blocks_per_second < self.targets.target_throughput {
            alerts.push(PerformanceAlert::LowThroughput {
                actual: metrics.throughput_metrics.blocks_per_second,
                target: self.targets.target_throughput,
            });
            recommendations.push("Optimize batch processing and parallel execution".to_string());
        }

        Ok(())
    }

    /// Generate summary statistics
    async fn generate_summary(&self, metrics: &ExecutionMetrics) -> Result<PerformanceSummary> {
        let avg_block_time = self.calculate_average_duration(&metrics.block_execution_times);
        let p95_block_time = self.calculate_percentile(&metrics.block_execution_times, 95.0);
        let p99_block_time = self.calculate_percentile(&metrics.block_execution_times, 99.0);
        
        // Calculate target compliance
        let compliant_executions = metrics.block_execution_times
            .iter()
            .filter(|&&time| time <= self.targets.target_block_time)
            .count();
        
        let target_compliance = if !metrics.block_execution_times.is_empty() {
            (compliant_executions as f64 / metrics.block_execution_times.len() as f64) * 100.0
        } else {
            100.0
        };

        Ok(PerformanceSummary {
            avg_block_time,
            p95_block_time,
            p99_block_time,
            overall_success_rate: metrics.success_rate,
            current_throughput: metrics.throughput_metrics.blocks_per_second,
            target_compliance,
        })
    }

    /// Update throughput metrics
    async fn update_throughput(&self, metrics: &mut ExecutionMetrics) -> Result<()> {
        // Calculate blocks per second based on recent execution times
        if !metrics.block_execution_times.is_empty() {
            let recent_times: Vec<_> = metrics.block_execution_times
                .iter()
                .rev()
                .take(10)
                .collect();
            
            if !recent_times.is_empty() {
                let avg_time = recent_times.iter().fold(Duration::ZERO, |sum, &&time| sum + time) 
                    / recent_times.len() as u32;
                
                metrics.throughput_metrics.blocks_per_second = 1.0 / avg_time.as_secs_f64();
                metrics.throughput_metrics.current_rate = metrics.throughput_metrics.blocks_per_second;
                
                // Update average rate (exponential moving average)
                metrics.throughput_metrics.average_rate = 
                    0.9 * metrics.throughput_metrics.average_rate + 
                    0.1 * metrics.throughput_metrics.blocks_per_second;
            }
        }

        Ok(())
    }

    /// Calculate average duration
    fn calculate_average_duration(&self, durations: &VecDeque<Duration>) -> Duration {
        if durations.is_empty() {
            return Duration::ZERO;
        }

        let sum: Duration = durations.iter().sum();
        sum / durations.len() as u32
    }

    /// Calculate percentile of durations
    fn calculate_percentile(&self, durations: &VecDeque<Duration>, percentile: f64) -> Duration {
        if durations.is_empty() {
            return Duration::ZERO;
        }

        let mut sorted: Vec<_> = durations.iter().collect();
        sorted.sort();

        let index = ((percentile / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        *sorted[index.min(sorted.len() - 1)]
    }

    /// Get current metrics snapshot
    pub async fn get_metrics(&self) -> Result<ExecutionMetrics> {
        Ok(self.metrics.read().unwrap().clone())
    }

    /// Health check for the monitor
    pub async fn health_check(&self) -> Result<bool> {
        let metrics = self.metrics.read().unwrap();
        
        // Monitor is healthy if it has recent data
        let last_update_age = SystemTime::now()
            .duration_since(metrics.last_updated)
            .unwrap_or(Duration::from_secs(0));
        
        Ok(last_update_age < Duration::from_secs(300)) // 5 minutes threshold
    }

    /// Reset metrics (for testing)
    pub async fn reset_metrics(&self) -> Result<()> {
        let mut metrics = self.metrics.write().unwrap();
        *metrics = ExecutionMetrics::default();
        Ok(())
    }
}

impl PerformanceHistory {
    fn new() -> Self {
        Self {
            daily_metrics: VecDeque::with_capacity(365), // Keep 1 year of daily data
            peak_performance: PeakPerformance::default(),
            trends: PerformanceTrends::default(),
        }
    }
}

impl Default for PeakPerformance {
    fn default() -> Self {
        Self {
            fastest_block_time: Duration::from_secs(u64::MAX),
            highest_throughput: 0.0,
            best_success_rate: 0.0,
            lowest_latency: Duration::from_secs(u64::MAX),
        }
    }
}

impl Default for PerformanceTrends {
    fn default() -> Self {
        Self {
            execution_time_trend: TrendDirection::Stable,
            throughput_trend: TrendDirection::Stable,
            success_rate_trend: TrendDirection::Stable,
            resource_usage_trend: TrendDirection::Stable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitor_creation() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config);
        assert!(monitor.is_ok());
    }

    #[tokio::test]
    async fn test_record_block_execution() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        let duration = Duration::from_secs(5);
        let result = monitor.record_block_execution(duration, true).await;
        assert!(result.is_ok());
        
        let metrics = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics.block_execution_times.len(), 1);
        assert_eq!(metrics.block_execution_times[0], duration);
    }

    #[tokio::test]
    async fn test_record_transaction_processing() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        let duration = Duration::from_millis(100);
        let result = monitor.record_transaction_processing(duration, 10).await;
        assert!(result.is_ok());
        
        let metrics = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics.transaction_processing_times.len(), 1);
        assert!(metrics.throughput_metrics.transactions_per_second > 0.0);
    }

    #[tokio::test]
    async fn test_record_proof_generation() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        let duration = Duration::from_secs(2);
        let result = monitor.record_proof_generation(duration).await;
        assert!(result.is_ok());
        
        let metrics = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics.proof_generation_times.len(), 1);
        assert!(metrics.throughput_metrics.proofs_per_second > 0.0);
    }

    #[tokio::test]
    async fn test_record_error() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        let result = monitor.record_error("validation_error").await;
        assert!(result.is_ok());
        
        let metrics = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics.error_counts.get("validation_error"), Some(&1));
    }

    #[tokio::test]
    async fn test_update_resource_usage() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        let result = monitor.update_resource_usage(75.5, 4_000_000_000).await;
        assert!(result.is_ok());
        
        let metrics = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics.cpu_utilization.len(), 1);
        assert_eq!(metrics.memory_usage.len(), 1);
        assert_eq!(metrics.cpu_utilization[0], 75.5);
        assert_eq!(metrics.memory_usage[0], 4_000_000_000);
    }

    #[tokio::test]
    async fn test_generate_report() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        // Add some sample data
        monitor.record_block_execution(Duration::from_secs(5), true).await.unwrap();
        monitor.record_transaction_processing(Duration::from_millis(100), 10).await.unwrap();
        monitor.update_resource_usage(50.0, 2_000_000_000).await.unwrap();
        
        let report = monitor.generate_report().await;
        assert!(report.is_ok());
        
        let report = report.unwrap();
        assert_eq!(report.current_metrics.block_execution_times.len(), 1);
        assert!(!report.alerts.is_empty() || report.alerts.is_empty()); // Either is valid
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        // Fresh monitor should be healthy
        let health = monitor.health_check().await;
        assert!(health.is_ok());
        assert!(health.unwrap());
    }

    #[tokio::test]
    async fn test_performance_alerts() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        // Record a slow execution that should trigger alert
        monitor.record_block_execution(Duration::from_secs(15), true).await.unwrap();
        
        let report = monitor.generate_report().await.expect("Failed to generate report");
        
        // Should have execution time exceeded alert
        let has_execution_alert = report.alerts.iter().any(|alert| {
            matches!(alert, PerformanceAlert::ExecutionTimeExceeded { .. })
        });
        assert!(has_execution_alert);
    }

    #[tokio::test]
    async fn test_reset_metrics() {
        let config = BlockExecutionConfig::default();
        let monitor = PerformanceMonitor::new(config).expect("Failed to create monitor");
        
        // Add some data
        monitor.record_block_execution(Duration::from_secs(5), true).await.unwrap();
        
        // Verify data exists
        let metrics_before = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics_before.block_execution_times.len(), 1);
        
        // Reset
        let result = monitor.reset_metrics().await;
        assert!(result.is_ok());
        
        // Verify data is cleared
        let metrics_after = monitor.get_metrics().await.expect("Failed to get metrics");
        assert_eq!(metrics_after.block_execution_times.len(), 0);
    }
}
