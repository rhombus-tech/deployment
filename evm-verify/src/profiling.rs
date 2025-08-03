use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tracing::{info, debug, instrument};

/// Comprehensive performance profiling system for ZODA
#[derive(Debug, Clone)]
pub struct ZodaPerformanceProfiler {
    timings: Arc<Mutex<HashMap<String, Vec<Duration>>>>,
    memory_snapshots: Arc<Mutex<Vec<MemorySnapshot>>>,
    operation_counts: Arc<Mutex<HashMap<String, usize>>>,
    start_time: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub operation: String,
    pub timestamp: Duration,
    pub memory_used: usize,
    pub memory_delta: isize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub total_runtime: Duration,
    pub operation_timings: HashMap<String, OperationStats>,
    pub memory_usage: MemoryUsageStats,
    pub throughput_metrics: ThroughputMetrics,
    pub bottleneck_analysis: Vec<BottleneckReport>,
    pub optimization_recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStats {
    pub operation_name: String,
    pub sample_count: usize,
    pub total_time: Duration,
    pub average_time: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
    pub percentile_95: Duration,
    pub percentile_99: Duration,
    pub operations_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsageStats {
    pub peak_memory: usize,
    pub average_memory: usize,
    pub memory_growth_rate: f64,
    pub largest_allocations: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputMetrics {
    pub circuits_per_second: f64,
    pub proofs_per_second: f64,
    pub bytes_processed_per_second: f64,
    pub verification_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BottleneckReport {
    pub operation: String,
    pub percentage_of_total_time: f64,
    pub severity: BottleneckSeverity,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BottleneckSeverity {
    Critical,  // >30% of total time
    Major,     // 10-30% of total time
    Minor,     // 5-10% of total time
}

impl ZodaPerformanceProfiler {
    pub fn new() -> Self {
        Self {
            timings: Arc::new(Mutex::new(HashMap::new())),
            memory_snapshots: Arc::new(Mutex::new(Vec::new())),
            operation_counts: Arc::new(Mutex::new(HashMap::new())),
            start_time: Instant::now(),
        }
    }
    
    /// Time a specific operation with detailed profiling
    #[instrument(skip(self, operation))]
    pub fn time_operation<F, R>(&self, name: &str, operation: F) -> R
    where F: FnOnce() -> R
    {
        let start = Instant::now();
        let start_memory = get_memory_usage();
        
        debug!("Starting operation: {}", name);
        
        let result = operation();
        
        let duration = start.elapsed();
        let end_memory = get_memory_usage();
        let memory_delta = end_memory as isize - start_memory as isize;
        
        // Record timing
        self.timings.lock().unwrap()
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
        
        // Record memory usage
        self.memory_snapshots.lock().unwrap().push(MemorySnapshot {
            operation: name.to_string(),
            timestamp: start.elapsed(),
            memory_used: end_memory,
            memory_delta,
        });
        
        // Update operation count
        *self.operation_counts.lock().unwrap()
            .entry(name.to_string())
            .or_insert(0) += 1;
        
        debug!("Completed operation: {} in {:?}", name, duration);
        
        result
    }
    
    /// Time an async operation
    pub async fn time_async_operation<F, Fut, R>(&self, name: &str, operation: F) -> R
    where 
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let start_memory = get_memory_usage();
        
        debug!("Starting async operation: {}", name);
        
        let result = operation().await;
        
        let duration = start.elapsed();
        let end_memory = get_memory_usage();
        let memory_delta = end_memory as isize - start_memory as isize;
        
        // Record timing
        self.timings.lock().unwrap()
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
        
        // Record memory usage
        self.memory_snapshots.lock().unwrap().push(MemorySnapshot {
            operation: name.to_string(),
            timestamp: start.elapsed(),
            memory_used: end_memory,
            memory_delta,
        });
        
        // Update operation count
        *self.operation_counts.lock().unwrap()
            .entry(name.to_string())
            .or_insert(0) += 1;
        
        debug!("Completed async operation: {} in {:?}", name, duration);
        
        result
    }
    
    /// Generate comprehensive performance report
    pub fn generate_report(&self) -> PerformanceReport {
        let total_runtime = self.start_time.elapsed();
        let timings = self.timings.lock().unwrap();
        let memory_snapshots = self.memory_snapshots.lock().unwrap();
        let operation_counts = self.operation_counts.lock().unwrap();
        
        // Calculate operation statistics
        let mut operation_timings = HashMap::new();
        let mut total_time_all_ops = Duration::ZERO;
        
        for (operation, times) in timings.iter() {
            let sample_count = times.len();
            let total_time: Duration = times.iter().sum();
            let average_time = total_time / sample_count as u32;
            let min_time = *times.iter().min().unwrap();
            let max_time = *times.iter().max().unwrap();
            
            // Calculate percentiles
            let mut sorted_times = times.clone();
            sorted_times.sort();
            let percentile_95 = sorted_times[(sample_count as f64 * 0.95) as usize];
            let percentile_99 = sorted_times[(sample_count as f64 * 0.99) as usize];
            
            let operations_per_second = sample_count as f64 / total_time.as_secs_f64();
            
            operation_timings.insert(operation.clone(), OperationStats {
                operation_name: operation.clone(),
                sample_count,
                total_time,
                average_time,
                min_time,
                max_time,
                percentile_95,
                percentile_99,
                operations_per_second,
            });
            
            total_time_all_ops += total_time;
        }
        
        // Memory usage analysis
        let memory_usage = self.analyze_memory_usage(&memory_snapshots);
        
        // Throughput metrics
        let total_operations: usize = operation_counts.values().sum();
        let throughput_metrics = ThroughputMetrics {
            circuits_per_second: *operation_counts.get("circuit_processing")
                .unwrap_or(&0) as f64 / total_runtime.as_secs_f64(),
            proofs_per_second: *operation_counts.get("proof_generation")
                .unwrap_or(&0) as f64 / total_runtime.as_secs_f64(),
            bytes_processed_per_second: 0.0, // Would calculate from actual data
            verification_rate: *operation_counts.get("verification")
                .unwrap_or(&0) as f64 / total_runtime.as_secs_f64(),
        };
        
        // Bottleneck analysis
        let bottleneck_analysis = self.analyze_bottlenecks(&operation_timings, total_time_all_ops);
        
        // Optimization recommendations
        let optimization_recommendations = self.generate_optimization_recommendations(
            &operation_timings, 
            &memory_usage, 
            &bottleneck_analysis
        );
        
        PerformanceReport {
            total_runtime,
            operation_timings,
            memory_usage,
            throughput_metrics,
            bottleneck_analysis,
            optimization_recommendations,
        }
    }
    
    fn analyze_memory_usage(&self, snapshots: &[MemorySnapshot]) -> MemoryUsageStats {
        if snapshots.is_empty() {
            return MemoryUsageStats {
                peak_memory: 0,
                average_memory: 0,
                memory_growth_rate: 0.0,
                largest_allocations: vec![],
            };
        }
        
        let peak_memory = snapshots.iter().map(|s| s.memory_used).max().unwrap_or(0);
        let average_memory = snapshots.iter().map(|s| s.memory_used).sum::<usize>() / snapshots.len();
        
        // Calculate memory growth rate
        let first_memory = snapshots.first().unwrap().memory_used as f64;
        let last_memory = snapshots.last().unwrap().memory_used as f64;
        let total_time = snapshots.last().unwrap().timestamp.as_secs_f64();
        let memory_growth_rate = if total_time > 0.0 {
            (last_memory - first_memory) / total_time
        } else {
            0.0
        };
        
        // Find largest allocations
        let mut largest_allocations: Vec<_> = snapshots.iter()
            .filter(|s| s.memory_delta > 0)
            .map(|s| (s.operation.clone(), s.memory_delta as usize))
            .collect();
        largest_allocations.sort_by(|a, b| b.1.cmp(&a.1));
        largest_allocations.truncate(5); // Top 5
        
        MemoryUsageStats {
            peak_memory,
            average_memory,
            memory_growth_rate,
            largest_allocations,
        }
    }
    
    fn analyze_bottlenecks(&self, operation_timings: &HashMap<String, OperationStats>, total_time: Duration) -> Vec<BottleneckReport> {
        let mut bottlenecks = Vec::new();
        
        for (_, stats) in operation_timings {
            let percentage = (stats.total_time.as_secs_f64() / total_time.as_secs_f64()) * 100.0;
            
            let (severity, recommendation) = match percentage {
                p if p > 30.0 => (
                    BottleneckSeverity::Critical,
                    format!("CRITICAL: {} consumes {:.1}% of total time. Immediate optimization required.", stats.operation_name, p)
                ),
                p if p > 10.0 => (
                    BottleneckSeverity::Major,
                    format!("MAJOR: {} consumes {:.1}% of total time. Consider optimization.", stats.operation_name, p)
                ),
                p if p > 5.0 => (
                    BottleneckSeverity::Minor,
                    format!("MINOR: {} consumes {:.1}% of total time. Monitor for optimization opportunities.", stats.operation_name, p)
                ),
                _ => continue,
            };
            
            bottlenecks.push(BottleneckReport {
                operation: stats.operation_name.clone(),
                percentage_of_total_time: percentage,
                severity,
                recommendation,
            });
        }
        
        // Sort by severity and percentage
        bottlenecks.sort_by(|a, b| {
            b.percentage_of_total_time.partial_cmp(&a.percentage_of_total_time).unwrap()
        });
        
        bottlenecks
    }
    
    fn generate_optimization_recommendations(
        &self, 
        operation_timings: &HashMap<String, OperationStats>,
        memory_usage: &MemoryUsageStats,
        bottlenecks: &[BottleneckReport]
    ) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Performance recommendations
        if let Some(critical_bottleneck) = bottlenecks.iter().find(|b| matches!(b.severity, BottleneckSeverity::Critical)) {
            recommendations.push(format!(
                "🚨 URGENT: Optimize '{}' operation - it's consuming {:.1}% of total execution time",
                critical_bottleneck.operation, critical_bottleneck.percentage_of_total_time
            ));
        }
        
        // Memory recommendations
        if memory_usage.memory_growth_rate > 1024.0 * 1024.0 { // > 1MB/sec growth
            recommendations.push(format!(
                "🧠 MEMORY: High memory growth rate ({:.2} MB/sec). Check for memory leaks or optimize allocations.",
                memory_usage.memory_growth_rate / (1024.0 * 1024.0)
            ));
        }
        
        if memory_usage.peak_memory > 1024 * 1024 * 1024 { // > 1GB peak
            recommendations.push(format!(
                "🧠 MEMORY: High peak memory usage ({:.2} GB). Consider streaming or batch processing.",
                memory_usage.peak_memory as f64 / (1024.0 * 1024.0 * 1024.0)
            ));
        }
        
        // Throughput recommendations
        for (operation, stats) in operation_timings {
            if stats.operations_per_second < 10.0 && stats.sample_count > 10 {
                recommendations.push(format!(
                    "⚡ THROUGHPUT: '{}' has low throughput ({:.2} ops/sec). Consider parallelization or algorithm optimization.",
                    operation, stats.operations_per_second
                ));
            }
            
            // High variance detection
            let variance_ratio = stats.max_time.as_secs_f64() / stats.min_time.as_secs_f64();
            if variance_ratio > 10.0 {
                recommendations.push(format!(
                    "📊 CONSISTENCY: '{}' has high variance ({}x difference between min/max). Investigate inconsistent performance.",
                    operation, variance_ratio as u32
                ));
            }
        }
        
        // Parallelization opportunities
        let sequential_operations = operation_timings.iter()
            .filter(|(_, stats)| stats.operations_per_second < 100.0 && stats.sample_count > 50)
            .count();
        
        if sequential_operations > 2 {
            recommendations.push(
                "🔄 PARALLELIZATION: Multiple slow operations detected. Consider parallel processing or async optimization.".to_string()
            );
        }
        
        // General recommendations
        if recommendations.is_empty() {
            recommendations.push("✅ PERFORMANCE: System performance looks good! Monitor for any degradation over time.".to_string());
        }
        
        recommendations
    }
    
    /// Export detailed performance data to JSON
    pub fn export_detailed_data(&self, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let report = self.generate_report();
        let json_data = serde_json::to_string_pretty(&report)?;
        std::fs::write(file_path, json_data)?;
        Ok(())
    }
    
    /// Print a human-readable performance summary
    pub fn print_summary(&self) {
        let report = self.generate_report();
        
        println!("\n🚀 ZODA PERFORMANCE ANALYSIS REPORT");
        println!("=====================================");
        println!("Total Runtime: {:?}", report.total_runtime);
        println!("Peak Memory: {:.2} MB", report.memory_usage.peak_memory as f64 / (1024.0 * 1024.0));
        println!();
        
        println!("📊 TOP OPERATIONS BY TIME:");
        let mut sorted_ops: Vec<_> = report.operation_timings.values().collect();
        sorted_ops.sort_by(|a, b| b.total_time.cmp(&a.total_time));
        
        for (i, stats) in sorted_ops.iter().take(5).enumerate() {
            println!("  {}. {} - {:?} total ({:.2} ops/sec)", 
                     i + 1, stats.operation_name, stats.total_time, stats.operations_per_second);
        }
        
        println!();
        println!("🎯 BOTTLENECK ANALYSIS:");
        for bottleneck in &report.bottleneck_analysis {
            let icon = match bottleneck.severity {
                BottleneckSeverity::Critical => "🚨",
                BottleneckSeverity::Major => "⚠️",
                BottleneckSeverity::Minor => "ℹ️",
            };
            println!("  {} {}", icon, bottleneck.recommendation);
        }
        
        println!();
        println!("💡 OPTIMIZATION RECOMMENDATIONS:");
        for (i, rec) in report.optimization_recommendations.iter().enumerate() {
            println!("  {}. {}", i + 1, rec);
        }
        
        println!();
    }
}

impl Default for ZodaPerformanceProfiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current memory usage (simplified implementation)
fn get_memory_usage() -> usize {
    // In a real implementation, this would use platform-specific APIs
    // For now, we'll simulate with a simple estimate
    use std::alloc::{GlobalAlloc, Layout, System};
    
    // This is a simplified estimation - in production you'd use:
    // - On Linux: /proc/self/status or mallinfo
    // - On macOS: task_info with TASK_VM_INFO
    // - On Windows: GetProcessMemoryInfo
    
    // For demonstration, we'll return a mock value based on time
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    
    (1024 * 1024 * 10) + ((elapsed % 1000) * 1024) as usize // Base 10MB + some variation
}

/// Performance profiling macro for easy operation timing
#[macro_export]
macro_rules! profile_operation {
    ($profiler:expr, $name:expr, $operation:expr) => {
        $profiler.time_operation($name, || $operation)
    };
}

/// Async performance profiling macro
#[macro_export]
macro_rules! profile_async_operation {
    ($profiler:expr, $name:expr, $operation:expr) => {
        $profiler.time_async_operation($name, || async { $operation }).await
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_performance_profiler() {
        let profiler = ZodaPerformanceProfiler::new();
        
        // Test some operations
        profiler.time_operation("test_operation_1", || {
            thread::sleep(Duration::from_millis(10));
            42
        });
        
        profiler.time_operation("test_operation_2", || {
            thread::sleep(Duration::from_millis(5));
            "test"
        });
        
        // Another call to the same operation
        profiler.time_operation("test_operation_1", || {
            thread::sleep(Duration::from_millis(15));
            84
        });
        
        let report = profiler.generate_report();
        
        assert_eq!(report.operation_timings.len(), 2);
        assert!(report.operation_timings.contains_key("test_operation_1"));
        assert!(report.operation_timings.contains_key("test_operation_2"));
        
        let op1_stats = &report.operation_timings["test_operation_1"];
        assert_eq!(op1_stats.sample_count, 2);
        assert!(op1_stats.total_time >= Duration::from_millis(25));
    }
    
    #[tokio::test]
    async fn test_async_profiler() {
        let profiler = ZodaPerformanceProfiler::new();
        
        let result = profiler.time_async_operation("async_test", || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            "async_result"
        }).await;
        
        assert_eq!(result, "async_result");
        
        let report = profiler.generate_report();
        assert!(report.operation_timings.contains_key("async_test"));
    }
}
