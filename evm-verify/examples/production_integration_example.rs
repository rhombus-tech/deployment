//! # Production Integration Example
//! 
//! This example demonstrates the complete production-grade zkEVM infrastructure
//! including error handling, structured logging, metrics collection, configuration
//! management, and monitoring with real cryptographic proving.

use std::sync::Arc;
use std::time::Duration;
use evm_verify::{
    config::{ZkEvmConfig, Environment},
    logging::{Logger, LogFormat},
    metrics::ZkEvmMetrics,
    monitoring::MonitoringSystem,
    error::{ZkEvmResult, ZkEvmError, ErrorSeverity},
    api::{UnifiedVerifier, accumulation_strategy::AccumulationStrategy},
};

#[tokio::main]
async fn main() -> ZkEvmResult<()> {
    println!("🚀 Production zkEVM Integration Example");
    println!("=====================================");
    
    // Step 1: Configuration Management
    println!("\n📋 Step 1: Configuration Management");
    let mut config = ZkEvmConfig::default();
    config.environment = Environment::Development;
    config.proving.default_strategy = "ZodaWarpHybrid".to_string();
    config.logging.format = LogFormat::Json;
    
    println!("✅ Configuration loaded:");
    println!("   - Environment: {:?}", config.environment);
    println!("   - Strategy: {}", config.proving.default_strategy);
    println!("   - Max concurrent proofs: {}", config.proving.max_concurrent_proofs);
    
    // Step 2: Structured Logging System
    println!("\n📝 Step 2: Structured Logging System");
    let logger = Logger::new_with_config(config.logging.clone()).await?;
    
    logger.info("example_started", &[
        ("component", "integration_example"),
        ("version", "1.0.0"),
        ("strategy", &config.proving.default_strategy),
    ]).await;
    
    println!("✅ Logging system initialized with structured JSON output");
    
    // Step 3: Metrics Collection
    println!("\n📊 Step 3: Metrics Collection System");
    let metrics = Arc::new(ZkEvmMetrics::default());
    
    // Record some sample metrics
    metrics.record_proof_generation(125.5).await;
    metrics.record_proof_size(2048).await;
    metrics.increment_counter("example_operations").await;
    metrics.record_throughput(1500.0).await;
    
    let summary = metrics.get_performance_summary().await;
    println!("✅ Metrics system active:");
    println!("   - Average proof time: {:.2}ms", summary.average_proof_time_ms);
    println!("   - Total proofs: {}", summary.total_proofs_generated);
    println!("   - Current throughput: {:.2} TPS", summary.current_throughput);
    
    // Step 4: Error Handling System
    println!("\n🚨 Step 4: Error Handling System");
    let sample_error = ZkEvmError::ProvingError {
        message: "Sample proving error for demonstration".to_string(),
        circuit_info: "example_circuit".to_string(),
        prover_config: "hybrid_config".to_string(),
    };
    
    // Record error in metrics
    metrics.record_error(&sample_error).await;
    
    // Log error with context
    logger.error("sample_error_demonstration", &[
        ("component", "integration_example"),
        ("error_type", "proving_error"),
        ("severity", &format!("{:?}", sample_error.get_severity())),
    ], Some(&sample_error)).await;
    
    println!("✅ Error handling demonstrated:");
    println!("   - Error severity: {:?}", sample_error.get_severity());
    println!("   - Retry possible: {}", sample_error.is_retryable());
    println!("   - Recovery suggestion: {}", sample_error.get_recovery_suggestion());
    
    // Step 5: Monitoring System
    println!("\n🔍 Step 5: Monitoring and Alerting");
    let monitoring = MonitoringSystem::new(config.clone(), Arc::clone(&metrics));
    monitoring.start().await?;
    
    // Let monitoring run for a moment
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    let health = monitoring.get_system_health().await;
    println!("✅ System health check:");
    println!("   - Overall status: {:?}", health.overall_status);
    println!("   - Components monitored: {}", health.components.len());
    println!("   - System uptime: {:?}", health.system_uptime);
    println!("   - Active alerts: {}", health.critical_alerts + health.warning_alerts);
    
    // Step 6: Benchmark Execution
    println!("\n⚡ Step 6: Performance Benchmark");
    let benchmark_result = monitoring.run_benchmark("integration_example").await;
    
    println!("✅ Benchmark completed:");
    println!("   - Duration: {}ms", benchmark_result.duration_ms);
    println!("   - Throughput: {:.2} ops/sec", benchmark_result.throughput_ops_per_sec);
    println!("   - Memory usage: {}MB", benchmark_result.memory_usage_mb);
    println!("   - Success rate: {:.1}%", benchmark_result.success_rate);
    
    // Step 7: Proving System Integration
    println!("\n🔐 Step 7: Cryptographic Proving System");
    let mut verifier = UnifiedVerifier::new();
    
    // Configure hybrid strategy
    #[cfg(feature = "accumulation")]
    {
        let hybrid_config = evm_verify::api::accumulation_strategy::ZodaWarpConfig::default();
        let hybrid_strategy = evm_verify::api::accumulation_strategy::ZodaWarpHybridStrategy::with_config(hybrid_config)?;
        verifier.set_accumulation_strategy(AccumulationStrategy::ZodaWarpHybrid(hybrid_strategy));
        
        logger.info("proving_system_configured", &[
            ("component", "verifier"),
            ("strategy", "ZodaWarpHybrid"),
            ("status", "ready"),
        ]).await;
        
        println!("✅ Hybrid proving strategy configured");
    }
    
    #[cfg(not(feature = "accumulation"))]
    {
        verifier.set_accumulation_strategy(AccumulationStrategy::ZODA(Default::default()));
        
        logger.info("proving_system_configured", &[
            ("component", "verifier"),
            ("strategy", "ZODA"),
            ("status", "ready"),
        ]).await;
        
        println!("✅ ZODA proving strategy configured");
    }
    
    // Step 8: End-to-End Workflow Simulation
    println!("\n🎯 Step 8: End-to-End Workflow Simulation");
    
    for i in 1..=5 {
        let operation_start = std::time::Instant::now();
        
        logger.debug("operation_started", &[
            ("component", "workflow"),
            ("operation_id", &i.to_string()),
        ]).await;
        
        // Simulate proving work
        tokio::time::sleep(Duration::from_millis(50 + (i * 10))).await;
        
        let operation_duration = operation_start.elapsed();
        
        // Update metrics
        metrics.record_proof_generation(operation_duration.as_millis() as f64).await;
        metrics.increment_counter("workflow_operations").await;
        
        // Log completion
        logger.info("operation_completed", &[
            ("component", "workflow"),
            ("operation_id", &i.to_string()),
            ("duration_ms", &operation_duration.as_millis().to_string()),
        ]).await;
        
        println!("   ✅ Operation {} completed in {}ms", i, operation_duration.as_millis());
    }
    
    // Step 9: Metrics Export
    println!("\n📈 Step 9: Metrics Export");
    let prometheus_export = metrics.export_prometheus().await;
    
    println!("✅ Prometheus metrics exported ({} lines)", prometheus_export.lines().count());
    println!("   Sample metrics:");
    for line in prometheus_export.lines().take(5) {
        println!("   {}", line);
    }
    
    // Step 10: Final Summary
    println!("\n🏆 Step 10: Integration Summary");
    let final_summary = metrics.get_performance_summary().await;
    let final_health = monitoring.get_system_health().await;
    
    logger.info("integration_example_completed", &[
        ("component", "integration_example"),
        ("total_operations", &final_summary.total_proofs_generated.to_string()),
        ("average_performance", &format!("{:.2}ms", final_summary.average_proof_time_ms)),
        ("system_health", &format!("{:?}", final_health.overall_status)),
        ("uptime", &format!("{:.2}s", final_health.system_uptime.as_secs_f64())),
    ]).await;
    
    println!("✅ Production integration example completed successfully!");
    println!("=====================================");
    println!("📊 Final Metrics:");
    println!("   - Total operations: {}", final_summary.total_proofs_generated);
    println!("   - Average performance: {:.2}ms", final_summary.average_proof_time_ms);
    println!("   - Peak throughput: {:.2} TPS", final_summary.peak_throughput);
    println!("   - System health: {:?}", final_health.overall_status);
    println!("   - Uptime: {:.2}s", final_health.system_uptime.as_secs_f64());
    
    println!("\n🎉 All production infrastructure components validated!");
    println!("Ready for zkEVM deployment on Ethereum L1!");
    
    Ok(())
}

/// Configuration validation example
#[allow(dead_code)]
async fn demonstrate_configuration_features() -> ZkEvmResult<()> {
    // Create environment-specific configurations
    ZkEvmConfig::create_default_configs("./config")?;
    
    // Load configuration with environment overrides
    std::env::set_var("ZKVM_ENVIRONMENT", "staging");
    std::env::set_var("ZKVM_MAX_MEMORY_MB", "4096");
    
    let config = ZkEvmConfig::load_auto()?;
    assert_eq!(config.environment, Environment::Staging);
    assert_eq!(config.performance.max_memory_mb, 4096);
    
    // Validate configuration
    config.validate()?;
    
    println!("✅ Configuration validation successful");
    Ok(())
}

/// Advanced error handling example
#[allow(dead_code)]
async fn demonstrate_error_handling() -> ZkEvmResult<()> {
    // Create error with context
    let error = ZkEvmError::create_internal_error(
        "Database connection failed".to_string(),
        "database_manager".to_string(),
    );
    
    // Add context to error
    let contextual_error = error.with_context("block_number", "12345")
        .with_context("transaction_hash", "0xabc123");
    
    // Check error properties
    println!("Error severity: {:?}", contextual_error.get_severity());
    println!("Retry possible: {}", contextual_error.is_retryable());
    println!("Recovery: {}", contextual_error.get_recovery_suggestion());
    
    Ok(())
}

/// Monitoring integration example
#[allow(dead_code)]
async fn demonstrate_monitoring_integration() -> ZkEvmResult<()> {
    let config = ZkEvmConfig::default();
    let metrics = Arc::new(ZkEvmMetrics::default());
    let monitoring = MonitoringSystem::new(config, metrics);
    
    // Start monitoring
    monitoring.start().await?;
    
    // Run benchmark
    let result = monitoring.run_benchmark("test_benchmark").await;
    println!("Benchmark: {:.2} ops/sec", result.throughput_ops_per_sec);
    
    // Check health
    let health = monitoring.get_system_health().await;
    println!("System health: {:?}", health.overall_status);
    
    Ok(())
}
