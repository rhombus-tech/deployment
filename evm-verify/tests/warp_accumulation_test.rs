use anyhow::Result;
use evm_verify::api::accumulation_strategy::{WarpStrategy, ZODAStrategy};
use std::time::Instant;

/// Test WARP batch accumulation functionality
#[test]
fn test_warp_batch_accumulation() -> Result<()> {
    println!("🧪 Testing WARP Batch Accumulation Implementation");
    
    // Create test proof inputs
    let test_inputs = vec![
        vec![0x60, 0x80, 0x60, 0x40], // Sample EVM bytecode
        vec![0x60, 0x00, 0x35, 0x80], // Another sample
        vec![0x63, 0x12, 0x34, 0x56], // PUSH4 instruction
        vec![0x7f, 0xff, 0xff, 0xff], // PUSH32 prefix
        vec![0x00, 0x01, 0x02, 0x03], // Simple data
    ];
    
    // Test WarpStrategy accumulation
    let mut warp_strategy = WarpStrategy::new();
    let start_time = Instant::now();
    let warp_result = warp_strategy.accumulate_batch(&test_inputs)?;
    let warp_time = start_time.elapsed();
    
    println!("✅ WARP accumulation: {} inputs → {} bytes in {:?}", 
             test_inputs.len(), warp_result.len(), warp_time);
    
    // Validate result structure
    assert!(!warp_result.is_empty(), "WARP result should not be empty");
    assert!(warp_result.len() >= 24, "WARP result should include header + commitment");
    
    // Test ZODAStrategy accumulation
    let mut zoda_strategy = ZODAStrategy::new();
    let start_time = Instant::now();
    let zoda_result = zoda_strategy.accumulate_batch(&test_inputs)?;
    let zoda_time = start_time.elapsed();
    
    println!("✅ ZODA accumulation: {} inputs → {} bytes in {:?}", 
             test_inputs.len(), zoda_result.len(), zoda_time);
    
    // Validate result structure
    assert!(!zoda_result.is_empty(), "ZODA result should not be empty");
    assert!(zoda_result.len() >= 24, "ZODA result should include header + commitment");
    
    // Test performance requirements
    assert!(warp_time.as_millis() < 100, "WARP accumulation should be under 100ms");
    assert!(zoda_time.as_millis() < 100, "ZODA accumulation should be under 100ms");
    
    // Test proof size requirements (should be compact)
    assert!(warp_result.len() < 300, "WARP proof should be under 300 bytes");
    assert!(zoda_result.len() < 300, "ZODA proof should be under 300 bytes");
    
    println!("🎉 All WARP batch accumulation tests passed!");
    Ok(())
}

/// Benchmark WARP accumulation performance with different batch sizes
#[test]
fn benchmark_warp_accumulation_performance() -> Result<()> {
    println!("📊 Benchmarking WARP Accumulation Performance");
    
    // Test with different batch sizes
    let batch_sizes = vec![1, 5, 10, 25, 50, 100];
    
    for &size in &batch_sizes {
        // Generate test inputs
        let test_inputs: Vec<Vec<u8>> = (0..size)
            .map(|i| vec![0x60 + (i % 32) as u8, 0x80, 0x60, 0x40])
            .collect();
        
        // Benchmark WARP accumulation
        let mut warp_strategy = WarpStrategy::new();
        let start_time = Instant::now();
        let result = warp_strategy.accumulate_batch(&test_inputs)?;
        let duration = start_time.elapsed();
        
        let throughput = size as f64 / duration.as_secs_f64();
        
        println!("📈 Batch size: {:<3} | Time: {:>8.2}ms | Size: {:>3} bytes | Throughput: {:>6.1} proofs/sec", 
                 size, 
                 duration.as_millis(),
                 result.len(),
                 throughput);
        
        // Validate performance requirements
        assert!(duration.as_millis() < size as u128 * 10, "Should be under 10ms per proof");
        assert!(result.len() < 500, "Accumulated proof should stay compact");
    }
    
    println!("🎉 Performance benchmarks completed successfully!");
    Ok(())
}

/// Test edge cases for WARP accumulation
#[test]
fn test_warp_accumulation_edge_cases() -> Result<()> {
    println!("🧪 Testing WARP Accumulation Edge Cases");
    
    let mut warp_strategy = WarpStrategy::new();
    let mut zoda_strategy = ZODAStrategy::new();
    
    // Test empty input
    let empty_inputs: Vec<Vec<u8>> = vec![];
    let empty_result = warp_strategy.accumulate_batch(&empty_inputs)?;
    assert!(empty_result.is_empty(), "Empty input should produce empty result");
    
    // Test single input
    let single_input = vec![vec![0x60, 0x80]];
    let single_result = warp_strategy.accumulate_batch(&single_input)?;
    assert!(!single_result.is_empty(), "Single input should produce valid result");
    
    // Test inputs with empty vectors
    let mixed_inputs = vec![
        vec![0x60, 0x80],
        vec![], // Empty vector
        vec![0x35, 0x80],
    ];
    let mixed_result = warp_strategy.accumulate_batch(&mixed_inputs)?;
    assert!(!mixed_result.is_empty(), "Mixed inputs should produce valid result");
    
    // Test large input
    let large_input = vec![vec![0u8; 1000]; 10];
    let large_result = warp_strategy.accumulate_batch(&large_input)?;
    assert!(!large_result.is_empty(), "Large input should be handled");
    assert!(large_result.len() < 1000, "Large input should still produce compact result");
    
    println!("✅ All edge case tests passed!");
    Ok(())
}
