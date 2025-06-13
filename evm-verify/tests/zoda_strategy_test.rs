use anyhow::Result;
use evm_verify::api::unified::UnifiedVerifier;
use evm_verify::api::accumulation_strategy::VerificationStrategy;
use std::time::Instant;

/// Test bytecode with a reentrancy vulnerability
fn get_vulnerable_bytecode() -> Vec<u8> {
    // Simple bytecode that simulates a contract with reentrancy vulnerability
    let mut bytecode = vec![];
    
    // Create larger bytecode to better demonstrate ZODA's advantages
    // This simulates a more realistic contract with repeated patterns
    for i in 0..50 {
        // PUSH1 values (simulating various operations)
        bytecode.push(0x60);
        bytecode.push(i as u8);
        
        // PUSH1 another value
        bytecode.push(0x60);
        bytecode.push((i + 1) as u8);
        
        // ADD operations (potential overflow)
        bytecode.push(0x01);
        
        // MUL operations
        bytecode.push(0x02);
        
        // Different storage operations
        if i % 3 == 0 {
            // SSTORE
            bytecode.push(0x55);
        }
        
        // External calls (potential reentrancy)
        if i % 5 == 0 {
            bytecode.push(0xF1); // CALL
        }
        
        // Occasionally add a SELFDESTRUCT
        if i % 20 == 0 {
            bytecode.push(0xFF);
        }
    }
    
    bytecode
}

#[test]
fn test_groth16_strategy() -> Result<()> {
    // Create a verifier with Groth16 strategy
    let verifier = UnifiedVerifier::with_strategy(VerificationStrategy::Groth16);

    // Analyze bytecode with a reentrancy vulnerability
    let bytecode = get_vulnerable_bytecode();
    let result = verifier.analyze_bytecode(&bytecode)?;

    // Print the result for debugging
    println!("Groth16 analysis result: {:?}", result);

    // Verify that we found at least one vulnerability
    assert!(!result.vulnerabilities.is_empty());
    
    Ok(())
}

#[test]
fn test_zoda_strategy() -> Result<()> {
    // Create a verifier with ZODA strategy in test mode (with smaller matrix dimensions)
    let verifier = UnifiedVerifier::with_zoda_test_mode();

    // Analyze bytecode with a reentrancy vulnerability
    let bytecode = get_vulnerable_bytecode();
    
    // With our improved implementation in test mode, this should now succeed
    let result = verifier.analyze_bytecode(&bytecode)?;
    
    // Print the result for debugging
    println!("ZODA analysis result: {:?}", result);

    // Verify that we found at least one vulnerability
    assert!(!result.vulnerabilities.is_empty());
    
    // Verify the first vulnerability is reentrancy
    let first_vuln = result.vulnerabilities.first();
    assert!(first_vuln.is_some());
    assert!(first_vuln.unwrap().title.to_lowercase().contains("reentrancy"));
    
    // Get the performance metrics
    let (setup_time, verification_time, circuit_count) = verifier.get_accumulation_metrics();
    println!("ZODA performance metrics:");
    println!(" - Setup time: {:?}", setup_time);
    println!(" - Verification time: {:?}", verification_time);
    println!(" - Circuit count: {}", circuit_count);
    
    Ok(())
}

#[test]
fn test_compare_strategies() -> Result<()> {
    println!("===== BENCHMARKING GROTH16 VS ZODA WITH LARGER BYTECODE =====\n");
    
    let bytecode = get_vulnerable_bytecode();
    println!("Bytecode size: {} bytes\n", bytecode.len());
    
    // Number of iterations for more accurate benchmarking
    let iterations = 5;
    
    // ===== GROTH16 BENCHMARKING =====
    println!("GROTH16 BENCHMARKING:");
    println!("---------------------");
    
    // Initialize Groth16 verifier once
    let groth16_init_start = Instant::now();
    let groth16_verifier = UnifiedVerifier::with_strategy(VerificationStrategy::Groth16);
    let groth16_init_time = groth16_init_start.elapsed();
    println!("Groth16 initialization time: {:?}", groth16_init_time);
    
    // Run multiple Groth16 analysis iterations
    let mut groth16_analysis_times = Vec::with_capacity(iterations);
    let mut groth16_vulnerability_count = 0;
    
    for i in 0..iterations {
        println!("Groth16 iteration {}/{}", i + 1, iterations);
        let start = Instant::now();
        let result = groth16_verifier.analyze_bytecode(&bytecode)?;
        let elapsed = start.elapsed();
        groth16_analysis_times.push(elapsed);
        groth16_vulnerability_count = result.vulnerabilities.len();
    }
    
    // Calculate average Groth16 analysis time
    let groth16_total_analysis_time: u128 = groth16_analysis_times.iter().map(|t| t.as_nanos()).sum();
    let groth16_avg_analysis_time = groth16_total_analysis_time as f64 / iterations as f64;
    println!("Groth16 vulnerabilities found: {}", groth16_vulnerability_count);
    println!("Groth16 average analysis time: {:.3} ms", groth16_avg_analysis_time / 1_000_000.0);
    
    // ===== ZODA BENCHMARKING =====
    println!("\nZODA BENCHMARKING:");
    println!("-----------------");
    
    // Initialize ZODA verifier once
    let zoda_init_start = Instant::now();
    let zoda_verifier = UnifiedVerifier::with_zoda_test_mode();
    let zoda_init_time = zoda_init_start.elapsed();
    println!("ZODA initialization time: {:?}", zoda_init_time);
    
    // Run multiple ZODA analysis iterations
    let mut zoda_analysis_times = Vec::with_capacity(iterations);
    let mut zoda_vulnerability_count = 0;
    
    for i in 0..iterations {
        println!("ZODA iteration {}/{}", i + 1, iterations);
        let start = Instant::now();
        let result = zoda_verifier.analyze_bytecode(&bytecode)?;
        let elapsed = start.elapsed();
        zoda_analysis_times.push(elapsed);
        zoda_vulnerability_count = result.vulnerabilities.len();
    }
    
    // Calculate average ZODA analysis time
    let zoda_total_analysis_time: u128 = zoda_analysis_times.iter().map(|t| t.as_nanos()).sum();
    let zoda_avg_analysis_time = zoda_total_analysis_time as f64 / iterations as f64;
    println!("ZODA vulnerabilities found: {}", zoda_vulnerability_count);
    println!("ZODA average analysis time: {:.3} ms", zoda_avg_analysis_time / 1_000_000.0);
    
    // Get internal performance metrics from ZODA
    let (setup_time, verification_time, circuit_count) = zoda_verifier.get_accumulation_metrics();
    println!("ZODA internal setup time: {:?}", setup_time);
    println!("ZODA internal verification time: {:?}", verification_time);
    println!("ZODA circuits processed: {}", circuit_count);
    
    // ===== PERFORMANCE COMPARISON =====
    println!("\nPERFORMANCE COMPARISON:");
    println!("----------------------");
    
    // Compare initialization times
    if zoda_init_time < groth16_init_time {
        let init_speedup = groth16_init_time.as_nanos() as f64 / zoda_init_time.as_nanos() as f64;
        println!("ZODA initialization is {:.2}x faster than Groth16", init_speedup);
    } else {
        let init_slowdown = zoda_init_time.as_nanos() as f64 / groth16_init_time.as_nanos() as f64;
        println!("ZODA initialization is {:.2}x slower than Groth16", init_slowdown);
    }
    
    // Compare analysis times
    if zoda_avg_analysis_time < groth16_avg_analysis_time {
        let analysis_speedup = groth16_avg_analysis_time / zoda_avg_analysis_time;
        println!("ZODA analysis is {:.2}x faster than Groth16", analysis_speedup);
    } else {
        let analysis_slowdown = zoda_avg_analysis_time / groth16_avg_analysis_time;
        println!("ZODA analysis is {:.2}x slower than Groth16", analysis_slowdown);
    }
    
    Ok(())
}
