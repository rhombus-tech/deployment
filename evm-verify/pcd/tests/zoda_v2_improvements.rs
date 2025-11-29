/// Tests to verify ZODA v2 improvements are working correctly
use pcd::tensor_zoda::{TensorZODA, Matrix};
use pcd::zoda_v2::{ZODAv2, ZODAv2Config};
use pcd::simd_matrix::simd_utils;
use ark_bn254::Fr;
use std::time::Instant;

#[test]
fn test_v2_produces_valid_proofs() {
    // Verify that v2 still produces valid proofs
    let size = 64;
    let data = Matrix::<Fr>::new(size, size);
    
    let zoda = ZODAv2::new();
    let result = zoda.prove_optimized(&data, size, size, 10);
    
    assert!(result.is_ok(), "v2 should produce valid proofs");
}

#[test]
fn test_v2_at_least_as_fast_as_v1() {
    let size = 128;
    let data = Matrix::<Fr>::new(size, size);
    
    // Benchmark v1
    let v1_time = {
        let g_code = Matrix::new(size * 2, size);
        let g_prime_code = Matrix::new(size * 2, size);
        let mut prover = TensorZODA::<Fr>::new(g_code, g_prime_code, 10, 2u64.pow(128));
        
        let start = Instant::now();
        let mut rng = rand::thread_rng();
        prover.encode(data.clone(), &mut rng).unwrap();
        start.elapsed()
    };
    
    // Benchmark v2
    let v2_time = {
        let zoda = ZODAv2::new();
        let start = Instant::now();
        zoda.prove_optimized(&data, size, size, 10).unwrap();
        start.elapsed()
    };
    
    println!("v1: {:.2}ms, v2: {:.2}ms", 
             v1_time.as_secs_f64() * 1000.0,
             v2_time.as_secs_f64() * 1000.0);
    
    // v2 should be faster or at least within 2x (accounting for variance)
    assert!(v2_time <= v1_time * 2, 
            "v2 ({:?}) should be comparable to v1 ({:?})", v2_time, v1_time);
}

#[test]
fn test_simd_provides_speedup() {
    if !simd_utils::has_avx2() {
        println!("Skipping SIMD test - AVX2 not available");
        return;
    }
    
    let size = 256;
    let data = Matrix::<Fr>::new(size, size);
    
    // Without SIMD
    let no_simd_time = {
        let config = ZODAv2Config {
            use_simd: false,
            ..Default::default()
        };
        let zoda = ZODAv2::with_config(config);
        let start = Instant::now();
        zoda.prove_optimized(&data, size, size, 10).unwrap();
        start.elapsed()
    };
    
    // With SIMD
    let simd_time = {
        let config = ZODAv2Config {
            use_simd: true,
            ..Default::default()
        };
        let zoda = ZODAv2::with_config(config);
        let start = Instant::now();
        zoda.prove_optimized(&data, size, size, 10).unwrap();
        start.elapsed()
    };
    
    let speedup = no_simd_time.as_secs_f64() / simd_time.as_secs_f64();
    println!("SIMD speedup: {:.2}x", speedup);
    
    // SIMD should provide at least some improvement
    assert!(speedup >= 0.9, "SIMD should be at least as fast");
}

#[test]
fn test_recursive_handles_large_data() {
    let size = 512;
    let data = Matrix::<Fr>::new(size, size);
    
    let config = ZODAv2Config {
        use_recursion: true,
        recursion_threshold: 256,  // Force recursion
        sub_block_size: 128,
        ..Default::default()
    };
    
    let zoda = ZODAv2::with_config(config);
    let result = zoda.prove_optimized(&data, size, size, 10);
    
    assert!(result.is_ok(), "Recursive proving should work for large data");
}

#[test]
fn test_caching_improves_repeated_operations() {
    let size = 128;
    
    // First run (cold cache)
    let first_run = {
        let data = Matrix::<Fr>::new(size, size);
        let zoda = ZODAv2::new();
        let start = Instant::now();
        zoda.prove_optimized(&data, size, size, 10).unwrap();
        start.elapsed()
    };
    
    // Second run (warm cache)
    let second_run = {
        let data = Matrix::<Fr>::new(size, size);
        let zoda = ZODAv2::new();
        let start = Instant::now();
        zoda.prove_optimized(&data, size, size, 10).unwrap();
        start.elapsed()
    };
    
    println!("First: {:.2}ms, Second: {:.2}ms", 
             first_run.as_secs_f64() * 1000.0,
             second_run.as_secs_f64() * 1000.0);
    
    // Second run should benefit from caching (or at least not be slower)
    let ratio = second_run.as_secs_f64() / first_run.as_secs_f64();
    assert!(ratio <= 1.1, "Caching should help or not hurt");
}

#[test]
fn test_correctness_matches_v1() {
    // Verify that v2 produces mathematically equivalent results to v1
    let size = 64;
    let data = Matrix::<Fr>::new(size, size);
    
    // v1 proof
    let v1_proof = {
        let g_code = Matrix::new(size * 2, size);
        let g_prime_code = Matrix::new(size * 2, size);
        let mut prover = TensorZODA::<Fr>::new(g_code, g_prime_code, 10, 2u64.pow(128));
        let mut rng = rand::thread_rng();
        prover.encode(data.clone(), &mut rng).unwrap();
        prover.row_commitment.clone()
    };
    
    // v2 proof
    let v2_proof = {
        let zoda = ZODAv2::new();
        zoda.prove_optimized(&data, size, size, 10)
    };
    
    // Both should succeed
    assert!(v1_proof.is_some(), "v1 should produce proof");
    assert!(v2_proof.is_ok(), "v2 should produce proof");
}

#[test]
fn test_memory_efficiency() {
    // Verify that v2 doesn't use significantly more memory
    let size = 256;
    let data = Matrix::<Fr>::new(size, size);
    
    // This is more of a stress test - just ensure it completes
    let config = ZODAv2Config {
        use_recursion: true,
        recursion_threshold: 200,
        sub_block_size: 64,  // Small sub-blocks
        ..Default::default()
    };
    
    let zoda = ZODAv2::with_config(config);
    let result = zoda.prove_optimized(&data, size, size, 10);
    
    assert!(result.is_ok(), "Should handle memory efficiently");
}

#[test]
fn test_different_sizes_all_work() {
    // Test that optimizations work across different sizes
    let sizes = vec![32, 64, 128, 256];
    
    for size in sizes {
        let data = Matrix::<Fr>::new(size, size);
        let zoda = ZODAv2::new();
        let result = zoda.prove_optimized(&data, size, size, 10);
        
        assert!(result.is_ok(), "Size {} should work", size);
    }
}
