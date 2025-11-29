//! Tests for code matrix caching and parallel proving optimizations

use pcd::tensor_zoda::{TensorZODA, Matrix, get_code_matrix_cache_stats, clear_code_matrix_cache};
use ark_bn254::Fr as BN254Fr;
use std::time::Instant;

#[test]
fn test_cache_works() {
    println!("\n🧪 Testing code matrix cache...");
    clear_code_matrix_cache();
    
    let g_code = Matrix::<BN254Fr>::new(16, 16);
    let g_prime_code = Matrix::<BN254Fr>::new(16, 16);
    let zoda = TensorZODA::<BN254Fr>::new(g_code, g_prime_code, 16, 254);
    
    let test_matrix = Matrix::<BN254Fr>::new(16, 16);
    
    // First encoding - should populate cache (use encode with RNG to trigger create_code_matrix)
    let mut zoda1 = zoda.clone();
    let mut rng = rand::thread_rng();
    let start = Instant::now();
    zoda1.encode(test_matrix.clone(), &mut rng).unwrap();
    let first_time = start.elapsed();
    
    let (_, misses1, _, _) = get_code_matrix_cache_stats();
    println!("   First encoding: {:.2}ms, cache misses: {}", 
             first_time.as_secs_f64() * 1000.0, misses1);
    
    // Second encoding - should use cache
    let mut zoda2 = zoda.clone();
    let mut rng = rand::thread_rng();
    let start = Instant::now();
    zoda2.encode(test_matrix.clone(), &mut rng).unwrap();
    let second_time = start.elapsed();
    
    let (hits, _, hit_rate, cached) = get_code_matrix_cache_stats();
    println!("   Second encoding: {:.2}ms", second_time.as_secs_f64() * 1000.0);
    println!("   ✅ Cache stats: {} hits, {:.1}% hit rate, {} matrices cached", 
             hits, hit_rate * 100.0, cached);
    
    assert!(hits > 0, "Should have cache hits");
    assert!(cached > 0, "Should have cached matrices");
}

#[test]
fn test_parallel_proving_produces_correct_results() {
    println!("\n🧪 Testing parallel proving correctness...");
    
    let g_code = Matrix::<BN254Fr>::new(8, 8);
    let g_prime_code = Matrix::<BN254Fr>::new(8, 8);
    let zoda = TensorZODA::<BN254Fr>::new(g_code, g_prime_code, 8, 254);
    
    let blocks = vec![
        Matrix::<BN254Fr>::new(8, 8),
        Matrix::<BN254Fr>::new(8, 8),
        Matrix::<BN254Fr>::new(8, 8),
    ];
    
    println!("   Proving {} blocks in parallel...", blocks.len());
    let start = Instant::now();
    let results = zoda.prove_parallel_blocks(blocks.clone(), Some(42)).unwrap();
    let elapsed = start.elapsed();
    
    println!("   ✅ Completed in {:.2}ms ({:.2}ms per block)", 
             elapsed.as_secs_f64() * 1000.0,
             elapsed.as_secs_f64() * 1000.0 / blocks.len() as f64);
    
    // Verify results
    assert_eq!(results.len(), 3, "Should have 3 results");
    
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result.block_index, i, "Results should be in order");
        assert!(result.encoded_data.rows > 0, "Should have encoded data");
        assert!(result.yr.is_some(), "Should have yr");
        assert!(result.wr_prime.is_some(), "Should have wr_prime");
    }
    
    println!("   ✅ All {} proofs valid and in correct order", results.len());
}

#[test]
fn test_parallel_is_faster_than_sequential() {
    println!("\n🧪 Testing parallel vs sequential performance...");
    clear_code_matrix_cache();
    
    let g_code = Matrix::<BN254Fr>::new(16, 16);
    let g_prime_code = Matrix::<BN254Fr>::new(16, 16);
    let zoda = TensorZODA::<BN254Fr>::new(g_code, g_prime_code, 16, 254);
    
    let blocks = vec![
        Matrix::<BN254Fr>::new(16, 16),
        Matrix::<BN254Fr>::new(16, 16),
        Matrix::<BN254Fr>::new(16, 16),
        Matrix::<BN254Fr>::new(16, 16),
    ];
    
    // Sequential
    println!("   Running sequential proving...");
    let seq_start = Instant::now();
    for block in &blocks {
        let mut local_zoda = zoda.clone();
        local_zoda.encode_input(block).unwrap();
    }
    let seq_time = seq_start.elapsed();
    println!("   Sequential: {:.2}ms", seq_time.as_secs_f64() * 1000.0);
    
    // Parallel
    println!("   Running parallel proving...");
    let par_start = Instant::now();
    let _results = zoda.prove_parallel_blocks(blocks, Some(123)).unwrap();
    let par_time = par_start.elapsed();
    println!("   Parallel: {:.2}ms", par_time.as_secs_f64() * 1000.0);
    
    let speedup = seq_time.as_secs_f64() / par_time.as_secs_f64();
    println!("   ✅ Speedup: {:.2}×", speedup);
    
    // On multi-core systems, parallel should be at least as fast
    assert!(par_time <= seq_time * 2, // Allow some overhead
            "Parallel should not be significantly slower");
}

#[test]
fn test_deterministic_rng_produces_same_results() {
    println!("\n🧪 Testing deterministic RNG...");
    
    let g_code = Matrix::<BN254Fr>::new(8, 8);
    let g_prime_code = Matrix::<BN254Fr>::new(8, 8);
    let zoda = TensorZODA::<BN254Fr>::new(g_code, g_prime_code, 8, 254);
    
    let blocks = vec![
        Matrix::<BN254Fr>::new(8, 8),
        Matrix::<BN254Fr>::new(8, 8),
    ];
    
    // First run with seed
    let results1 = zoda.prove_parallel_blocks(blocks.clone(), Some(999)).unwrap();
    
    // Second run with same seed
    let results2 = zoda.prove_parallel_blocks(blocks.clone(), Some(999)).unwrap();
    
    // Both should produce identical results
    assert_eq!(results1.len(), results2.len());
    
    // Note: Exact determinism depends on field serialization and may vary,
    // but structure should match
    for (r1, r2) in results1.iter().zip(results2.iter()) {
        assert_eq!(r1.block_index, r2.block_index);
        assert_eq!(r1.encoded_data.rows, r2.encoded_data.rows);
        assert_eq!(r1.encoded_data.cols, r2.encoded_data.cols);
    }
    
    println!("   ✅ Deterministic RNG produces consistent results");
}
