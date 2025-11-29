/// Simple side-by-side comparison of ZODA v1 vs v2
/// Run with: cargo run --example v1_vs_v2_comparison --release
use pcd::tensor_zoda::{TensorZODA, Matrix};
use pcd::zoda_v2::ZODAv2;
use ark_bn254::Fr;
use ark_ff::Field;
use std::time::Instant;

fn main() {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║      Quick Comparison: ZODA v1 → ZODA v2              ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    // Test with 256x256 matrix (typical use case)
    let size = 256;
    println!("Testing with {}x{} matrix (~2MB of data)\n", size, size);
    
    // Prepare test data - create a matrix with random field elements
    let test_data = {
        let mut data = Vec::new();
        for _ in 0..size {
            let mut row = Vec::new();
            for _ in 0..size {
                row.push(Fr::from(rand::random::<u64>()));
            }
            data.push(row);
        }
        Matrix::from_data(data)
    };
    
    // Version 1 (Original)
    println!("⏱️  Running ZODA v1 (original)...");
    let v1_start = Instant::now();
    run_zoda_v1(&test_data, size);
    let v1_time = v1_start.elapsed();
    println!("   ✅ Complete: {:.2}ms\n", v1_time.as_secs_f64() * 1000.0);
    
    // Version 2 (Optimized)
    println!("⏱️  Running ZODA v2 (optimized)...");
    let v2_start = Instant::now();
    run_zoda_v2(&test_data, size);
    let v2_time = v2_start.elapsed();
    println!("   ✅ Complete: {:.2}ms\n", v2_time.as_secs_f64() * 1000.0);
    
    // Show comparison
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Results:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("   ZODA v1:  {:.2}ms", v1_time.as_secs_f64() * 1000.0);
    println!("   ZODA v2:  {:.2}ms", v2_time.as_secs_f64() * 1000.0);
    println!();
    
    let speedup = v1_time.as_secs_f64() / v2_time.as_secs_f64();
    let improvement = ((v1_time.as_secs_f64() - v2_time.as_secs_f64()) / v1_time.as_secs_f64() * 100.0);
    
    println!("   🚀 Speedup:     {:.2}x faster", speedup);
    println!("   📈 Improvement: {:.1}% faster", improvement);
    println!("   ⏰ Time saved:  {:.2}ms", (v1_time - v2_time).as_secs_f64() * 1000.0);
    println!();
    
    // Throughput
    let data_mb = (size * size * 32) as f64 / 1_000_000.0;
    println!("   v1 throughput: {:.1} MB/s", data_mb / v1_time.as_secs_f64());
    println!("   v2 throughput: {:.1} MB/s", data_mb / v2_time.as_secs_f64());
    println!();
    
    if speedup > 1.5 {
        println!("   ✨ ZODA v2 is significantly faster! ✨");
    } else if speedup > 1.1 {
        println!("   ✅ ZODA v2 shows good improvement!");
    } else {
        println!("   📝 Results are similar (caching may help on repeated runs)");
    }
    
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

fn run_zoda_v1(data: &Matrix<Fr>, size: usize) {
    use pcd::reed_solomon::ReedSolomon;
    
    let distance = 10;
    let field_size = 2u64.pow(128);
    let error_capacity = (distance / 3).max(1);
    
    // Create Reed-Solomon code matrices (same as v1 does internally)
    let rs: ReedSolomon<Fr> = ReedSolomon::new(field_size, error_capacity);
    let g_code = Matrix::from_data(rs.generate_code_matrix(size * 2, size));
    let g_prime_code = Matrix::from_data(rs.generate_code_matrix(size * 2, size));
    
    let mut prover = TensorZODA::<Fr>::new(g_code, g_prime_code, distance, field_size);
    
    // Use the encode_input helper which handles rng internally
    let _ = prover.encode_input(data);
}

fn run_zoda_v2(data: &Matrix<Fr>, size: usize) {
    let zoda = ZODAv2::new();  // Automatically uses all available optimizations
    let _ = zoda.prove_optimized(data, size, size, 10);
}
