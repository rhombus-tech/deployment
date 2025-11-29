/// Ultra-simple timing comparison
/// Just measure encode time without complex setup
use pcd::tensor_zoda::Matrix;
use pcd::zoda_v2::{ZODAv2, ZODAv2Config};
use ark_bn254::Fr;
use std::time::Instant;

fn main() {
    println!("\n🚀 ZODA v2 Timing Test\n");
    
    let size = 128;  // Smaller for quick test
    println!("Testing {}x{} matrix encoding...\n", size, size);
    
    // Create simple test data
    let test_data = {
        let mut data = Vec::new();
        for i in 0..size {
            let mut row = Vec::new();
            for j in 0..size {
                row.push(Fr::from((i * size + j) as u64));
            }
            data.push(row);
        }
        Matrix::from_data(data)
    };
    
    // Test 1: Standard (no optimizations)
    println!("1️⃣  Standard mode (baseline):");
    let config_standard = ZODAv2Config {
        use_binary_fields: false,
        use_simd: false,
        use_recursion: false,
        recursion_threshold: 1024,
        sub_block_size: 256,
    };
    let zoda_standard = ZODAv2::with_config(config_standard);
    
    let start = Instant::now();
    let _ = zoda_standard.prove_optimized(&test_data, size, size, 10);
    let standard_time = start.elapsed();
    println!("   Time: {:.2}ms\n", standard_time.as_secs_f64() * 1000.0);
    
    // Test 2: With all optimizations
    println!("2️⃣  Optimized mode (v2):");
    let zoda_optimized = ZODAv2::new();  // Uses all optimizations
    
    let start = Instant::now();
    let _ = zoda_optimized.prove_optimized(&test_data, size, size, 10);
    let optimized_time = start.elapsed();
    println!("   Time: {:.2}ms\n", optimized_time.as_secs_f64() * 1000.0);
    
    // Comparison
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let speedup = standard_time.as_secs_f64() / optimized_time.as_secs_f64();
    println!("📊 Speedup: {:.2}x faster with optimizations", speedup);
    
    if speedup > 1.5 {
        println!("✨ Significant improvement! ✨");
    } else if speedup > 1.1 {
        println!("✅ Good improvement!");
    } else {
        println!("📝 Similar performance (caching helps on repeated runs)");
    }
    println!();
}
