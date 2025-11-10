use std::time::Instant;
use evm_verify::crypto::constant_time_matrix::{ConstantTimeMatrix, ConstantTimeFieldElement, ConstantTimeUtils};

fn main() {
    println!("Testing Constant Time Matrix Operations");
    println!("=====================================");
    
    test_field_operations();
    test_matrix_operations();
    test_timing_consistency();
    test_security_utilities();
}

fn test_field_operations() {
    println!("\n🔧 Testing Field Operations:");
    
    let modulus = 2147483647; // Large prime
    let a = ConstantTimeFieldElement::new(12345, modulus);
    let b = ConstantTimeFieldElement::new(67890, modulus);
    
    let sum = a.add(&b);
    let product = a.multiply(&b);
    
    println!("  ✓ Addition: {} + {} = {}", a.value(), b.value(), sum.value());
    println!("  ✓ Multiplication: {} * {} = {}", a.value(), b.value(), product.value());
    
    // Test constant-time conditional selection
    let selected = ConstantTimeFieldElement::conditional_select(true, &a, &b);
    println!("  ✓ Conditional select (true): {}", selected.value());
    
    let selected_false = ConstantTimeFieldElement::conditional_select(false, &a, &b);
    println!("  ✓ Conditional select (false): {}", selected_false.value());
}

fn test_matrix_operations() {
    println!("\n📊 Testing Matrix Operations:");
    
    let modulus = 97; // Small prime for testing
    
    let data_a = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
    ];
    
    let data_b = vec![
        vec![7, 8],
        vec![9, 10],
        vec![11, 12],
    ];
    
    let matrix_a = ConstantTimeMatrix::from_data(data_a, modulus).unwrap();
    let matrix_b = ConstantTimeMatrix::from_data(data_b, modulus).unwrap();
    
    println!("  Matrix A: 2x3, Matrix B: 3x2");
    
    let result = matrix_a.multiply(&matrix_b).unwrap();
    println!("  ✓ Matrix multiplication successful");
    println!("  Result dimensions: {:?}", result.dimensions());
    
    // Print some results
    println!("  Result[0,0]: {}", result.get_element(0, 0).value());
    println!("  Result[0,1]: {}", result.get_element(0, 1).value());
    
    // Test matrix addition
    let square_a = ConstantTimeMatrix::from_data(vec![vec![1, 2], vec![3, 4]], modulus).unwrap();
    let square_b = ConstantTimeMatrix::from_data(vec![vec![5, 6], vec![7, 8]], modulus).unwrap();
    
    let sum_result = square_a.add(&square_b).unwrap();
    println!("  ✓ Matrix addition successful");
    println!("  Sum[0,0]: {}", sum_result.get_element(0, 0).value());
}

fn test_timing_consistency() {
    println!("\n⏱️  Testing Timing Consistency:");
    
    let modulus = 2147483647;
    let iterations = 1000;
    
    // Test constant-time field operations with different values
    let mut times_small = Vec::new();
    let mut times_large = Vec::new();
    
    let small_val = ConstantTimeFieldElement::new(1, modulus);
    let large_val = ConstantTimeFieldElement::new(modulus - 1, modulus);
    
    // Measure small value operations
    for _ in 0..iterations {
        let start = Instant::now();
        let _result = small_val.multiply(&small_val);
        times_small.push(start.elapsed().as_nanos());
    }
    
    // Measure large value operations
    for _ in 0..iterations {
        let start = Instant::now();
        let _result = large_val.multiply(&large_val);
        times_large.push(start.elapsed().as_nanos());
    }
    
    let avg_small: f64 = times_small.iter().map(|&x| x as f64).sum::<f64>() / iterations as f64;
    let avg_large: f64 = times_large.iter().map(|&x| x as f64).sum::<f64>() / iterations as f64;
    
    println!("  Small values avg time: {:.2} ns", avg_small);
    println!("  Large values avg time: {:.2} ns", avg_large);
    
    let timing_ratio = avg_large / avg_small;
    println!("  Timing ratio (large/small): {:.3}", timing_ratio);
    
    if timing_ratio < 1.5 && timing_ratio > 0.67 {
        println!("  ✓ Timing appears consistent (ratio within acceptable range)");
    } else {
        println!("  ⚠️  Timing variance detected (may indicate timing vulnerabilities)");
    }
}

fn test_security_utilities() {
    println!("\n🛡️  Testing Security Utilities:");
    
    // Test secure memory comparison
    let data_a = b"secret_key_123456789";
    let data_b = b"secret_key_123456789";
    let data_c = b"different_key_123456";
    
    let same = ConstantTimeUtils::secure_compare(data_a, data_b);
    let different = ConstantTimeUtils::secure_compare(data_a, data_c);
    
    println!("  ✓ Secure compare (same): {}", same);
    println!("  ✓ Secure compare (different): {}", different);
    
    // Test conditional swap
    let mut x = 42u64;
    let mut y = 84u64;
    
    println!("  Before swap: x={}, y={}", x, y);
    ConstantTimeUtils::conditional_swap(true, &mut x, &mut y);
    println!("  After conditional swap (true): x={}, y={}", x, y);
    
    // Test secure memory clearing
    let mut sensitive_data = vec![0xAA; 32];
    println!("  Before secure zero: first byte = 0x{:02X}", sensitive_data[0]);
    ConstantTimeUtils::secure_zero(&mut sensitive_data);
    println!("  After secure zero: first byte = 0x{:02X}", sensitive_data[0]);
    
    println!("\n✅ All constant-time tests completed!");
}
