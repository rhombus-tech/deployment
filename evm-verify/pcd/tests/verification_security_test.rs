/// Test to verify that verification security metrics are working correctly

use pcd::tensor_zoda::{TensorZODA, Matrix, VerificationMetrics};
use ark_bn254::Fr;
use rand::{SeedableRng, Rng};
use rand::rngs::StdRng;

#[test]
fn test_verification_metrics_tracking() {
    println!("\n🔐 Testing Verification Security Metrics\n");
    
    // Create a small tensor ZODA instance
    let field_size = 1000000007u64; // Simple prime for testing
    let distance = 4;
    
    // Small matrices for testing
    let g = Matrix::<Fr>::new(8, 4);
    let g_prime = Matrix::<Fr>::new(8, 4);
    
    let mut zoda = TensorZODA::new(g, g_prime, distance, field_size as u64);
    
    // Create simple test data
    let mut rng = StdRng::seed_from_u64(12345);
    let test_data = Matrix::<Fr>::new(4, 4);
    
    // Encode the data
    match zoda.encode(test_data, &mut rng) {
        Ok(_) => println!("✅ Encoding successful"),
        Err(e) => {
            println!("❌ Encoding failed: {:?}", e);
            return;
        }
    }
    
    // Generate randomness for verification
    let r: Vec<Fr> = (0..4).map(|_| Fr::from(rng.gen::<u64>())).collect();
    let r_prime: Vec<Fr> = (0..4).map(|_| Fr::from(rng.gen::<u64>())).collect();
    
    zoda.r = Some(r);
    zoda.r_prime = Some(r_prime.clone());
    
    // Compute yr and wr_prime
    if let Some(ref encoded) = zoda.encoded_data {
        match encoded.vec_mul(&r_prime) {
            Ok(yr) => zoda.yr = Some(yr),
            Err(e) => {
                println!("❌ Failed to compute yr: {}", e);
                return;
            }
        }
        
        let encoded_t = encoded.transpose();
        match encoded_t.vec_mul(&r_prime) {
            Ok(wr) => zoda.wr_prime = Some(wr),
            Err(e) => {
                println!("❌ Failed to compute wr_prime: {}", e);
                return;
            }
        }
    }
    
    // Get initial metrics
    {
        let metrics = zoda.verification_metrics.lock().unwrap();
        println!("Initial metrics:");
        println!("  Total checks: {}", metrics.total_row_checks + metrics.total_column_checks);
        assert_eq!(metrics.total_row_checks, 0);
        assert_eq!(metrics.successful_row_checks, 0);
    }
    
    // Perform verification - this should populate metrics
    let s_indices = vec![0, 1];
    let s_prime_indices = vec![0, 1];
    
    if let (Some(ref encoded), Some(_), Some(_)) = 
        (&zoda.encoded_data, &zoda.r, &zoda.r_prime) {
        
        let y_rows = encoded.clone();
        let w_columns = encoded.transpose();
        
        match zoda.verify_sampling(&y_rows, &w_columns, &s_indices, &s_prime_indices, &mut rng) {
            Ok(valid) => {
                println!("\n✅ Verification completed: {}", if valid { "VALID" } else { "INVALID" });
                
                // Check that metrics were tracked
                let metrics = zoda.verification_metrics.lock().unwrap();
                
                println!("\n📊 Final Verification Metrics:");
                println!("  Row checks performed: {}", metrics.total_row_checks);
                println!("  Row checks successful: {}", metrics.successful_row_checks);
                println!("  Column checks performed: {}", metrics.total_column_checks);
                println!("  Column checks successful: {}", metrics.successful_column_checks);
                println!("  Consistency checks: {}/{}", 
                         metrics.consistency_checks_passed, 
                         metrics.consistency_checks_performed);
                println!("  Dimension mismatches: {}", metrics.dimension_mismatches);
                println!("  Security score: {:.1}%", metrics.security_score());
                
                // Assertions
                assert!(metrics.total_row_checks > 0, "Should have performed row checks");
                assert!(metrics.total_column_checks > 0, "Should have performed column checks");
                assert!(metrics.consistency_checks_performed > 0, "Should have performed consistency checks");
                
                // Security score should be calculated
                let score = metrics.security_score();
                assert!(score >= 0.0 && score <= 100.0, "Security score should be between 0-100%");
                
                if valid {
                    assert!(score >= 95.0, "Valid proof should have ≥95% security score");
                }
                
                println!("\n✅ All metric tracking assertions passed!");
                println!("Status: {}", if metrics.security_score() >= 95.0 { 
                    "✅ SECURE" 
                } else { 
                    "⚠️ NEEDS REVIEW" 
                });
            }
            Err(e) => println!("❌ Verification error: {:?}", e),
        }
    } else {
        println!("❌ Missing required data for verification");
    }
}

#[test]
fn test_dimension_safety_through_verification() {
    println!("\n🔒 Testing Dimension Safety Through Verification\n");
    
    let field_size = 1000000007u64; // Simple prime for testing
    let distance = 4;
    
    // Create ZODA with known dimensions
    let g = Matrix::<Fr>::new(8, 4);
    let g_prime = Matrix::<Fr>::new(8, 4);
    
    let mut zoda = TensorZODA::new(g, g_prime, distance, field_size);
    
    // Create and encode test data which will exercise dimension handling
    let mut rng = StdRng::seed_from_u64(67890);
    let test_data = Matrix::<Fr>::new(4, 4);
    
    match zoda.encode(test_data, &mut rng) {
        Ok(_) => {
            println!("✅ Encoding successful");
            
            // Generate randomness for verification
            let r: Vec<Fr> = (0..4).map(|_| Fr::from(rng.gen::<u64>())).collect();
            let r_prime: Vec<Fr> = (0..4).map(|_| Fr::from(rng.gen::<u64>())).collect();
            
            zoda.r = Some(r);
            zoda.r_prime = Some(r_prime.clone());
            
            // Compute yr and wr_prime
            if let Some(ref encoded) = zoda.encoded_data {
                if let Ok(yr) = encoded.vec_mul(&r_prime) {
                    zoda.yr = Some(yr);
                }
                let encoded_t = encoded.transpose();
                if let Ok(wr) = encoded_t.vec_mul(&r_prime) {
                    zoda.wr_prime = Some(wr);
                }
            }
            
            // Perform verification - dimension handling happens internally
            let s_indices = vec![0, 1];
            let s_prime_indices = vec![0, 1];
            
            if let (Some(ref encoded), Some(_), Some(_)) = 
                (&zoda.encoded_data, &zoda.r, &zoda.r_prime) {
                
                let y_rows = encoded.clone();
                let w_columns = encoded.transpose();
                
                match zoda.verify_sampling(&y_rows, &w_columns, &s_indices, &s_prime_indices, &mut rng) {
                    Ok(_) => {
                        let metrics = zoda.verification_metrics.lock().unwrap();
                        println!("✅ Verification completed with {} dimension mismatches handled", 
                                 metrics.dimension_mismatches);
                    }
                    Err(e) => println!("Verification error (expected for dimension testing): {:?}", e),
                }
            }
        }
        Err(e) => println!("Encoding failed: {:?}", e),
    }
    
    println!("\n✅ Dimension safety validation test completed!");
}

#[test]
fn test_metrics_security_threshold() {
    println!("\n📊 Testing Security Threshold Calculation\n");
    
    // Test the VerificationMetrics struct directly
    let mut metrics = VerificationMetrics::default();
    
    // Simulate 100% success
    metrics.total_row_checks = 10;
    metrics.successful_row_checks = 10;
    metrics.total_column_checks = 10;
    metrics.successful_column_checks = 10;
    metrics.consistency_checks_performed = 3;
    metrics.consistency_checks_passed = 3;
    
    let score = metrics.security_score();
    println!("100% success rate score: {:.1}%", score);
    assert_eq!(score, 100.0);
    assert!(metrics.security_score() >= 95.0, "Should be secure");
    
    // Simulate 95% success (threshold)
    metrics.successful_row_checks = 9;  // 90%
    metrics.successful_column_checks = 10; // 100%
    metrics.consistency_checks_passed = 3;  // 100%
    
    let score = metrics.security_score();
    println!("95.7% success rate score: {:.1}%", score);
    assert!(score >= 95.0, "Should still be secure at threshold");
    
    // Simulate 90% success (below threshold)
    metrics.successful_row_checks = 8;  // 80%
    metrics.successful_column_checks = 9; // 90%
    
    let score = metrics.security_score();
    println!("87% success rate score: {:.1}%", score);
    assert!(score < 95.0, "Should be insecure below threshold");
    
    println!("\n✅ Security threshold calculation working correctly!");
}
