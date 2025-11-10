use pcd::tensor_zoda::{ExtractableCommitment, CommitmentType, Matrix};
use ark_bn254::Fr as BN254Fr;
use ark_ff::Field;
use rand::thread_rng;

fn main() {
    println!("=== zkEVM Economic Masking Demonstration ===\n");
    
    let mut rng = thread_rng();
    let mut matrix = Matrix::<BN254Fr>::new(4, 4);
    
    // Fill with sample tensor data
    for i in 0..4 {
        for j in 0..4 {
            matrix.data[i][j] = BN254Fr::from((i * 4 + j + 1) as u64);
        }
    }
    
    println!("Testing different masking security levels:\n");
    
    // Test StandardHiding (Investigation accessible)
    let standard_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::StandardHiding,
        &mut rng,
    );
    
    println!("🔒 StandardHiding Commitment:");
    println!("  Security Bits: {}", standard_commit.security_bits);
    println!("  Hiding: {}", standard_commit.is_hiding());
    println!("  Binding: {}", standard_commit.is_binding());
    println!("  Unmasking Cost: ${:.0}", standard_commit.unmasking_cost_estimate());
    println!("  Rational for $10M investigation: {}", 
             standard_commit.is_unmasking_rational(10_000_000.0));
    println!("  Rational for $100K attack: {}\n", 
             standard_commit.is_unmasking_rational(100_000.0));
    
    // Test Hiding (Nation-state level)
    let hiding_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::Hiding,
        &mut rng,
    );
    
    println!("🔐 Hiding Commitment:");
    println!("  Security Bits: {}", hiding_commit.security_bits);
    println!("  Hiding: {}", hiding_commit.is_hiding());
    println!("  Binding: {}", hiding_commit.is_binding());
    println!("  Unmasking Cost: ${:.0}", hiding_commit.unmasking_cost_estimate());
    println!("  Rational for $10B government: {}", 
             hiding_commit.is_unmasking_rational(10_000_000_000.0));
    println!("  Rational for $1M corporate: {}\n", 
             hiding_commit.is_unmasking_rational(1_000_000.0));
    
    // Test StrongHiding (Physically impossible)
    let strong_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::StrongHiding,
        &mut rng,
    );
    
    println!("🛡️  StrongHiding Commitment:");
    println!("  Security Bits: {}", strong_commit.security_bits);
    println!("  Hiding: {}", strong_commit.is_hiding());
    println!("  Binding: {}", strong_commit.is_binding());
    println!("  Unmasking Cost: ${}", strong_commit.unmasking_cost_estimate());
    println!("  Rational for any finite budget: {}\n", 
             strong_commit.is_unmasking_rational(f64::MAX));
    
    // Test Extractable (Trapdoor access)
    let extractable_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::Extractable,
        &mut rng,
    );
    
    println!("🔑 Extractable Commitment:");
    println!("  Security Bits: {}", extractable_commit.security_bits);
    println!("  Hiding: {}", extractable_commit.is_hiding());
    println!("  Binding: {}", extractable_commit.is_binding());
    println!("  Has Trapdoor: {}", extractable_commit.extraction_trapdoor.is_some());
    println!("  Unmasking Cost: ${:.0}", extractable_commit.unmasking_cost_estimate());
    println!("  Rational for $10B (w/o trapdoor): {}\n", 
             extractable_commit.is_unmasking_rational(10_000_000_000.0));
    
    println!("=== Strategic Deployment Recommendations ===\n");
    
    println!("📊 For EF Performance Metrics:");
    println!("  Use: StandardHiding ($1M barrier)");
    println!("  Allows: Critical investigations");
    println!("  Blocks: Corporate espionage, casual attacks\n");
    
    println!("🔬 For Core ZODA Algorithms:");
    println!("  Use: StrongHiding (Physically impossible)");
    println!("  Allows: No unauthorized access");
    println!("  Blocks: All reverse engineering attempts\n");
    
    println!("⚖️  For Regulatory Compliance:");
    println!("  Use: Extractable (Trapdoor access)");
    println!("  Allows: Court-ordered disclosure");
    println!("  Blocks: Unauthorized competitors\n");
    
    println!("💡 Economic Security Achieved:");
    println!("  • Normal actors face economically irrational costs");
    println!("  • Legitimate investigations remain feasible");
    println!("  • Strategic IP protection maintains competitive advantage");
    println!("  • Regulatory compliance through controlled access");
}
