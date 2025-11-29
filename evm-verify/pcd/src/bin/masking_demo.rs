use pcd::tensor_zoda::{ExtractableCommitment, CommitmentType, Matrix};
use ark_bn254::Fr as BN254Fr;
use rand::thread_rng;

fn main() {
    println!("=== zkEVM Commitment Types Demonstration ===\n");
    
    let mut rng = thread_rng();
    let matrix = Matrix::<BN254Fr>::new(4, 4);
    
    println!("Testing different commitment types:\n");
    
    // Test Binding
    let binding_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::Binding,
        &mut rng,
    );
    
    println!("🔒 Binding Commitment:");
    println!("  Type: {:?}", binding_commit.commitment_type);
    println!("  Hiding: {}", binding_commit.is_hiding());
    println!("  Binding: {}", binding_commit.is_binding());
    println!("  Purpose: Computationally binding\n");
    
    // Test Hiding (Computationally hiding)
    let hiding_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::Hiding,
        &mut rng,
    );
    
    println!("🔐 Hiding Commitment:");
    println!("  Type: {:?}", hiding_commit.commitment_type);
    println!("  Hiding: {}", hiding_commit.is_hiding());
    println!("  Binding: {}", hiding_commit.is_binding());
    println!("  Purpose: Computationally hiding\n");
    
    // Test PerfectHiding (Information-theoretically hiding)
    let perfect_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::PerfectHiding,
        &mut rng,
    );
    
    println!("🛡️  PerfectHiding Commitment:");
    println!("  Type: {:?}", perfect_commit.commitment_type);
    println!("  Hiding: {}", perfect_commit.is_hiding());
    println!("  Binding: {}", perfect_commit.is_binding());
    println!("  Purpose: Information-theoretically hiding\n");
    
    // Test Extractable (Trapdoor access)
    let extractable_commit = ExtractableCommitment::new(
        &matrix,
        CommitmentType::Extractable,
        &mut rng,
    );
    
    println!("🔑 Extractable Commitment:");
    println!("  Type: {:?}", extractable_commit.commitment_type);
    println!("  Hiding: {}", extractable_commit.is_hiding());
    println!("  Binding: {}", extractable_commit.is_binding());
    println!("  Has Trapdoor: {}", extractable_commit.extraction_trapdoor.is_some());
    println!("  Purpose: Allows extraction of committed value\n");
    
    println!("=== Commitment Type Usage ===\n");
    
    println!("📊 Binding:");
    println!("  - Cannot change committed value");
    println!("  - Used for non-repudiation\n");
    
    println!("🔐 Hiding:");
    println!("  - Computationally hides committed value");
    println!("  - Used for privacy-preserving protocols\n");
    
    println!("🛡️  PerfectHiding:");
    println!("  - Information-theoretically secure");
    println!("  - Maximum privacy guarantees\n");
    
    println!("🔑 Extractable:");
    println!("  - Trapdoor allows value extraction");
    println!("  - Used for compliance/auditing");
    println!("  Blocks: Unauthorized competitors\n");
    
    println!("💡 Economic Security Achieved:");
    println!("  • Normal actors face economically irrational costs");
    println!("  • Legitimate investigations remain feasible");
    println!("  • Strategic IP protection maintains competitive advantage");
    println!("  • Regulatory compliance through controlled access");
}
