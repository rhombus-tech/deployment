#[cfg(test)]
mod tests {
    use crate::analyzer::stability::*;
    use crate::analyzer::Property;
    use anyhow::Result;

    // Sample bytecode representing a simple algorithmic stablecoin contract
    const STABLECOIN_BYTECODE: &[u8] = &[
        0x60, 0x80, 0x60, 0x40, 0x52, // Setup
        0x60, 0x04, 0x36, 0x10, 0x60, 0x2d, 0x57, // Function selector  
        0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x60, 0x32, 0x57, // rebalance()
        0x63, 0x70, 0xa0, 0x82, 0x31, 0x14, 0x60, 0x47, 0x57, // getPrice()
        0x63, 0x18, 0x16, 0x0d, 0xdd, 0x14, 0x60, 0x5c, 0x57, // mint()
        0x5b, 0x60, 0x00, 0x80, 0xfd, // Revert
        // Rebalance function
        0x5b, 0x60, 0x00, 0x54, 0x60, 0x64, 0x81, 0x02, 0x60, 0x00, 0x55, 0x56,
        // Price function  
        0x5b, 0x60, 0x01, 0x54, 0x60, 0x40, 0x51, 0x80, 0x82, 0x81, 0x52, 0x60, 0x20, 0x01, 0x91, 0x90, 0x50, 0xf3,
        // Mint function
        0x5b, 0x60, 0x02, 0x54, 0x34, 0x01, 0x60, 0x02, 0x55, 0x56,
    ];

    #[test]
    fn test_stability_analyzer_creation() {
        let analyzer = StabilityAnalyzer::new(
            0.05,  // 5% max deviation
            300,   // 5 minute convergence window  
            2.0,   // 200% min collateral ratio
            3.0,   // 3x attack cost multiplier
        );

        // Test completed - analyzer created successfully
        println!("✅ StabilityAnalyzer created successfully");
    }

    #[test]
    fn test_basic_verification() -> Result<()> {
        let analyzer = StabilityAnalyzer::new(0.05, 300, 0.2, 5.0);
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;

        // Basic proof structure checks
        assert_eq!(proof.proven_max_deviation, 0.05);
        assert!(proof.timestamp > 0);
        assert_ne!(proof.proof_hash, [0u8; 32]);
        
        println!("✅ Basic verification completed");
        println!("   Max deviation: {:.2}%", proof.proven_max_deviation * 100.0);
        
        Ok(())
    }

    #[test]
    fn test_convergence_proof() -> Result<()> {
        let analyzer = StabilityAnalyzer::new(0.05, 300, 0.2, 5.0);
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Check convergence properties
        let convergence = &proof.convergence_proof;
        assert!(convergence.max_convergence_time > 0);
        assert!(convergence.lyapunov_function.energy_bound > 0.0);
        
        println!("✅ Convergence proof verified");
        println!("   Convergence time: {} blocks", convergence.max_convergence_time);
        
        Ok(())
    }

    #[test]
    fn test_anti_death_spiral_proof() -> Result<()> {
        let analyzer = StabilityAnalyzer::new(0.05, 300, 0.2, 5.0);
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Check anti-death spiral properties
        let ds_proof = &proof.anti_death_spiral_proof;
        assert!(ds_proof.critical_backing_ratio > 1.0);
        assert!(ds_proof.backing_increase_proof.positive_feedback_prevention);
        
        println!("✅ Anti-death spiral proof verified");
        println!("   Critical backing ratio: {:.2}", ds_proof.critical_backing_ratio);
        
        Ok(())
    }

    #[test]
    fn test_attack_resistance() -> Result<()> {
        let analyzer = StabilityAnalyzer::new(0.05, 300, 0.2, 5.0);
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Check attack resistance
        let attack_proof = &proof.attack_resistance_proof;
        assert!(!attack_proof.manipulation_cost_function.is_empty());
        assert!(attack_proof.max_manipulation_profit >= 0.0);
        assert!(attack_proof.cost_exceeds_profit_proof);
        
        println!("✅ Attack resistance verified");
        
        Ok(())
    }

    #[test]
    fn test_proof_integrity() -> Result<()> {
        let analyzer = StabilityAnalyzer::new(0.05, 300, 0.2, 5.0);
        let proof1 = analyzer.verify(STABLECOIN_BYTECODE)?;
        let proof2 = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Same input should produce same proof hash
        assert_eq!(proof1.proof_hash, proof2.proof_hash);
        
        println!("✅ Proof integrity verified");
        
        Ok(())
    }

    #[test]
    fn test_performance() -> Result<()> {
        let analyzer = StabilityAnalyzer::new(0.05, 300, 0.2, 5.0);
        
        let start = std::time::Instant::now();
        let _proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        let duration = start.elapsed();
        
        // Verification should complete reasonably fast
        assert!(duration.as_millis() < 1000, "Verification took too long: {:?}", duration);
        
        println!("✅ Performance test passed: {:?}", duration);
        
        Ok(())
    }
}
