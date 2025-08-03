#[cfg(test)]
mod tests {
    use crate::analyzer::game_theory::*;
    use crate::analyzer::Property;
    use anyhow::Result;

    // Test bytecode representing a stablecoin rebalancing mechanism
    const STABLECOIN_BYTECODE: &[u8] = &[
        0x60, 0x80, 0x60, 0x40, // PUSH1 0x80 PUSH1 0x40
        0x52, // MSTORE
        0x34, 0x80, 0x15, // CALLVALUE DUP1 ISZERO
        0x61, 0x00, 0x10, // PUSH2 0x0010
        0x57, // JUMPI
        0x60, 0x00, 0x80, 0xfd, // PUSH1 0x00 DUP1 REVERT
        // Rebalancing logic
        0x5b, // JUMPDEST
        0x50, // POP
        0x60, 0x04, // PUSH1 0x04
        0x36, // CALLDATASIZE
        0x10, // LT
        0x61, 0x00, 0x23, // PUSH2 0x0023
        0x57, // JUMPI
        0x60, 0x00, 0x35, // PUSH1 0x00 CALLDATALOAD
        0x7c, 0x01, 0x00, 0x00, 0x00, // PUSH29
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_game_theory_analyzer_creation() {
        let analyzer = GameTheoryAnalyzer::new(
            5,      // player_types: arbitrageurs, holders, attackers, etc.
            0.02,   // min_profit_margin: 2% minimum profit to act
            10000.0, // max_manipulation_profit: maximum profit from attacks
            10.0,   // attack_cost_multiplier: attacks cost 10x profit
        );
        
        // Constructor should succeed - can't access private fields directly
        // but we can verify through the analyzer's behavior
        println!("✅ GameTheoryAnalyzer created successfully");
    }

    #[test]
    fn test_nash_equilibrium_verification() -> Result<()> {
        let analyzer = GameTheoryAnalyzer::new(5, 0.02, 10000.0, 10.0);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Verify Nash equilibrium exists and is stable
        assert!(proof.nash_equilibrium_proof.equilibria_count > 0);
        assert!(proof.nash_equilibrium_proof.evolutionary_stability_proof);
        assert!(proof.nash_equilibrium_proof.convergence_time > 0);
        assert!(proof.attack_prevention_proof.unprofitability_proof);
        assert!(!proof.proof_hash.is_empty());
        
        println!("✅ Nash equilibrium verified");
        Ok(())
    }

    #[test]
    fn test_attack_resistance_analysis() -> Result<()> {
        let analyzer = GameTheoryAnalyzer::new(3, 0.01, 5000.0, 15.0);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Verify attack resistance properties
        assert!(proof.attack_prevention_proof.unprofitability_proof);
        assert!(proof.attack_prevention_proof.coordination_prevention_proof);
        assert!(proof.attack_prevention_proof.minimum_attack_capital > 0.0);
        
        println!("✅ Attack resistance verified");
        Ok(())
    }

    #[test]
    fn test_incentive_compatibility() -> Result<()> {
        let analyzer = GameTheoryAnalyzer::new(4, 0.03, 15000.0, 8.0);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Check incentive compatibility
        assert!(proof.incentive_compatibility_proof.dominant_strategy_proof);
        assert!(!proof.incentive_compatibility_proof.honesty_optimality_proof.is_empty());
        assert!(!proof.incentive_compatibility_proof.honest_behavior_rewards.is_empty());
        
        println!("✅ Incentive compatibility verified");
        Ok(())
    }

    #[test]
    fn test_game_theory_proof_integrity() -> Result<()> {
        let analyzer = GameTheoryAnalyzer::new(5, 0.02, 10000.0, 10.0);
        
        let proof1 = analyzer.verify(STABLECOIN_BYTECODE)?;
        let proof2 = analyzer.verify(STABLECOIN_BYTECODE)?;
        
        // Same input should produce same proof hash
        assert_eq!(proof1.proof_hash, proof2.proof_hash);
        assert!(!proof1.proof_hash.is_empty());
        
        println!("✅ Proof integrity verified");
        Ok(())
    }

    #[test]
    fn test_performance_benchmarks() -> Result<()> {
        let analyzer = GameTheoryAnalyzer::new(5, 0.02, 10000.0, 10.0);
        
        let start = std::time::Instant::now();
        let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
        let duration = start.elapsed();
        
        // Game theory analysis should complete quickly
        assert!(duration.as_millis() < 200, "Analysis took too long: {:?}", duration);
        assert!(proof.nash_equilibrium_proof.equilibria_count > 0);
        
        println!("✅ Performance benchmark passed");
        println!("   Analysis time: {:?}", duration);
        
        Ok(())
    }
}
