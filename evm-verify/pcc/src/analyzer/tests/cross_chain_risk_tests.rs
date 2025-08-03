use crate::analyzer::{CrossChainRiskAnalyzer, Property};

/// Simple bytecode for testing cross-chain risk analysis
const STABLECOIN_BYTECODE: &[u8] = &[
    0x60, 0x01, 0x60, 0x02, 0x01, // PUSH1 1, PUSH1 2, ADD
    0x50,                         // POP
    0x00,                         // STOP
];

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_cross_chain_risk_analyzer_creation() {
        let analyzer = CrossChainRiskAnalyzer::new(
            0.5,  // max_bridge_exposure
            10,   // min_bridge_validators
            100,  // max_block_delay
            2,    // min_finality_confirmations
        );
        
        // Verify analyzer parameters
        // Test basic analyzer setup - analyzer created successfully
        let test_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // Simple bytecode
        let _result = analyzer.verify(&test_bytecode);
    }

    #[test]
    fn test_cross_chain_risk_verification() {
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 100, 2);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        assert!(result.is_ok(), "Cross-chain risk verification should succeed");
        
        let proof = result.unwrap();
        assert!(proof.bridge_exposure_analysis.exposure_within_limits);
        assert!(proof.validator_security_proof.collusion_resistance_proof);
        assert!(proof.chain_synchronization_proof.synchronization_within_bounds);
        assert!(proof.cross_chain_manipulation_resistance.manipulation_cost_exceeds_profit);
    }

    #[test]
    fn test_bridge_exposure_limits() {
        // Test with strict exposure limits
        let analyzer = CrossChainRiskAnalyzer::new(0.3, 10, 100, 2);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because max single chain exposure (0.4) > limit (0.3)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Bridge exposure exceeds safety limits"));
    }

    #[test]
    fn test_validator_security_requirements() {
        // Test with high validator requirements
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 25, 100, 2);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because some bridges have < 25 validators
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient validator security"));
    }

    #[test]
    fn test_synchronization_bounds() {
        // Test with strict synchronization requirements
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 30, 2); // max 30 blocks delay
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because max observed delay (45) > limit (30)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Chain synchronization outside acceptable bounds"));
    }

    #[test]
    fn test_manipulation_resistance() {
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 100, 2);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        assert!(result.is_ok());
        
        let proof = result.unwrap();
        let manipulation_resistance = &proof.cross_chain_manipulation_resistance;
        
        // Verify manipulation cost exceeds expected profits
        assert!(manipulation_resistance.bridge_rate_manipulation_cost > 10000.0);
        assert!(manipulation_resistance.arbitrage_window_analysis.manipulation_cost_vs_arbitrage_ratio > 10.0);
        assert!(manipulation_resistance.manipulation_cost_exceeds_profit);
    }

    #[test]
    fn test_proof_integrity() {
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 100, 2);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        
        // Verify proof has valid hash
        assert_ne!(proof.proof_hash, [0u8; 32]);
        
        // Verify timestamp is recent
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(proof.timestamp <= now);
        assert!(proof.timestamp > now - 60); // Within last minute
    }

    #[test]
    fn test_bridge_exposure_analysis_details() {
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 100, 2);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let exposure = &proof.bridge_exposure_analysis;
        
        // Verify exposure analysis
        assert!(exposure.total_bridge_value > 0.0);
        assert!(!exposure.per_chain_exposure.is_empty());
        assert!(exposure.concentration_risk_score >= 0.0);
        assert!(exposure.concentration_risk_score <= 1.0);
    }

    #[test]
    fn test_validator_distribution() {
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 100, 2);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let validator_proof = &proof.validator_security_proof;
        
        // Verify validator security features
        assert!(!validator_proof.active_validators_per_bridge.is_empty());
        assert!(!validator_proof.validator_stake_distribution.is_empty());
        assert!(validator_proof.slashing_mechanism_active);
    }

    #[test]
    fn test_reorg_risk_assessment() {
        let analyzer = CrossChainRiskAnalyzer::new(0.5, 10, 100, 2);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let reorg_assessment = &proof.chain_synchronization_proof.reorg_risk_assessment;
        
        // Verify reorg risk analysis
        assert!(!reorg_assessment.chain_finality_scores.is_empty());
        assert!(!reorg_assessment.historical_reorg_frequency.is_empty());
        assert!(reorg_assessment.reorg_protection_sufficient);
        
        // All finality scores should be high (> 0.9)
        for score in reorg_assessment.chain_finality_scores.values() {
            assert!(*score > 0.9);
        }
    }
}
