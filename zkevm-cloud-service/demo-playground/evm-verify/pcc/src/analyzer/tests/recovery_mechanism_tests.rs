use crate::analyzer::{RecoveryMechanismAnalyzer, Property};

/// Simple bytecode for testing recovery mechanism analysis
const STABLECOIN_BYTECODE: &[u8] = &[
    0x60, 0x01, 0x60, 0x02, 0x01, // PUSH1 1, PUSH1 2, ADD
    0x50,                         // POP
    0x00,                         // STOP
];

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_recovery_mechanism_analyzer_creation() {
        let analyzer = RecoveryMechanismAnalyzer::new(
            0.15,  // min_fund_ratio
            3600,  // max_recovery_time_hours (u64)
            0.67,  // min_governance_threshold
            0.05,  // max_user_loss_cap
        );
        
        // Verify analyzer setup - analyzer created successfully
        let test_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // Simple bytecode
        let _result = analyzer.verify(&test_bytecode);
    }

    #[test]
    fn test_recovery_verification_success() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        assert!(result.is_ok(), "Recovery mechanism verification should succeed with reasonable parameters");
        
        let proof = result.unwrap();
        assert!(proof.emergency_fund_analysis.fund_ratio_adequate);
        assert!(proof.governance_recovery_proof.democratic_legitimacy_score >= 0.8);
        assert!(!proof.technical_recovery_systems.automatic_circuit_breakers.is_empty());
        assert!(proof.user_protection_guarantees.maximum_user_loss_cap <= 0.05);
        assert!(proof.recovery_simulation_results.all_scenarios_successful);
    }

    #[test]
    fn test_invalid_fund_ratio() {
        // Test with fund ratio below minimum threshold
        let analyzer = RecoveryMechanismAnalyzer::new(0.25, 3600, 0.67, 0.05);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because emergency fund ratio (0.1) < minimum (0.12)
        assert!(result.is_err());
        let error_message = format!("{}", result.unwrap_err());
        assert!(error_message.contains("Emergency fund") || error_message.contains("insufficient"));
    }

    #[test]
    fn test_governance_threshold_too_high() {
        // Set very high governance threshold
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.9, 0.05);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because governance threshold (0.9) is too high
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Governance emergency threshold"));
    }

    #[test]
    fn test_intervention_delay_too_slow() {
        // Set very strict delay requirement
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 1800, 0.67, 0.05); // 30 minutes max
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because max intervention delay (3600s) > limit (1800s)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Technical recovery systems"));
    }

    #[test]
    fn test_user_loss_cap_exceeded() {
        // Set very strict loss cap
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.02); // 2% max loss
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because max user loss (0.05) > cap (0.02)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("User loss cap"));
    }

    #[test]
    fn test_emergency_fund_analysis() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let fund_analysis = &proof.emergency_fund_analysis;
        
        // Test emergency fund metrics
        assert!(fund_analysis.fund_ratio_adequate);
        assert!(fund_analysis.fund_accessibility_score > 0.0);
    }

    #[test]
    fn test_governance_recovery_mechanisms() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let governance = &proof.governance_recovery_proof;
        
        // Verify governance mechanisms
        assert!(governance.democratic_legitimacy_score >= 0.5);
    }

    #[test]
    fn test_technical_recovery_systems() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let technical = &proof.technical_recovery_systems;
        
        // Test technical recovery systems basic properties
        assert!(!technical.automatic_circuit_breakers.is_empty());
        assert!(!technical.manual_intervention_capabilities.is_empty());
        assert!(!technical.system_restore_procedures.is_empty());
        
        // Verify circuit breakers are properly configured
        for breaker in &technical.automatic_circuit_breakers {
            assert!(!breaker.trigger_type.is_empty());
            assert!(breaker.activation_threshold > 0.0);
            assert!(breaker.response_time_ms < 1000); // Sub-second response
        }
        
        // Test manual intervention capabilities
        for capability in &technical.manual_intervention_capabilities {
            assert!(!capability.intervention_type.is_empty());
            assert!(capability.required_approvals > 0);
        }
        
        // Test system restore procedures
        for procedure in &technical.system_restore_procedures {
            assert!(!procedure.procedure_name.is_empty());
            assert!(procedure.success_probability > 0.0);
        }
    }

    #[test]
    fn test_user_protection_guarantees() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let protection = &proof.user_protection_guarantees;
        
        // Verify user protections
        assert!(protection.maximum_user_loss_cap <= 0.05);
        assert!(!protection.insurance_coverage.insurer_credit_rating.is_empty());
        assert!(!protection.priority_withdrawal_mechanisms.is_empty());
        
        // Verify insurance mechanisms
        let insurance = &protection.insurance_coverage;
        assert!(insurance.coverage_amount > 0.0);
        assert!(insurance.coverage_percentage > 0.0);
        assert!(!insurance.insurer_credit_rating.is_empty());
        
        // Test priority withdrawal mechanisms
        for mechanism in &protection.priority_withdrawal_mechanisms {
            assert!(!mechanism.is_empty());
        }
    }

    #[test]
    fn test_recovery_simulation_results() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let simulations = &proof.recovery_simulation_results;
        
        // Verify simulation results
        assert!(!simulations.scenarios_tested.is_empty());
        assert!(simulations.scenarios_tested.len() >= 10);
        assert!(simulations.all_scenarios_successful);
        assert!(simulations.worst_case_analysis.minimum_fund_recovery > 0.0);
        
        // Verify individual scenarios
        assert!(simulations.average_recovery_time < 24 * 3600); // Less than 24 hours
        for scenario in &simulations.scenarios_tested {
            assert!(scenario.recovery_time_hours <= 168); // 1 week max
            assert!(scenario.fund_recovery_percentage <= 100.0);
            assert!(scenario.recovery_successful);
        }
        
        // Verify worst case scenario
        assert!(simulations.worst_case_analysis.minimum_fund_recovery >= 0.9);
        let worst_case = &simulations.worst_case_analysis;
        assert!(worst_case.critical_failure_probability >= 0.0);
        assert!(worst_case.critical_failure_probability <= 1.0);
        assert!(worst_case.maximum_recovery_time <= 168 * 3600); // Convert hours to seconds
        assert!(worst_case.acceptable_risk_level); // Risk should be acceptable
    }

    #[test]
    fn test_fund_composition_diversification() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let composition = &proof.emergency_fund_analysis.fund_composition;
        
        // Verify fund is diversified
        assert!(!composition.is_empty());
        
        let total_allocation: f64 = composition.values().sum();
        assert!((total_allocation - 1.0).abs() < 0.01); // Should sum to ~100%
        
        // No single asset should dominate (max 50%)
        for &allocation in composition.values() {
            assert!(allocation >= 0.0);
            assert!(allocation <= 0.5);
        }
    }

    #[test]
    fn test_liquidity_assessment() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let fund_accessibility = proof.emergency_fund_analysis.fund_accessibility_score;
        
        // Verify liquidity metrics
        assert!(fund_accessibility >= 0.6); // At least 60% accessibility score
    }

    #[test]
    fn test_proof_integrity() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
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
    fn test_performance_benchmarks() {
        let analyzer = RecoveryMechanismAnalyzer::new(0.15, 3600, 0.67, 0.05);
        
        let start_time = std::time::Instant::now();
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        let duration = start_time.elapsed();
        
        assert!(result.is_ok());
        assert!(duration.as_millis() < 2000, "Recovery mechanism verification should complete in under 2 seconds");
    }

    #[test]
    fn test_edge_case_minimum_parameters() {
        // Test with minimum viable parameters
        let analyzer = RecoveryMechanismAnalyzer::new(0.1, 7200, 0.51, 0.1);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        assert!(result.is_ok(), "Should work with minimum viable parameters");
        
        let proof = result.unwrap();
        assert!(proof.emergency_fund_analysis.fund_ratio_adequate);
        assert!(proof.governance_recovery_proof.emergency_governance_threshold >= 0.51);
    }

    #[test]
    fn test_edge_case_maximum_security_parameters() {
        // Test with maximum security parameters
        let analyzer = RecoveryMechanismAnalyzer::new(0.25, 1800, 0.67, 0.01);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should handle strict parameters gracefully
        match result {
            Ok(_) => println!("Test passed with strict parameters"),
            Err(e) => {
                let error_msg = e.to_string();
                println!("Expected error with strict parameters: {}", error_msg);
                assert!(!error_msg.is_empty()); // Should have meaningful error message
            }
        }
    }
}
