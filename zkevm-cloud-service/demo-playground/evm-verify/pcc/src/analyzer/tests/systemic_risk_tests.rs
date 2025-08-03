use crate::analyzer::{SystemicRiskAnalyzer, Property};

/// Simple bytecode for testing systemic risk analysis
const STABLECOIN_BYTECODE: &[u8] = &[
    0x60, 0x01, 0x60, 0x02, 0x01, // PUSH1 1, PUSH1 2, ADD
    0x50,                         // POP
    0x00,                         // STOP
];

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_systemic_risk_analyzer_creation() {
        let analyzer = SystemicRiskAnalyzer::new(
            0.4,  // max_market_correlation
            0.2,  // min_stress_liquidity_buffer
            0.2,  // max_asset_class_exposure
            0.6,  // min_diversification_score
        );
        
        // Test basic analyzer setup - analyzer created successfully
        let test_bytecode = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // Simple bytecode
        let _result = analyzer.verify(&test_bytecode);
    }

    #[test]
    fn test_systemic_risk_verification_success() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        assert!(result.is_ok(), "Systemic risk verification should succeed with reasonable parameters");
        
        let proof = result.unwrap();
        assert!(proof.market_correlation_analysis.max_correlation_within_limits);
        assert!(proof.stress_test_results.all_scenarios_passed);
        assert!(proof.contagion_risk_assessment.isolated_from_contagion);
        assert!(proof.black_swan_resilience.resilience_score >= 0.7);
    }

    #[test]
    fn test_high_correlation_failure() {
        // Set very low correlation limit to trigger failure
        let analyzer = SystemicRiskAnalyzer::new(0.2, 0.2, 0.2, 0.6);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because crypto correlation (0.35) > limit (0.2)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Market correlation exceeds"));
    }

    #[test]
    fn test_insufficient_liquidity_buffer() {
        // Set high buffer requirement to trigger failure
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.4, 0.2, 0.6);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because total buffer (0.3) < requirement (0.4)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient liquidity buffers"));
    }

    #[test]
    fn test_insufficient_diversification() {
        // Set high diversification requirement
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.8);
        
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        // Should fail because diversification score (0.65) < requirement (0.8)
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient portfolio diversification"));
    }

    #[test]
    fn test_market_correlation_analysis() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let correlation = &proof.market_correlation_analysis;
        
        // Verify correlation values are reasonable
        assert!(correlation.correlation_with_sp500 >= 0.0);
        assert!(correlation.correlation_with_sp500 <= 1.0);
        assert!(correlation.correlation_with_crypto_market >= 0.0);
        assert!(correlation.correlation_with_crypto_market <= 1.0);
        assert!(correlation.diversification_score >= 0.0);
        assert!(correlation.diversification_score <= 1.0);
    }

    #[test]
    fn test_stress_test_scenarios() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let stress_results = &proof.stress_test_results;
        
        // Verify all stress scenarios maintain stability
        assert!(stress_results.market_crash_scenario.stability_maintained);
        assert!(stress_results.liquidity_crisis_scenario.stability_maintained);
        assert!(stress_results.regulatory_shock_scenario.stability_maintained);
        assert!(stress_results.crypto_winter_scenario.stability_maintained);
        assert!(stress_results.all_scenarios_passed);
        
        // Verify recovery times are reasonable
        assert!(stress_results.market_crash_scenario.recovery_time_hours <= 168); // 1 week max
        assert!(stress_results.liquidity_crisis_scenario.recovery_time_hours <= 168);
    }

    #[test]
    fn test_contagion_risk_assessment() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let contagion = &proof.contagion_risk_assessment;
        
        // Verify contagion risk metrics
        assert!(!contagion.defi_protocol_exposures.is_empty());
        assert!(!contagion.centralized_exchange_risks.is_empty());
        assert!(contagion.counterparty_concentration_risk >= 0.0);
        assert!(contagion.counterparty_concentration_risk <= 1.0);
        assert!(contagion.contagion_firewall_effectiveness > 0.5);
        assert!(contagion.isolated_from_contagion);
    }

    #[test]
    fn test_black_swan_resilience() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let resilience = &proof.black_swan_resilience;
        
        // Verify black swan preparation
        assert!(!resilience.extreme_event_scenarios.is_empty());
        assert!(!resilience.circuit_breaker_mechanisms.is_empty());
        assert!(resilience.emergency_shutdown_capability.user_exit_guarantees);
        assert!(!resilience.fund_recovery_mechanisms.is_empty());
        assert!(resilience.resilience_score >= 0.7);
        
        // Verify circuit breakers have reasonable response times
        for breaker in &resilience.circuit_breaker_mechanisms {
            assert!(breaker.response_time_seconds <= 300); // 5 minutes max
        }
    }

    #[test]
    fn test_liquidity_crisis_preparedness() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let liquidity = &proof.liquidity_crisis_preparedness;
        
        // Verify liquidity preparation
        assert!(!liquidity.liquidity_buffers.is_empty());
        assert!(!liquidity.emergency_funding_sources.is_empty());
        assert!(liquidity.stress_liquidity_ratio >= 0.2); // At least 20% buffer
        
        let crisis_plan = &liquidity.crisis_response_plan;
        assert!(!crisis_plan.escalation_levels.is_empty());
        assert!(!crisis_plan.response_time_targets.is_empty());
        assert!(crisis_plan.stakeholder_communication_plan);
        assert!(crisis_plan.regulatory_coordination_protocol);
    }

    #[test]
    fn test_extreme_event_scenarios() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let scenarios = &proof.black_swan_resilience.extreme_event_scenarios;
        
        // Verify we have major extreme event scenarios covered
        let event_types: Vec<&String> = scenarios.iter().map(|s| &s.event_type).collect();
        assert!(event_types.iter().any(|t| t.contains("Financial Crisis")));
        
        // Verify all scenarios have reasonable parameters
        for scenario in scenarios {
            assert!(scenario.probability_estimate >= 0.0);
            assert!(scenario.probability_estimate <= 1.0);
            assert!(scenario.impact_severity >= 0.0);
            assert!(scenario.impact_severity <= 1.0);
            assert!(scenario.survivability_score >= 0.0);
            assert!(scenario.survivability_score <= 1.0);
        }
    }

    #[test]
    fn test_emergency_shutdown_capability() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let proof = analyzer.verify(STABLECOIN_BYTECODE).unwrap();
        let shutdown = &proof.black_swan_resilience.emergency_shutdown_capability;
        
        // Verify emergency shutdown features
        assert!(shutdown.governance_threshold > 0.5); // Majority required
        assert!(shutdown.governance_threshold <= 1.0);
        assert!(shutdown.timelock_duration_hours >= 1); // At least 1 hour timelock
        assert!(!shutdown.fund_protection_mechanisms.is_empty());
        assert!(shutdown.user_exit_guarantees);
    }

    #[test]
    fn test_proof_integrity() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
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
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        
        let start_time = std::time::Instant::now();
        let result = analyzer.verify(STABLECOIN_BYTECODE);
        let duration = start_time.elapsed();
        
        assert!(result.is_ok());
        assert!(duration.as_millis() < 1000, "Systemic risk verification should complete in under 1 second");
    }
}
