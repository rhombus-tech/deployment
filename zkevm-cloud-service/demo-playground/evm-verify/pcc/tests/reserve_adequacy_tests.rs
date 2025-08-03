use pcc::analyzer::reserve_adequacy::*;
use pcc::analyzer::Property;
use anyhow::Result;

/// Sample stablecoin bytecode for testing
const STABLECOIN_BYTECODE: &[u8] = &[
    0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57,
    0x60, 0x00, 0x80, 0xfd, 0x5b, 0x50, 0x61, 0x02, 0x00, 0x80, 0x61, 0x00,
    0x1d, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3, 0xfe, 0x60, 0x80, 0x60, 0x40,
];

#[test]
fn test_reserve_adequacy_analyzer_creation() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(
        1.2,  // min_overcollateralization_ratio: 120%
        0.4,  // max_asset_concentration: 40%
        0.7,  // max_asset_correlation: 70%
        0.8,  // min_liquidity_ratio: 80%
    );
    
    assert_eq!(analyzer.min_overcollateralization_ratio, 1.2);
    assert_eq!(analyzer.max_asset_concentration, 0.4);
    assert_eq!(analyzer.max_asset_correlation, 0.7);
    assert_eq!(analyzer.min_liquidity_ratio, 0.8);
    assert_eq!(analyzer.max_cascade_risk, 0.1); // Default 10%
    assert_eq!(analyzer.emergency_reserve_buffer, 0.2); // Default 20%
    
    Ok(())
}

#[test]
fn test_reserve_adequacy_verification() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.2, 0.4, 0.7, 0.8);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    // Test overcollateralization proof
    assert!(proof.overcollateralization_proof.current_ratio > 1.0);
    assert_eq!(proof.overcollateralization_proof.guaranteed_min_ratio, 1.2);
    assert!(!proof.overcollateralization_proof.stress_scenarios.is_empty());
    assert!(!proof.overcollateralization_proof.recovery_mechanisms.is_empty());
    
    // Test diversification proof
    assert!(proof.diversification_proof.concentration_analysis.hhi_index >= 0.0);
    assert!(proof.diversification_proof.concentration_analysis.max_single_asset_percent <= 0.4);
    assert!(proof.diversification_proof.correlation_matrix.max_correlation >= 0.0);
    
    // Test collateral quality proof
    assert!(!proof.collateral_quality_proof.credit_risk_analysis.credit_ratings.is_empty());
    assert!(proof.collateral_quality_proof.credit_risk_analysis.credit_concentration >= 0.0);
    assert!(!proof.collateral_quality_proof.liquidity_risk_analysis.bid_ask_spreads.is_empty());
    
    // Test liquidation cascade proof
    assert!(!proof.liquidation_cascade_proof.cascade_simulations.is_empty());
    assert!(!proof.liquidation_cascade_proof.circuit_breakers.is_empty());
    
    // Test emergency reserve proof
    assert!(proof.emergency_reserve_proof.current_reserve_size > 0.0);
    assert!(!proof.emergency_reserve_proof.deployment_scenarios.is_empty());
    
    // Test dynamic collateral proof
    assert!(!proof.dynamic_collateral_proof.market_monitoring.volatility_monitoring.is_empty());
    assert!(!proof.dynamic_collateral_proof.adjustment_triggers.is_empty());
    
    Ok(())
}

#[test]
fn test_overcollateralization_stress_scenarios() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.5, 0.3, 0.6, 0.9);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let stress_scenarios = &proof.overcollateralization_proof.stress_scenarios;
    
    // Should have multiple stress scenarios
    assert!(stress_scenarios.len() >= 3);
    
    // Find market crash scenario
    let market_crash = stress_scenarios.iter()
        .find(|s| s.name.contains("Market Crash"))
        .expect("Should have market crash scenario");
    
    assert_eq!(market_crash.collateral_loss_percent, 50.0);
    assert!(market_crash.passes_test);
    
    // Find black swan scenario
    let black_swan = stress_scenarios.iter()
        .find(|s| s.name.contains("Black Swan"))
        .expect("Should have black swan scenario");
    
    assert_eq!(black_swan.collateral_loss_percent, 80.0);
    assert!(!black_swan.passes_test); // Should fail due to extreme loss
    
    Ok(())
}

#[test]
fn test_diversification_analysis() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.3, 0.35, 0.8, 0.85);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let diversification = &proof.diversification_proof;
    
    // Check asset concentration
    let concentration = &diversification.concentration_analysis;
    assert!(concentration.max_single_asset_percent <= analyzer.max_asset_concentration);
    assert!(concentration.concentration_risk_score >= 0.0);
    assert!(concentration.hhi_index < 1.0); // Should be diversified
    
    // Check correlation matrix
    let correlation = &diversification.correlation_matrix;
    assert!(!correlation.asset_ids.is_empty());
    assert!(correlation.max_correlation <= 1.0);
    assert!(correlation.average_correlation >= -1.0 && correlation.average_correlation <= 1.0);
    
    // Check geographic diversification
    let geographic = &diversification.geographic_diversification;
    assert!(!geographic.regions.is_empty());
    assert!(geographic.max_region_percent <= 1.0);
    assert!(geographic.geographic_risk_score >= 0.0);
    
    // Check sector diversification
    let sector = &diversification.sector_diversification;
    assert!(!sector.sectors.is_empty());
    assert!(sector.sector_risk_score >= 0.0);
    
    // Check liquidity diversification
    let liquidity = &diversification.liquidity_diversification;
    assert!(!liquidity.venues.is_empty());
    assert!(liquidity.average_daily_volume > 0.0);
    assert!(liquidity.liquidation_time_hours > 0.0);
    
    Ok(())
}

#[test]
fn test_collateral_quality_assessment() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.4, 0.4, 0.7, 0.9);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let quality = &proof.collateral_quality_proof;
    
    // Check credit risk analysis
    let credit_risk = &quality.credit_risk_analysis;
    assert!(!credit_risk.credit_ratings.is_empty());
    assert!(!credit_risk.default_probabilities.is_empty());
    assert!(credit_risk.credit_concentration >= 0.0);
    
    // Check liquidity risk analysis
    let liquidity_risk = &quality.liquidity_risk_analysis;
    assert!(!liquidity_risk.market_depths.is_empty());
    assert!(!liquidity_risk.bid_ask_spreads.is_empty());
    assert!(!liquidity_risk.stress_test_results.is_empty());
    
    // Check volatility analysis
    let volatility = &quality.volatility_analysis;
    assert!(!volatility.historical_volatilities.is_empty());
    assert!(!volatility.var_calculations.is_empty());
    assert!(!volatility.expected_shortfall.is_empty());
    
    // Check counterparty risks
    assert!(!quality.counterparty_risk.custodian_risks.is_empty());
    for risk in &quality.counterparty_risk.custodian_risks {
        assert!(risk.custody_percent >= 0.0 && risk.custody_percent <= 100.0);
        assert!(!risk.custodian_id.is_empty());
    }
    
    Ok(())
}

#[test]
fn test_liquidation_cascade_protection() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.25, 0.45, 0.75, 0.8);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let cascade_proof = &proof.liquidation_cascade_proof;
    
    // Check cascade simulations
    assert!(!cascade_proof.cascade_simulations.is_empty());
    for simulation in &cascade_proof.cascade_simulations {
        assert!(!simulation.trigger_event.is_empty());
        assert!(!simulation.liquidation_sequence.is_empty());
        assert!(simulation.total_loss_percent >= 0.0);
    }
    
    // Check circuit breakers
    assert!(!cascade_proof.circuit_breakers.is_empty());
    for breaker in &cascade_proof.circuit_breakers {
        assert!(!breaker.trigger_condition.is_empty());
        assert!(breaker.cooldown_minutes > 0);
    }
    
    // Check liquidation optimization
    let optimization = &cascade_proof.liquidation_optimization;
    assert!(!optimization.optimal_sequence.is_empty()); // Should have liquidation sequence
    assert!(!optimization.expected_impacts.is_empty()); // Should have impact analysis
    
    // Check recovery protocols
    assert!(!cascade_proof.recovery_protocols.is_empty());
    for protocol in &cascade_proof.recovery_protocols {
        assert!(!protocol.trigger_conditions.is_empty());
        assert!(!protocol.recovery_actions.is_empty());
        assert!(protocol.success_probability >= 0.0 && protocol.success_probability <= 1.0);
    }
    
    Ok(())
}

#[test]
fn test_emergency_reserve_adequacy() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.3, 0.4, 0.7, 0.85);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let emergency_proof = &proof.emergency_reserve_proof;
    
    // Check reserve amounts
    assert!(emergency_proof.current_reserve_size > 0.0);
    assert!(emergency_proof.recommended_reserve_size > 0.0);
    assert!(emergency_proof.current_reserve_size >= emergency_proof.recommended_reserve_size); // Should be adequately reserved
    
    // Check deployment scenarios
    assert!(!emergency_proof.deployment_scenarios.is_empty());
    for scenario in &emergency_proof.deployment_scenarios {
        assert!(scenario.amount_deployed > 0.0);
        assert!(scenario.deployment_time_minutes > 0);
        assert!(scenario.effectiveness_score >= 0.0 && scenario.effectiveness_score <= 1.0);
        assert!(!scenario.trigger.is_empty());
    }
    
    // Check replenishment mechanisms
    assert!(!emergency_proof.replenishment_mechanisms.is_empty());
    
    Ok(())
}

#[test]
fn test_dynamic_collateral_mechanisms() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.4, 0.35, 0.8, 0.9);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let dynamic_proof = &proof.dynamic_collateral_proof;
    
    // Check market monitoring
    let monitoring = &dynamic_proof.market_monitoring;
    assert!(!monitoring.volatility_monitoring.is_empty());
    assert!(!monitoring.correlation_monitoring.is_empty());
    assert!(!monitoring.liquidity_monitoring.is_empty());
    
    // Check adjustment triggers
    assert!(!dynamic_proof.adjustment_triggers.is_empty());
    for trigger in &dynamic_proof.adjustment_triggers {
        assert!(!trigger.thresholds.is_empty());
        assert!(trigger.adjustment_magnitude >= 0.0);
        assert!(trigger.response_time_minutes > 0);
    }
    
    // Check requirement adjustments
    assert!(!dynamic_proof.requirement_adjustments.is_empty());
    for adjustment in &dynamic_proof.requirement_adjustments {
        assert!(adjustment.old_requirement > 0.0);
        assert!(adjustment.new_requirement > 0.0);
        assert!(adjustment.implementation_hours > 0);
    }
    
    // Check feedback loop analysis
    let feedback_analysis = &dynamic_proof.feedback_analysis;
    assert!(!feedback_analysis.stability_analysis.is_empty());
    assert!(!feedback_analysis.feedback_loops.is_empty());
    
    for loop_info in &feedback_analysis.feedback_loops {
        assert!(!loop_info.description.is_empty());
        assert!(loop_info.stability_impact >= 0.0);
        assert!(!loop_info.mitigations.is_empty());
    }
    
    Ok(())
}

#[test]
fn test_property_trait_implementation() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.2, 0.4, 0.7, 0.8);
    
    // Test basic functionality - removed property_name and property_description as they're not in the trait
    
    // Test verify method through Property trait
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    assert!(proof.overcollateralization_proof.current_ratio > 0.0);
    
    Ok(())
}

#[test]
fn test_conservative_parameter_validation() -> Result<()> {
    // Test with very conservative parameters
    let conservative_analyzer = ReserveAdequacyAnalyzer::new(
        2.0,  // 200% overcollateralization
        0.2,  // Max 20% concentration
        0.3,  // Max 30% correlation
        0.95, // 95% liquidity ratio
    );
    
    let proof = conservative_analyzer.verify(STABLECOIN_BYTECODE)?;
    
    // Should still work with conservative parameters
    assert!(proof.overcollateralization_proof.guaranteed_min_ratio == 2.0);
    assert!(proof.diversification_proof.correlation_matrix.max_correlation >= 0.0);
    assert!(!proof.collateral_quality_proof.liquidity_risk_analysis.bid_ask_spreads.is_empty());
    
    Ok(())
}

#[test]
fn test_recovery_mechanism_types() -> Result<()> {
    let analyzer = ReserveAdequacyAnalyzer::new(1.5, 0.4, 0.7, 0.8);
    let proof = analyzer.verify(STABLECOIN_BYTECODE)?;
    
    let mechanisms = &proof.overcollateralization_proof.recovery_mechanisms;
    
    // Should have different types of recovery mechanisms
    let has_minting_halt = mechanisms.iter().any(|m| matches!(m, CollateralRecoveryMechanism::MintingHalt { .. }));
    let has_emergency_liquidation = mechanisms.iter().any(|m| matches!(m, CollateralRecoveryMechanism::EmergencyLiquidation { .. }));
    let has_dynamic_requirements = mechanisms.iter().any(|m| matches!(m, CollateralRecoveryMechanism::DynamicRequirements { .. }));
    let has_emergency_reserve = mechanisms.iter().any(|m| matches!(m, CollateralRecoveryMechanism::EmergencyReserveDeploy { .. }));
    
    assert!(has_minting_halt);
    assert!(has_emergency_liquidation);
    assert!(has_dynamic_requirements);
    assert!(has_emergency_reserve);
    
    Ok(())
}
