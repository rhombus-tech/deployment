use super::super::peg_stability::*;
use anyhow::Result;

#[test]
fn test_peg_stability_analyzer_creation() {
    let analyzer = PegStabilityAnalyzer::new(
        0.05,   // max_peg_deviation (5%)
        3600,   // peg_recovery_time_limit (1 hour)
        0.001,  // minimum_arbitrage_incentive (0.1%)
        0.8,    // max_oracle_correlation
    );
    
    assert_eq!(analyzer.max_peg_deviation, 0.05);
    assert_eq!(analyzer.peg_recovery_time_limit, 3600);
}

#[test]
fn test_risk_level_assessment() {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    assert!(matches!(analyzer.assess_risk_level(0.005), PegRiskLevel::Stable));
    assert!(matches!(analyzer.assess_risk_level(0.02), PegRiskLevel::Minor));
    assert!(matches!(analyzer.assess_risk_level(0.04), PegRiskLevel::Moderate));
    assert!(matches!(analyzer.assess_risk_level(0.08), PegRiskLevel::Severe));
    assert!(matches!(analyzer.assess_risk_level(0.15), PegRiskLevel::Critical));
}

#[test]
fn test_arbitrage_strength_calculation() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    let market_data = PegMarketData {
        current_price: 1.02,
        target_price: 1.00,
        time_since_depeg: 1800,
        total_liquidity: 2_000_000.0,
        market_prices: vec![
            MarketPrice {
                market_name: "Uniswap".to_string(),
                price: 1.02,
                liquidity: 1_000_000.0,
                trading_fees: 0.003,
                volume_24h: 500_000.0,
            },
            MarketPrice {
                market_name: "Curve".to_string(),
                price: 1.015,
                liquidity: 800_000.0,
                trading_fees: 0.0005,
                volume_24h: 300_000.0,
            },
        ],
        arbitrage_bot_activity: 0.7,
        market_maker_spread: 0.001,
        emergency_reserves_ratio: 0.12,
        oracle_health_score: 0.95,
        peg_defense_active: true,
    };
    
    let strength = analyzer.calculate_arbitrage_strength(&market_data)?;
    assert!(strength > 0.0, "Should detect arbitrage opportunities");
    
    Ok(())
}

#[test]
fn test_defense_mechanisms_assessment() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    let good_market = PegMarketData {
        current_price: 1.01,
        target_price: 1.00,
        time_since_depeg: 600,
        total_liquidity: 5_000_000.0,
        market_prices: vec![],
        arbitrage_bot_activity: 0.8,
        market_maker_spread: 0.0015,
        emergency_reserves_ratio: 0.15,
        oracle_health_score: 0.9,
        peg_defense_active: true,
    };
    
    let status = analyzer.assess_defense_mechanisms(&good_market)?;
    
    assert!(status.arbitrage_bots_active, "Arbitrage bots should be active");
    assert!(status.market_makers_engaged, "Market makers should be engaged");
    assert!(status.oracle_feeds_healthy, "Oracle feeds should be healthy");
    assert!(status.liquidity_adequate, "Liquidity should be adequate");
    assert!(status.peg_defense_algorithms_operational, "Peg defense should be operational");
    
    Ok(())
}

#[test]
fn test_recovery_time_prediction() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    let market_data = PegMarketData {
        current_price: 1.03,
        target_price: 1.00,
        time_since_depeg: 1200,
        total_liquidity: 2_000_000.0,
        market_prices: vec![],
        arbitrage_bot_activity: 0.6,
        market_maker_spread: 0.002,
        emergency_reserves_ratio: 0.1,
        oracle_health_score: 0.85,
        peg_defense_active: true,
    };
    
    let recovery_time = analyzer.predict_recovery_time(0.03, &market_data)?;
    
    assert!(recovery_time > 0, "Recovery time should be positive");
    assert!(recovery_time <= analyzer.peg_recovery_time_limit, "Recovery time should be within limits");
    
    Ok(())
}

#[test]
fn test_peg_intervention_generation() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    let defense_status = DefenseMechanismsStatus {
        arbitrage_bots_active: false,
        market_makers_engaged: false,
        emergency_reserves_available: 0.08,
        oracle_feeds_healthy: true,
        liquidity_adequate: false,
        peg_defense_algorithms_operational: true,
    };
    
    let interventions = analyzer.generate_peg_interventions(
        0.08, // 8% deviation
        &PegRiskLevel::Severe,
        &defense_status,
    )?;
    
    assert!(!interventions.is_empty(), "Should generate interventions for severe depeg");
    
    // Should include emergency peg defense for severe deviation
    let has_emergency_defense = interventions.iter().any(|i| {
        matches!(i.intervention_type, PegInterventionType::EmergencyPegDefense)
    });
    assert!(has_emergency_defense, "Should include emergency peg defense");
    
    // Should include market maker activation since they're not engaged
    let has_market_maker = interventions.iter().any(|i| {
        matches!(i.intervention_type, PegInterventionType::MarketMakerActivation)
    });
    assert!(has_market_maker, "Should include market maker activation");
    
    // Should include liquidity injection since liquidity is inadequate
    let has_liquidity_injection = interventions.iter().any(|i| {
        matches!(i.intervention_type, PegInterventionType::LiquidityInjection)
    });
    assert!(has_liquidity_injection, "Should include liquidity injection");
    
    Ok(())
}

#[test]
fn test_full_peg_stability_analysis() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    let market_data = PegMarketData {
        current_price: 1.035,
        target_price: 1.00,
        time_since_depeg: 2400,
        total_liquidity: 1_500_000.0,
        market_prices: vec![
            MarketPrice {
                market_name: "DEX A".to_string(),
                price: 1.04,
                liquidity: 800_000.0,
                trading_fees: 0.003,
                volume_24h: 400_000.0,
            },
            MarketPrice {
                market_name: "DEX B".to_string(),
                price: 1.03,
                liquidity: 700_000.0,
                trading_fees: 0.001,
                volume_24h: 350_000.0,
            },
        ],
        arbitrage_bot_activity: 0.4,
        market_maker_spread: 0.0025,
        emergency_reserves_ratio: 0.09,
        oracle_health_score: 0.88,
        peg_defense_active: false,
    };
    
    let risk = analyzer.analyze_peg_stability(&market_data)?;
    
    assert!(risk.current_peg_deviation > 0.03, "Should detect significant depeg");
    assert!(matches!(risk.risk_level, PegRiskLevel::Moderate), "Should classify as moderate risk");
    assert!(risk.depeg_duration == 2400, "Should track depeg duration");
    assert!(risk.predicted_recovery_time > 0, "Should predict recovery time");
    assert!(!risk.required_interventions.is_empty(), "Should suggest interventions");
    
    Ok(())
}

#[test]
fn test_stable_conditions_analysis() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    // Perfect stable conditions
    let stable_market = PegMarketData {
        current_price: 1.002,
        target_price: 1.00,
        time_since_depeg: 0,
        total_liquidity: 10_000_000.0,
        market_prices: vec![
            MarketPrice {
                market_name: "DEX A".to_string(),
                price: 1.001,
                liquidity: 5_000_000.0,
                trading_fees: 0.0005,
                volume_24h: 1_000_000.0,
            },
        ],
        arbitrage_bot_activity: 0.9,
        market_maker_spread: 0.0008,
        emergency_reserves_ratio: 0.2,
        oracle_health_score: 0.98,
        peg_defense_active: true,
    };
    
    let risk = analyzer.analyze_peg_stability(&stable_market)?;
    
    assert!(risk.current_peg_deviation < 0.01, "Should detect minimal deviation");
    assert!(matches!(risk.risk_level, PegRiskLevel::Stable), "Should classify as stable");
    assert!(risk.market_depth_ratio > 1.0, "Should have adequate market depth");
    assert!(risk.defense_mechanisms_status.arbitrage_bots_active, "Defense mechanisms should be active");
    
    Ok(())
}

#[test]
fn test_critical_depeg_scenario() -> Result<()> {
    let analyzer = PegStabilityAnalyzer::new(0.05, 3600, 0.001, 0.8);
    
    // Critical depeg scenario
    let critical_market = PegMarketData {
        current_price: 0.85,
        target_price: 1.00,
        time_since_depeg: 7200,
        total_liquidity: 500_000.0,
        market_prices: vec![
            MarketPrice {
                market_name: "DEX A".to_string(),
                price: 0.83,
                liquidity: 200_000.0,
                trading_fees: 0.01,
                volume_24h: 2_000_000.0,
            },
        ],
        arbitrage_bot_activity: 0.1,
        market_maker_spread: 0.02,
        emergency_reserves_ratio: 0.03,
        oracle_health_score: 0.6,
        peg_defense_active: false,
    };
    
    let risk = analyzer.analyze_peg_stability(&critical_market)?;
    
    assert!(risk.current_peg_deviation > 0.1, "Should detect severe depeg");
    assert!(matches!(risk.risk_level, PegRiskLevel::Critical), "Should classify as critical");
    assert!(risk.market_depth_ratio < 1.0, "Should detect insufficient liquidity");
    assert!(!risk.defense_mechanisms_status.liquidity_adequate, "Should detect liquidity inadequacy");
    
    // Should generate critical interventions
    let has_critical_intervention = risk.required_interventions.iter().any(|i| {
        matches!(i.urgency, InterventionUrgency::Critical)
    });
    assert!(has_critical_intervention, "Should generate critical interventions");
    
    Ok(())
}
