use super::super::death_spiral_prevention::*;
use anyhow::Result;

#[test]
fn test_death_spiral_analyzer_creation() {
    let analyzer = DeathSpiralPreventionAnalyzer::new(
        0.6,  // confidence_threshold
        0.1,  // max_redemption_velocity
        1.2,  // min_reserve_buffer
        3.0,  // max_reflexivity_factor
    );
    
    assert_eq!(analyzer.confidence_threshold, 0.6);
    assert_eq!(analyzer.max_redemption_velocity, 0.1);
}

#[test]
fn test_confidence_level_calculation() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    // Normal market conditions
    let normal_market = MarketData {
        peg_deviation: 0.01,          // 1% deviation
        current_redemption_rate: 0.05, // 50% of max rate
        social_sentiment: 0.8,         // Good sentiment
        reserve_ratio: 1.5,            // 150% backed
        volume_volatility: 0.2,        // Low volatility
        confidence_decay_rate: 0.0,    // Stable
        market_cap: 100_000_000.0,
        daily_volume: 5_000_000.0,
    };
    
    let confidence = analyzer.calculate_confidence_level(&normal_market)?;
    assert!(confidence > 0.7, "Confidence should be high in normal conditions");
    
    // Crisis market conditions
    let crisis_market = MarketData {
        peg_deviation: 0.08,           // 8% deviation
        current_redemption_rate: 0.15, // 150% of max rate
        social_sentiment: 0.2,         // Low sentiment
        reserve_ratio: 1.1,            // Low reserves
        volume_volatility: 1.0,        // High volatility
        confidence_decay_rate: 0.1,    // Rapid decay
        market_cap: 100_000_000.0,
        daily_volume: 50_000_000.0,
    };
    
    let confidence = analyzer.calculate_confidence_level(&crisis_market)?;
    assert!(confidence < 0.4, "Confidence should be low in crisis conditions");
    
    Ok(())
}

#[test]
fn test_death_spiral_probability_calculation() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    let crisis_market = MarketData {
        peg_deviation: 0.10,
        current_redemption_rate: 0.2,
        social_sentiment: 0.1,
        reserve_ratio: 1.05,
        volume_volatility: 1.5,
        confidence_decay_rate: 0.2,
        market_cap: 100_000_000.0,
        daily_volume: 100_000_000.0,
    };
    
    let confidence_level = 0.3; // Below threshold
    let redemption_velocity_ratio = 2.0; // 200% of max
    let reflexivity_factor = 2.5;
    
    let probability = analyzer.calculate_death_spiral_probability(
        confidence_level,
        redemption_velocity_ratio,
        1.0, // reserve_buffer_ratio
        reflexivity_factor,
        &crisis_market,
    )?;
    
    assert!(probability > 0.6, "Death spiral probability should be high in crisis (got {})", probability);
    
    Ok(())
}

#[test]
fn test_intervention_generation() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    // Critical situation requiring emergency interventions
    let interventions = analyzer.generate_interventions(0.2, 1.5, 2.0, 0.9)?;
    
    assert!(!interventions.is_empty(), "Should generate interventions for critical situation");
    
    // Check for emergency reserve injection
    let has_emergency_injection = interventions.iter().any(|i| {
        matches!(i.intervention_type, InterventionType::EmergencyReserveInjection)
    });
    assert!(has_emergency_injection, "Should include emergency reserve injection");
    
    // Check for critical urgency
    let has_critical_urgency = interventions.iter().any(|i| {
        matches!(i.urgency, InterventionUrgency::Critical)
    });
    assert!(has_critical_urgency, "Should include critical urgency interventions");
    
    Ok(())
}

#[test]
fn test_recovery_timeline_creation() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    let timeline = analyzer.create_recovery_timeline(0.2, 0.8)?;
    
    assert!(!timeline.immediate_actions.is_empty(), "Should have immediate actions");
    assert!(!timeline.short_term_actions.is_empty(), "Should have short-term actions");
    assert!(!timeline.long_term_confidence_building.is_empty(), "Should have long-term actions");
    assert!(timeline.estimated_recovery_time > 0, "Should have estimated recovery time");
    
    Ok(())
}

#[test]
fn test_full_death_spiral_analysis() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    let market_data = MarketData {
        peg_deviation: 0.05,
        current_redemption_rate: 0.08,
        social_sentiment: 0.4,
        reserve_ratio: 1.3,
        volume_volatility: 0.6,
        confidence_decay_rate: 0.05,
        market_cap: 100_000_000.0,
        daily_volume: 10_000_000.0,
    };
    
    let risk = analyzer.analyze_death_spiral_risk(&market_data)?;
    
    assert!(risk.confidence_level >= 0.0 && risk.confidence_level <= 1.0);
    assert!(risk.death_spiral_probability >= 0.0 && risk.death_spiral_probability <= 1.0);
    assert!(risk.redemption_velocity_ratio >= 0.0);
    assert!(risk.reflexivity_factor >= 1.0);
    assert!(!risk.required_interventions.is_empty());
    
    Ok(())
}

#[test]
fn test_time_to_critical_calculation() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    // Already critical
    let time_critical = analyzer.calculate_time_to_critical(0.5, 0.1)?;
    assert_eq!(time_critical, 0, "Should be 0 if already critical");
    
    // Stable confidence
    let time_stable = analyzer.calculate_time_to_critical(0.8, 0.0)?;
    assert_eq!(time_stable, u64::MAX, "Should be max if stable");
    
    // Decaying confidence
    let time_decaying = analyzer.calculate_time_to_critical(0.8, 0.1)?;
    assert!(time_decaying > 0 && time_decaying < u64::MAX, "Should have finite time to critical");
    
    Ok(())
}

#[test]
fn test_reflexivity_factor_calculation() -> Result<()> {
    let analyzer = DeathSpiralPreventionAnalyzer::new(0.6, 0.1, 1.2, 3.0);
    
    // Low reflexivity market
    let stable_market = MarketData {
        peg_deviation: 0.005,
        current_redemption_rate: 0.02,
        social_sentiment: 0.9,
        reserve_ratio: 1.8,
        volume_volatility: 0.1,
        confidence_decay_rate: 0.0,
        market_cap: 100_000_000.0,
        daily_volume: 2_000_000.0,
    };
    
    let low_reflexivity = analyzer.calculate_reflexivity_factor(&stable_market)?;
    assert!(low_reflexivity < 1.5, "Reflexivity should be low in stable conditions");
    
    // High reflexivity market
    let volatile_market = MarketData {
        peg_deviation: 0.08,
        current_redemption_rate: 0.12,
        social_sentiment: 0.2,
        reserve_ratio: 1.1,
        volume_volatility: 1.2,
        confidence_decay_rate: 0.15,
        market_cap: 100_000_000.0,
        daily_volume: 80_000_000.0,
    };
    
    let high_reflexivity = analyzer.calculate_reflexivity_factor(&volatile_market)?;
    assert!(high_reflexivity > 2.0, "Reflexivity should be high in volatile conditions");
    
    Ok(())
}
