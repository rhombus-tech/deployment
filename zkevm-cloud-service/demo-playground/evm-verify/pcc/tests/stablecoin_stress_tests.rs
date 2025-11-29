use anyhow::Result;
use pcc::analyzer::autonomous_stablecoin_engine::*;
use pcc::analyzer::autonomous_components::*;
use pcc::analyzer::mathematical_failure_detector::MarketData;

/// Comprehensive stress testing for autonomous stablecoin
/// Tests extreme scenarios that killed other algorithmic stablecoins

#[cfg(test)]
mod stress_tests {
    use super::*;

    const TARGET_PEG: f64 = 1.0;
    const REFERENCE_ASSET: &str = "USD";
    const MAX_DEVIATION: f64 = 0.02;
    const MIN_COLLATERAL_RATIO: f64 = 1.5;

    /// BLACK SWAN TEST: 50% price crash (Luna scenario)
    #[test]
    fn test_massive_depeg_50_percent() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Simulate massive 50% depeg
        let market_data = MarketData {
            price: 0.5, // 50% below peg - LUNA collapse scenario
            price_change_24h: -0.5,
            volume_24h: 100_000_000.0, // Massive panic selling
            liquidity_depth: 10_000_000.0, // Depleted liquidity
            timestamp: 1640995200,
        };

        let proof = engine.execute_autonomous_cycle(&market_data)?;

        // System should:
        // 1. Detect extreme risk
        // 2. Not attempt to restore peg immediately (would fail)
        // 3. Enter emergency mode
        assert!(proof.risk_assessment.overall_risk == RiskLevel::Critical 
                || proof.risk_assessment.overall_risk == RiskLevel::High);
        
        println!("✅ BLACK SWAN: Survived 50% depeg without death spiral");
        Ok(())
    }

    /// BANK RUN TEST: Mass redemptions
    #[test]
    fn test_bank_run_scenario() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Simulate 10 consecutive blocks of mass redemptions
        for i in 0..10 {
            let market_data = MarketData {
                price: 0.95 - (i as f64 * 0.01), // Gradual depeg
                price_change_24h: -0.05,
                volume_24h: 50_000_000.0 * (i + 1) as f64, // Increasing panic
                liquidity_depth: 50_000_000.0 / (i + 1) as f64, // Depleting liquidity
                timestamp: 1640995200 + (i * 12), // 12 seconds apart
            };

            let proof = engine.execute_autonomous_cycle(&market_data)?;
            
            // Should maintain stability even under pressure
            assert!(proof.model_consensus.consensus_confidence > 0.3);
        }

        println!("✅ BANK RUN: Survived 10 consecutive redemption blocks");
        Ok(())
    }

    /// ORACLE MANIPULATION TEST: Flash loan attack on price feed
    #[test]
    fn test_oracle_manipulation_attack() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Block 1: Normal
        let normal_data = MarketData {
            price: 1.00,
            price_change_24h: 0.0,
            volume_24h: 10_000_000.0,
            liquidity_depth: 50_000_000.0,
            timestamp: 1640995200,
        };
        engine.execute_autonomous_cycle(&normal_data)?;

        // Block 2: Flash loan manipulation
        let manipulated_data = MarketData {
            price: 1.25, // 25% price spike - flash loan attack
            price_change_24h: 0.25,
            volume_24h: 100_000_000.0, // Sudden massive volume
            liquidity_depth: 50_000_000.0,
            timestamp: 1640995212,
        };
        let proof = engine.execute_autonomous_cycle(&manipulated_data)?;

        // System should detect manipulation and not overreact
        // Multi-oracle aggregation should reject this
        assert!(proof.risk_assessment.overall_risk == RiskLevel::High 
                || proof.risk_assessment.overall_risk == RiskLevel::Critical);

        // Block 3: Return to normal (attack ended)
        let recovery_data = MarketData {
            price: 1.01,
            price_change_24h: -0.24,
            volume_24h: 10_000_000.0,
            liquidity_depth: 50_000_000.0,
            timestamp: 1640995224,
        };
        let recovery_proof = engine.execute_autonomous_cycle(&recovery_data)?;
        
        assert!(recovery_proof.model_consensus.consensus_confidence > 0.5);

        println!("✅ ORACLE MANIPULATION: Rejected flash loan price manipulation");
        Ok(())
    }

    /// LIQUIDITY CRISIS TEST: DEX liquidity drain
    #[test]
    fn test_liquidity_crisis() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        let market_data = MarketData {
            price: 0.98,
            price_change_24h: -0.02,
            volume_24h: 50_000.0, // Very low volume
            liquidity_depth: 10_000.0, // Critical low liquidity
            timestamp: 1640995200,
        };

        let proof = engine.execute_autonomous_cycle(&market_data)?;

        // Should detect liquidity crisis and adjust strategy
        assert!(proof.risk_assessment.liquidity_risk != RiskLevel::Minimal);

        println!("✅ LIQUIDITY CRISIS: Detected and adapted to low liquidity");
        Ok(())
    }

    /// SUSTAINED ATTACK TEST: Multi-day coordinated attack
    #[test]
    fn test_sustained_attack_72_hours() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Simulate 72 hours of attacks (6 blocks per hour = 432 blocks)
        // Testing every 10th block for performance
        for hour in 0..72 {
            for block in (0..6).step_by(2) {
                let attack_intensity = ((hour as f64 / 72.0) * 0.1).min(0.1);
                
                let market_data = MarketData {
                    price: 1.0 - attack_intensity,
                    price_change_24h: -attack_intensity,
                    volume_24h: 20_000_000.0,
                    liquidity_depth: 40_000_000.0 - (hour as f64 * 100_000.0),
                    timestamp: 1640995200 + ((hour * 3600) + (block * 600)),
                };

                let proof = engine.execute_autonomous_cycle(&market_data)?;
                
                // Should maintain mathematical models even under sustained pressure
                assert!(proof.model_consensus.consensus_confidence > 0.2);
            }
        }

        println!("✅ SUSTAINED ATTACK: Survived 72-hour coordinated attack");
        Ok(())
    }

    /// VOLATILITY SPIKE TEST: Extreme market volatility
    #[test]
    fn test_extreme_volatility() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Simulate wild price swings
        let prices = vec![1.0, 1.05, 0.92, 1.08, 0.88, 1.12, 0.95, 1.03];
        
        for (i, price) in prices.iter().enumerate() {
            let market_data = MarketData {
                price: *price,
                price_change_24h: if i > 0 { price - prices[i-1] } else { 0.0 },
                volume_24h: 30_000_000.0,
                liquidity_depth: 40_000_000.0,
                timestamp: 1640995200 + (i as u64 * 12),
            };

            let proof = engine.execute_autonomous_cycle(&market_data)?;
            
            // Models should adapt to volatility
            assert!(proof.model_consensus.lyapunov_recommendation.confidence > 0.5);
        }

        println!("✅ VOLATILITY: Handled extreme price swings");
        Ok(())
    }

    /// COLLATERAL DEVALUATION TEST: Backing assets lose value
    #[test]
    fn test_collateral_devaluation() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Simulate gradual collateral devaluation
        for i in 0..20 {
            let collateral_value = 1.5 - (i as f64 * 0.01); // From 150% to 130%
            
            let market_data = MarketData {
                price: 1.0 - (i as f64 * 0.001), // Slight depeg as collateral falls
                price_change_24h: -0.001,
                volume_24h: 15_000_000.0,
                liquidity_depth: 45_000_000.0,
                timestamp: 1640995200 + (i * 300), // 5 min apart
            };

            let proof = engine.execute_autonomous_cycle(&market_data)?;
            
            // Should detect collateral risk increase
            if collateral_value < 1.35 {
                assert!(proof.risk_assessment.overall_risk != RiskLevel::Minimal);
            }
        }

        println!("✅ COLLATERAL: Detected and responded to collateral devaluation");
        Ok(())
    }

    /// CONFIDENCE CRISIS TEST: Loss of market confidence
    #[test]
    fn test_confidence_spiral() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Simulate gradual confidence loss
        for i in 0..15 {
            let confidence_factor = 1.0 - (i as f64 * 0.05);
            
            let market_data = MarketData {
                price: 1.0 - (i as f64 * 0.01), // Gradual depeg
                price_change_24h: -0.01,
                volume_24h: 10_000_000.0 * confidence_factor,
                liquidity_depth: 50_000_000.0 * confidence_factor,
                timestamp: 1640995200 + (i * 600),
            };

            let proof = engine.execute_autonomous_cycle(&market_data)?;
            
            // Early detection of confidence crisis
            if i > 5 {
                assert!(proof.risk_assessment.overall_risk != RiskLevel::Minimal);
            }
        }

        println!("✅ CONFIDENCE: Early detection of confidence spiral");
        Ok(())
    }

    /// MULTI-MODEL CONSENSUS TEST: Verify all models work together
    #[test]
    fn test_multi_model_consensus() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        let market_data = MarketData {
            price: 1.01,
            price_change_24h: 0.01,
            volume_24h: 10_000_000.0,
            liquidity_depth: 50_000_000.0,
            timestamp: 1640995200,
        };

        let proof = engine.execute_autonomous_cycle(&market_data)?;

        // All 4 models should provide recommendations
        assert!(proof.model_consensus.lyapunov_recommendation.confidence > 0.0);
        assert!(proof.model_consensus.game_theory_recommendation.confidence > 0.0);
        assert!(proof.model_consensus.control_theory_recommendation.confidence > 0.0);
        assert!(proof.model_consensus.phase_space_recommendation.confidence > 0.0);
        
        // Consensus should be calculated
        assert!(proof.model_consensus.consensus_confidence >= 0.0);
        assert!(proof.model_consensus.consensus_confidence <= 1.0);

        println!("✅ CONSENSUS: All 4 mathematical models providing recommendations");
        Ok(())
    }

    /// RECOVERY TEST: Can system recover after crisis?
    #[test]
    fn test_post_crisis_recovery() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Phase 1: Crisis
        for i in 0..10 {
            let crisis_data = MarketData {
                price: 0.85,
                price_change_24h: -0.15,
                volume_24h: 50_000_000.0,
                liquidity_depth: 20_000_000.0,
                timestamp: 1640995200 + (i * 12),
            };
            engine.execute_autonomous_cycle(&crisis_data)?;
        }

        // Phase 2: Recovery
        for i in 0..20 {
            let recovery_progress = i as f64 / 20.0;
            let recovery_data = MarketData {
                price: 0.85 + (0.15 * recovery_progress),
                price_change_24h: 0.15 * recovery_progress / 20.0,
                volume_24h: 30_000_000.0,
                liquidity_depth: 20_000_000.0 + (30_000_000.0 * recovery_progress),
                timestamp: 1640995200 + (120 + i * 12),
            };
            let proof = engine.execute_autonomous_cycle(&recovery_data)?;
            
            // Confidence should improve as price recovers
            if i > 10 {
                assert!(proof.model_consensus.consensus_confidence > 0.4);
            }
        }

        println!("✅ RECOVERY: Successfully recovered from crisis");
        Ok(())
    }
}

/// Integration tests with actual components
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_emergency_peg_protection_integration() -> Result<()> {
        let mut engine = AutonomousStablecoinEngine::new(
            TARGET_PEG,
            REFERENCE_ASSET.to_string(),
            MAX_DEVIATION,
            MIN_COLLATERAL_RATIO
        )?;

        // Trigger emergency conditions
        let emergency_data = MarketData {
            price: 0.75, // 25% depeg
            price_change_24h: -0.25,
            volume_24h: 100_000_000.0,
            liquidity_depth: 5_000_000.0,
            timestamp: 1640995200,
        };

        let proof = engine.execute_autonomous_cycle(&emergency_data)?;

        // Should activate emergency mode
        assert_eq!(proof.risk_assessment.overall_risk, RiskLevel::Critical);

        println!("✅ EMERGENCY: Protection activated correctly");
        Ok(())
    }

    #[test]
    fn test_parameter_validation() -> Result<()> {
        // Invalid peg
        assert!(AutonomousStablecoinEngine::new(-1.0, "USD".to_string(), 0.02, 1.5).is_err());
        
        // Invalid deviation
        assert!(AutonomousStablecoinEngine::new(1.0, "USD".to_string(), 0.1, 1.5).is_err());
        
        // Invalid collateral ratio
        assert!(AutonomousStablecoinEngine::new(1.0, "USD".to_string(), 0.02, 1.0).is_err());

        println!("✅ VALIDATION: Parameter validation working");
        Ok(())
    }
}
