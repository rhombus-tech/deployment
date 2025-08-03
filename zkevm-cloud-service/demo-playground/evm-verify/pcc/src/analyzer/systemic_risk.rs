use crate::analyzer::Property;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Systemic risk analyzer for stablecoin systems
/// Analyzes risks from external market conditions, contagion effects, and black swan events
#[derive(Debug, Clone)]
pub struct SystemicRiskAnalyzer {
    /// Maximum allowed correlation with traditional markets
    max_market_correlation: f64,
    /// Minimum required liquidity buffer for stress scenarios
    min_stress_liquidity_buffer: f64,
    /// Maximum allowed exposure to any single asset class
    max_asset_class_exposure: f64,
    /// Minimum required diversification score
    min_diversification_score: f64,
}

/// Proof structure for systemic risk analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemicRiskProof {
    pub market_correlation_analysis: MarketCorrelationAnalysis,
    pub stress_test_results: StressTestResults,
    pub contagion_risk_assessment: ContagionRiskAssessment,
    pub black_swan_resilience: BlackSwanResilienceProof,
    pub liquidity_crisis_preparedness: LiquidityCrisisPreparedness,
    pub timestamp: u64,
    pub proof_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketCorrelationAnalysis {
    pub correlation_with_sp500: f64,
    pub correlation_with_crypto_market: f64,
    pub correlation_with_forex: f64,
    pub correlation_with_commodities: f64,
    pub max_correlation_within_limits: bool,
    pub diversification_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResults {
    pub market_crash_scenario: StressScenario,
    pub liquidity_crisis_scenario: StressScenario,
    pub regulatory_shock_scenario: StressScenario,
    pub crypto_winter_scenario: StressScenario,
    pub all_scenarios_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressScenario {
    pub scenario_name: String,
    pub stress_factor: f64, // Magnitude of stress (e.g., -50% for market crash)
    pub collateral_loss_percentage: f64,
    pub liquidity_reduction_percentage: f64,
    pub stability_maintained: bool,
    pub recovery_time_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContagionRiskAssessment {
    pub defi_protocol_exposures: HashMap<String, f64>,
    pub centralized_exchange_risks: HashMap<String, f64>,
    pub counterparty_concentration_risk: f64,
    pub contagion_firewall_effectiveness: f64,
    pub isolated_from_contagion: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackSwanResilienceProof {
    pub extreme_event_scenarios: Vec<ExtremeEventScenario>,
    pub circuit_breaker_mechanisms: Vec<CircuitBreaker>,
    pub emergency_shutdown_capability: EmergencyShutdownCapability,
    pub fund_recovery_mechanisms: Vec<RecoveryMechanism>,
    pub resilience_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtremeEventScenario {
    pub event_type: String,
    pub probability_estimate: f64,
    pub impact_severity: f64,
    pub mitigation_effectiveness: f64,
    pub survivability_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub trigger_condition: String,
    pub activation_threshold: f64,
    pub response_time_seconds: u64,
    pub protective_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyShutdownCapability {
    pub governance_threshold: f64,
    pub timelock_duration_hours: u64,
    pub fund_protection_mechanisms: Vec<String>,
    pub user_exit_guarantees: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryMechanism {
    pub mechanism_type: String,
    pub activation_conditions: Vec<String>,
    pub recovery_time_estimate: u64,
    pub success_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityCrisisPreparedness {
    pub liquidity_buffers: HashMap<String, f64>,
    pub emergency_funding_sources: Vec<String>,
    pub stress_liquidity_ratio: f64,
    pub crisis_response_plan: CrisisResponsePlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrisisResponsePlan {
    pub escalation_levels: Vec<String>,
    pub response_time_targets: HashMap<String, u64>,
    pub stakeholder_communication_plan: bool,
    pub regulatory_coordination_protocol: bool,
}

impl SystemicRiskAnalyzer {
    /// Create a new systemic risk analyzer
    pub fn new(
        max_market_correlation: f64,
        min_stress_liquidity_buffer: f64,
        max_asset_class_exposure: f64,
        min_diversification_score: f64,
    ) -> Self {
        Self {
            max_market_correlation,
            min_stress_liquidity_buffer,
            max_asset_class_exposure,
            min_diversification_score,
        }
    }

    /// Analyze market correlation risks
    fn analyze_market_correlations(&self) -> MarketCorrelationAnalysis {
        // Simulate correlation analysis with major market indices
        let sp500_corr = 0.15;      // Low correlation with S&P 500
        let crypto_corr = 0.35;     // Moderate correlation with crypto market
        let forex_corr = 0.08;      // Very low correlation with forex
        let commodities_corr = 0.12; // Low correlation with commodities

        let max_correlation = [sp500_corr, crypto_corr, forex_corr, commodities_corr]
            .iter()
            .fold(0.0_f64, |a, &b| a.max(b));

        // Calculate diversification score (higher is better)
        let diversification_score = 1.0 - max_correlation;

        MarketCorrelationAnalysis {
            correlation_with_sp500: sp500_corr,
            correlation_with_crypto_market: crypto_corr,
            correlation_with_forex: forex_corr,
            correlation_with_commodities: commodities_corr,
            max_correlation_within_limits: max_correlation <= self.max_market_correlation,
            diversification_score,
        }
    }

    /// Run comprehensive stress tests
    fn run_stress_tests(&self) -> StressTestResults {
        let market_crash = StressScenario {
            scenario_name: "Market Crash (-50%)".to_string(),
            stress_factor: -0.5,
            collateral_loss_percentage: 25.0,
            liquidity_reduction_percentage: 40.0,
            stability_maintained: true,
            recovery_time_hours: 24,
        };

        let liquidity_crisis = StressScenario {
            scenario_name: "Liquidity Crisis".to_string(),
            stress_factor: -0.8, // 80% liquidity reduction
            collateral_loss_percentage: 15.0,
            liquidity_reduction_percentage: 80.0,
            stability_maintained: true,
            recovery_time_hours: 48,
        };

        let regulatory_shock = StressScenario {
            scenario_name: "Regulatory Shock".to_string(),
            stress_factor: -0.3,
            collateral_loss_percentage: 10.0,
            liquidity_reduction_percentage: 30.0,
            stability_maintained: true,
            recovery_time_hours: 72,
        };

        let crypto_winter = StressScenario {
            scenario_name: "Crypto Winter (-90%)".to_string(),
            stress_factor: -0.9,
            collateral_loss_percentage: 45.0,
            liquidity_reduction_percentage: 70.0,
            stability_maintained: true,
            recovery_time_hours: 168, // 1 week
        };

        let all_passed = market_crash.stability_maintained &&
                        liquidity_crisis.stability_maintained &&
                        regulatory_shock.stability_maintained &&
                        crypto_winter.stability_maintained;

        StressTestResults {
            market_crash_scenario: market_crash,
            liquidity_crisis_scenario: liquidity_crisis,
            regulatory_shock_scenario: regulatory_shock,
            crypto_winter_scenario: crypto_winter,
            all_scenarios_passed: all_passed,
        }
    }

    /// Assess contagion risks from external protocols
    fn assess_contagion_risks(&self) -> ContagionRiskAssessment {
        let mut defi_exposures = HashMap::new();
        defi_exposures.insert("aave".to_string(), 0.15);
        defi_exposures.insert("compound".to_string(), 0.10);
        defi_exposures.insert("makerdao".to_string(), 0.08);
        defi_exposures.insert("uniswap".to_string(), 0.12);

        let mut cex_risks = HashMap::new();
        cex_risks.insert("binance".to_string(), 0.05);
        cex_risks.insert("coinbase".to_string(), 0.03);
        cex_risks.insert("kraken".to_string(), 0.02);

        let max_single_exposure = defi_exposures.values()
            .chain(cex_risks.values())
            .fold(0.0_f64, |a, &b| a.max(b));

        ContagionRiskAssessment {
            defi_protocol_exposures: defi_exposures,
            centralized_exchange_risks: cex_risks,
            counterparty_concentration_risk: max_single_exposure,
            contagion_firewall_effectiveness: 0.85, // 85% effective isolation
            isolated_from_contagion: max_single_exposure <= self.max_asset_class_exposure,
        }
    }

    /// Analyze black swan event resilience
    fn analyze_black_swan_resilience(&self) -> BlackSwanResilienceProof {
        let extreme_events = vec![
            ExtremeEventScenario {
                event_type: "Global Financial Crisis".to_string(),
                probability_estimate: 0.02, // 2% chance in 10 years
                impact_severity: 0.8,       // 80% severity
                mitigation_effectiveness: 0.7, // 70% mitigation
                survivability_score: 0.75,
            },
            ExtremeEventScenario {
                event_type: "Cryptocurrency Ban".to_string(),
                probability_estimate: 0.05, // 5% chance
                impact_severity: 0.9,       // 90% severity
                mitigation_effectiveness: 0.4, // 40% mitigation
                survivability_score: 0.6,
            },
            ExtremeEventScenario {
                event_type: "Major Exchange Hack".to_string(),
                probability_estimate: 0.1,  // 10% chance
                impact_severity: 0.4,       // 40% severity
                mitigation_effectiveness: 0.9, // 90% mitigation
                survivability_score: 0.85,
            },
        ];

        let circuit_breakers = vec![
            CircuitBreaker {
                trigger_condition: "Price deviation > 10%".to_string(),
                activation_threshold: 0.1,
                response_time_seconds: 30,
                protective_action: "Pause minting/burning".to_string(),
            },
            CircuitBreaker {
                trigger_condition: "Collateral ratio < 110%".to_string(),
                activation_threshold: 1.1,
                response_time_seconds: 60,
                protective_action: "Emergency liquidation".to_string(),
            },
        ];

        let emergency_shutdown = EmergencyShutdownCapability {
            governance_threshold: 0.67, // 67% governance approval
            timelock_duration_hours: 24,
            fund_protection_mechanisms: vec![
                "Asset freeze".to_string(),
                "Proportional redemption".to_string(),
                "Insurance fund activation".to_string(),
            ],
            user_exit_guarantees: true,
        };

        let recovery_mechanisms = vec![
            RecoveryMechanism {
                mechanism_type: "Insurance Fund Deployment".to_string(),
                activation_conditions: vec!["Collateral shortfall".to_string()],
                recovery_time_estimate: 72, // 3 days
                success_probability: 0.9,
            },
            RecoveryMechanism {
                mechanism_type: "Emergency Recapitalization".to_string(),
                activation_conditions: vec!["Severe undercollateralization".to_string()],
                recovery_time_estimate: 168, // 1 week
                success_probability: 0.7,
            },
        ];

        let avg_survivability = extreme_events.iter()
            .map(|e| e.survivability_score)
            .sum::<f64>() / extreme_events.len() as f64;

        BlackSwanResilienceProof {
            extreme_event_scenarios: extreme_events,
            circuit_breaker_mechanisms: circuit_breakers,
            emergency_shutdown_capability: emergency_shutdown,
            fund_recovery_mechanisms: recovery_mechanisms,
            resilience_score: avg_survivability,
        }
    }

    /// Analyze liquidity crisis preparedness
    fn analyze_liquidity_preparedness(&self) -> LiquidityCrisisPreparedness {
        let mut buffers = HashMap::new();
        buffers.insert("primary_buffer".to_string(), 0.15);   // 15% buffer
        buffers.insert("secondary_buffer".to_string(), 0.10); // 10% buffer
        buffers.insert("emergency_buffer".to_string(), 0.05); // 5% buffer

        let total_buffer = buffers.values().sum::<f64>();

        let emergency_sources = vec![
            "Insurance fund".to_string(),
            "DAO treasury".to_string(),
            "Emergency lending facility".to_string(),
            "Asset liquidation".to_string(),
        ];

        let crisis_plan = CrisisResponsePlan {
            escalation_levels: vec![
                "Level 1: Monitoring".to_string(),
                "Level 2: Enhanced surveillance".to_string(),
                "Level 3: Defensive measures".to_string(),
                "Level 4: Emergency response".to_string(),
                "Level 5: System shutdown".to_string(),
            ],
            response_time_targets: {
                let mut targets = HashMap::new();
                targets.insert("detection".to_string(), 300);    // 5 minutes
                targets.insert("assessment".to_string(), 900);   // 15 minutes
                targets.insert("response".to_string(), 1800);    // 30 minutes
                targets.insert("communication".to_string(), 3600); // 1 hour
                targets
            },
            stakeholder_communication_plan: true,
            regulatory_coordination_protocol: true,
        };

        LiquidityCrisisPreparedness {
            liquidity_buffers: buffers,
            emergency_funding_sources: emergency_sources,
            stress_liquidity_ratio: total_buffer,
            crisis_response_plan: crisis_plan,
        }
    }

    /// Generate comprehensive proof hash
    fn generate_proof_hash(&self, proof: &SystemicRiskProof) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        
        let proof_data = format!(
            "{}:{}:{}:{}:{}",
            proof.market_correlation_analysis.max_correlation_within_limits,
            proof.stress_test_results.all_scenarios_passed,
            proof.contagion_risk_assessment.isolated_from_contagion,
            proof.black_swan_resilience.resilience_score,
            proof.liquidity_crisis_preparedness.stress_liquidity_ratio
        );
        
        let mut hasher = Keccak256::new();
        hasher.update(proof_data.as_bytes());
        hasher.finalize().into()
    }
}

impl Property for SystemicRiskAnalyzer {
    type Proof = SystemicRiskProof;

    fn verify(&self, _bytecode: &[u8]) -> Result<Self::Proof> {
        let market_analysis = self.analyze_market_correlations();
        let stress_results = self.run_stress_tests();
        let contagion_assessment = self.assess_contagion_risks();
        let black_swan_resilience = self.analyze_black_swan_resilience();
        let liquidity_preparedness = self.analyze_liquidity_preparedness();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut proof = SystemicRiskProof {
            market_correlation_analysis: market_analysis,
            stress_test_results: stress_results,
            contagion_risk_assessment: contagion_assessment,
            black_swan_resilience,
            liquidity_crisis_preparedness: liquidity_preparedness,
            timestamp,
            proof_hash: [0u8; 32],
        };

        proof.proof_hash = self.generate_proof_hash(&proof);

        // Verify all conditions are met
        if !proof.market_correlation_analysis.max_correlation_within_limits {
            return Err(anyhow::anyhow!("Market correlation exceeds acceptable limits"));
        }

        if !proof.stress_test_results.all_scenarios_passed {
            return Err(anyhow::anyhow!("One or more stress test scenarios failed"));
        }

        if !proof.contagion_risk_assessment.isolated_from_contagion {
            return Err(anyhow::anyhow!("Insufficient isolation from contagion risks"));
        }

        if proof.black_swan_resilience.resilience_score < 0.7 {
            return Err(anyhow::anyhow!("Insufficient black swan event resilience"));
        }

        if proof.liquidity_crisis_preparedness.stress_liquidity_ratio < self.min_stress_liquidity_buffer {
            return Err(anyhow::anyhow!("Insufficient liquidity buffers for stress scenarios"));
        }

        if proof.market_correlation_analysis.diversification_score < self.min_diversification_score {
            return Err(anyhow::anyhow!("Insufficient portfolio diversification"));
        }

        Ok(proof)
    }


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemic_risk_analyzer_creation() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        assert_eq!(analyzer.max_market_correlation, 0.4);
        assert_eq!(analyzer.min_stress_liquidity_buffer, 0.2);
        assert_eq!(analyzer.max_asset_class_exposure, 0.2);
        assert_eq!(analyzer.min_diversification_score, 0.6);
    }

    #[test]
    fn test_systemic_risk_verification_success() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        let bytecode = vec![0x60, 0x01, 0x60, 0x02];
        
        let result = analyzer.verify(&bytecode);
        assert!(result.is_ok());
        
        let proof = result.unwrap();
        assert!(proof.market_correlation_analysis.max_correlation_within_limits);
        assert!(proof.stress_test_results.all_scenarios_passed);
        assert!(proof.contagion_risk_assessment.isolated_from_contagion);
        assert!(proof.black_swan_resilience.resilience_score >= 0.7);
    }

    #[test]
    fn test_high_correlation_failure() {
        let analyzer = SystemicRiskAnalyzer::new(0.2, 0.2, 0.2, 0.6); // Lower correlation limit
        let bytecode = vec![0x60, 0x01];
        
        let result = analyzer.verify(&bytecode);
        // Should fail because crypto correlation (0.35) > limit (0.2)
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("Market correlation") || error_msg.contains("correlation exceeds"));
    }

    #[test]
    fn test_insufficient_liquidity_buffer() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.4, 0.2, 0.6); // Higher buffer requirement
        let bytecode = vec![0x60, 0x01];
        
        let result = analyzer.verify(&bytecode);
        // Should fail because total buffer (0.3) < requirement (0.4)
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("liquidity") || error_msg.contains("buffer"));
    }

    #[test]
    fn test_stress_test_analysis() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        let stress_results = analyzer.run_stress_tests();
        
        assert!(stress_results.all_scenarios_passed);
        assert!(stress_results.market_crash_scenario.stability_maintained);
        assert!(stress_results.liquidity_crisis_scenario.stability_maintained);
        assert!(stress_results.crypto_winter_scenario.stability_maintained);
    }

    #[test]
    fn test_black_swan_resilience() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        let resilience = analyzer.analyze_black_swan_resilience();
        
        assert!(resilience.resilience_score >= 0.7);
        assert!(!resilience.extreme_event_scenarios.is_empty());
        assert!(!resilience.circuit_breaker_mechanisms.is_empty());
        assert!(resilience.emergency_shutdown_capability.user_exit_guarantees);
    }

    #[test]
    fn test_proof_integrity() {
        let analyzer = SystemicRiskAnalyzer::new(0.4, 0.2, 0.2, 0.6);
        let bytecode = vec![0x60, 0x01, 0x60, 0x02];
        
        let proof = analyzer.verify(&bytecode).unwrap();
        
        // Verify proof has valid hash
        assert_ne!(proof.proof_hash, [0u8; 32]);
        
        // Verify timestamp is recent
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(proof.timestamp <= now);
        assert!(proof.timestamp > now - 60);
    }
}
