use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlackSwanEventType {
    CryptoMarketCrash50Percent,
    CryptoMarketCrash80Percent,
    StablecoinBankRunCascade,
    CorrelatedAssetFailure,
    RegulatoryShutdown,
    NetworkPartitioning,
    ExchangeDelistingCascade,
    InfrastructureFailure,
    SovereignDefaultCrisis,
    HyperInflationScenario,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackSwanScenario {
    pub event_type: BlackSwanEventType,
    pub severity: SecuritySeverity,
    pub probability_annual: f32,
    pub market_impact_percent: f32,
    pub duration_days: u32,
    pub collateral_impact_percent: f32,
    pub liquidity_impact_percent: f32,
    pub user_behavior_panic_factor: f32,
    pub recovery_time_weeks: u32,
    pub economic_loss_billions: f64,
    pub systemic_contagion_risk: f32,
    pub mitigation_effectiveness: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    pub scenario: BlackSwanScenario,
    pub protocol_survival_probability: f32,
    pub max_drawdown_percent: f32,
    pub liquidity_exhaustion_time_hours: u32,
    pub required_reserves_multiplier: f32,
    pub governance_response_adequacy: f32,
    pub user_confidence_impact: f32,
    pub cascade_propagation_risk: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackSwanVulnerability {
    pub event_type: BlackSwanEventType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub simulation_confidence: f32,
    pub impact_assessment: StressTestResult,
    pub mitigation_strategy: String,
    pub estimated_probability: f32,
}

pub struct BlackSwanSimulator {
    bytecode: Vec<u8>,
    collateral_functions: HashSet<[u8; 4]>,
    emergency_functions: HashSet<[u8; 4]>,
    oracle_functions: HashSet<[u8; 4]>,
    governance_functions: HashSet<[u8; 4]>,
    execution_trace: Option<EVMExecutionTrace>,
    collateral_composition: HashMap<String, f32>, // Asset -> percentage
    reserve_ratio: f32,
    circuit_breaker_thresholds: Vec<f32>,
}

impl BlackSwanSimulator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut collateral_functions = HashSet::new();
        collateral_functions.insert([0x70, 0xa0, 0x82, 0x31]); // balanceOf()
        collateral_functions.insert([0xa6, 0x94, 0xfc, 0x3a]); // deposit()
        collateral_functions.insert([0x2e, 0x1a, 0x7d, 0x4d]); // withdraw()

        let mut emergency_functions = HashSet::new();
        emergency_functions.insert([0x8d, 0xa5, 0xcb, 0x5b]); // pause()
        emergency_functions.insert([0x5c, 0x97, 0x5a, 0xbb]); // emergencyWithdraw()
        emergency_functions.insert([0x3f, 0x4b, 0xa8, 0x3a]); // unpause()

        let mut oracle_functions = HashSet::new();
        oracle_functions.insert([0x50, 0xd2, 0x5b, 0xcd]); // latestAnswer()
        oracle_functions.insert([0xfe, 0xaf, 0x96, 0x8c]); // latestRoundData()

        let mut governance_functions = HashSet::new();
        governance_functions.insert([0x40, 0xe5, 0x8e, 0xe5]); // propose()
        governance_functions.insert([0x15, 0x37, 0x3e, 0x3d]); // vote()
        governance_functions.insert([0xfe, 0x0d, 0x94, 0xc1]); // execute()

        let mut collateral_composition = HashMap::new();
        collateral_composition.insert("ETH".to_string(), 0.4);
        collateral_composition.insert("BTC".to_string(), 0.3);
        collateral_composition.insert("USDC".to_string(), 0.2);
        collateral_composition.insert("Other".to_string(), 0.1);

        Self {
            bytecode,
            collateral_functions,
            emergency_functions,
            oracle_functions,
            governance_functions,
            execution_trace: None,
            collateral_composition,
            reserve_ratio: 1.5, // 150% over-collateralization
            circuit_breaker_thresholds: vec![0.05, 0.10, 0.20], // 5%, 10%, 20% triggers
        }
    }

    pub fn with_collateral_composition(mut self, composition: HashMap<String, f32>) -> Self {
        self.collateral_composition = composition;
        self
    }

    pub fn with_reserve_ratio(mut self, ratio: f32) -> Self {
        self.reserve_ratio = ratio;
        self
    }

    pub fn simulate_black_swan_events(&self) -> Vec<BlackSwanVulnerability> {
        let mut vulnerabilities = Vec::new();

        let scenarios = self.generate_black_swan_scenarios();
        for scenario in scenarios {
            let stress_result = self.simulate_scenario(&scenario);
            
            // Convert stress test result to vulnerability
            let vulnerability = BlackSwanVulnerability {
                event_type: scenario.event_type.clone(),
                severity: scenario.severity.clone(),
                description: format!("Black swan event: {:?} with {}% market impact", scenario.event_type, scenario.market_impact_percent),
                simulation_confidence: stress_result.protocol_survival_probability,
                impact_assessment: stress_result,
                mitigation_strategy: "Implement emergency reserves and circuit breakers".to_string(),
                estimated_probability: scenario.probability_annual,
            };
            vulnerabilities.push(vulnerability);
        }

        vulnerabilities
    }

    fn generate_black_swan_scenarios(&self) -> Vec<BlackSwanScenario> {
        vec![
            // 50% Crypto Market Crash
            BlackSwanScenario {
                event_type: BlackSwanEventType::CryptoMarketCrash50Percent,
                severity: SecuritySeverity::High,
                probability_annual: 0.1, // 10% annual probability
                market_impact_percent: 50.0,
                duration_days: 30,
                collateral_impact_percent: 45.0, // Slightly less than market due to diversification
                liquidity_impact_percent: 70.0, // Higher liquidity impact
                user_behavior_panic_factor: 0.6,
                recovery_time_weeks: 12,
                economic_loss_billions: 500.0,
                systemic_contagion_risk: 0.7,
                mitigation_effectiveness: 0.4,
            },

            // 80% Crypto Market Crash (2018-style)
            BlackSwanScenario {
                event_type: BlackSwanEventType::CryptoMarketCrash80Percent,
                severity: SecuritySeverity::Critical,
                probability_annual: 0.02, // 2% annual probability
                market_impact_percent: 80.0,
                duration_days: 90,
                collateral_impact_percent: 75.0,
                liquidity_impact_percent: 90.0,
                user_behavior_panic_factor: 0.9,
                recovery_time_weeks: 52, // 1 year recovery
                economic_loss_billions: 2000.0,
                systemic_contagion_risk: 0.95,
                mitigation_effectiveness: 0.1, // Very limited effectiveness
            },

            // Stablecoin Bank Run Cascade (UST-style)
            BlackSwanScenario {
                event_type: BlackSwanEventType::StablecoinBankRunCascade,
                severity: SecuritySeverity::Critical,
                probability_annual: 0.05, // 5% annual probability
                market_impact_percent: 20.0,
                duration_days: 7,
                collateral_impact_percent: 30.0,
                liquidity_impact_percent: 95.0,
                user_behavior_panic_factor: 0.95,
                recovery_time_weeks: 26, // 6 months if recoverable
                economic_loss_billions: 100.0,
                systemic_contagion_risk: 0.8,
                mitigation_effectiveness: 0.2,
            },

            // Correlated Asset Failure
            BlackSwanScenario {
                event_type: BlackSwanEventType::CorrelatedAssetFailure,
                severity: SecuritySeverity::Critical,
                probability_annual: 0.03, // 3% annual probability
                market_impact_percent: 60.0,
                duration_days: 14,
                collateral_impact_percent: 85.0, // Higher than market due to correlation
                liquidity_impact_percent: 80.0,
                user_behavior_panic_factor: 0.8,
                recovery_time_weeks: 20,
                economic_loss_billions: 300.0,
                systemic_contagion_risk: 0.9,
                mitigation_effectiveness: 0.15,
            },

            // Regulatory Shutdown
            BlackSwanScenario {
                event_type: BlackSwanEventType::RegulatoryShutdown,
                severity: SecuritySeverity::Critical,
                probability_annual: 0.01, // 1% annual probability
                market_impact_percent: 40.0,
                duration_days: 180, // 6 months regulatory process
                collateral_impact_percent: 20.0,
                liquidity_impact_percent: 100.0, // Complete liquidity freeze
                user_behavior_panic_factor: 0.7,
                recovery_time_weeks: 104, // 2 years if ever
                economic_loss_billions: 1000.0,
                systemic_contagion_risk: 0.6,
                mitigation_effectiveness: 0.05, // Very limited technical mitigation
            },

            // Network Partitioning Attack
            BlackSwanScenario {
                event_type: BlackSwanEventType::NetworkPartitioning,
                severity: SecuritySeverity::High,
                probability_annual: 0.15, // 15% annual probability
                market_impact_percent: 15.0,
                duration_days: 3,
                collateral_impact_percent: 10.0,
                liquidity_impact_percent: 60.0,
                user_behavior_panic_factor: 0.4,
                recovery_time_weeks: 2,
                economic_loss_billions: 10.0,
                systemic_contagion_risk: 0.3,
                mitigation_effectiveness: 0.7, // Technical solutions available
            },
        ]
    }

    fn simulate_scenario(&self, scenario: &BlackSwanScenario) -> StressTestResult {
        // Calculate protocol survival probability
        let base_survival = self.calculate_base_survival_probability();
        let stress_impact = self.calculate_stress_impact(scenario);
        let mitigation_boost = scenario.mitigation_effectiveness * self.assess_mitigation_capabilities();
        
        let survival_probability = (base_survival * (1.0 - stress_impact) + mitigation_boost).max(0.0).min(1.0);

        // Calculate maximum drawdown
        let collateral_loss = scenario.collateral_impact_percent / 100.0;
        let panic_amplification = scenario.user_behavior_panic_factor;
        let max_drawdown = (collateral_loss * (1.0 + panic_amplification)).min(1.0) * 100.0;

        // Calculate liquidity exhaustion time
        let base_liquidity_hours = 168.0; // 1 week base
        let panic_factor = scenario.user_behavior_panic_factor;
        let liquidity_impact = scenario.liquidity_impact_percent / 100.0;
        let exhaustion_time = (base_liquidity_hours * (1.0 - liquidity_impact) / (1.0 + panic_factor)).max(1.0) as u32;

        // Calculate required reserves multiplier
        let current_reserves = self.reserve_ratio;
        let stress_multiplier = 1.0 + (scenario.market_impact_percent / 100.0) * 2.0;
        let required_multiplier = current_reserves * stress_multiplier;

        // Assess governance response adequacy
        let governance_response = self.assess_governance_response_capability(scenario);

        // Calculate user confidence impact
        let confidence_impact = scenario.user_behavior_panic_factor * 
                               (scenario.market_impact_percent / 100.0) * 
                               (1.0 - mitigation_boost);

        // Calculate cascade propagation risk
        let cascade_risk = scenario.systemic_contagion_risk * 
                          (1.0 - survival_probability) * 
                          (scenario.market_impact_percent / 100.0);

        StressTestResult {
            scenario: scenario.clone(),
            protocol_survival_probability: survival_probability,
            max_drawdown_percent: max_drawdown,
            liquidity_exhaustion_time_hours: exhaustion_time,
            required_reserves_multiplier: required_multiplier,
            governance_response_adequacy: governance_response,
            user_confidence_impact: confidence_impact,
            cascade_propagation_risk: cascade_risk,
        }
    }

    fn calculate_base_survival_probability(&self) -> f32 {
        let mut survival_score = 0.5f32; // Base 50%

        // Reserve ratio boost
        if self.reserve_ratio > 2.0 {
            survival_score += 0.2; // 200%+ reserves = +20%
        } else if self.reserve_ratio > 1.5 {
            survival_score += 0.1; // 150%+ reserves = +10%
        }

        // Diversification boost
        let max_concentration = self.collateral_composition.values()
            .fold(0.0f64, |max, &val| max.max(val as f64));
        if max_concentration < 0.4 {
            survival_score += 0.15; // Well diversified = +15%
        } else if max_concentration < 0.6 {
            survival_score += 0.05; // Moderately diversified = +5%
        }

        // Emergency function boost
        if self.has_emergency_functions() {
            survival_score += 0.1; // Emergency controls = +10%
        }

        // Circuit breaker boost
        if !self.circuit_breaker_thresholds.is_empty() {
            survival_score += 0.1; // Circuit breakers = +10%
        }

        survival_score.min(1.0f32)
    }

    fn calculate_stress_impact(&self, scenario: &BlackSwanScenario) -> f32 {
        let market_stress = scenario.market_impact_percent / 100.0;
        let liquidity_stress = scenario.liquidity_impact_percent / 100.0;
        let panic_stress = scenario.user_behavior_panic_factor;
        let duration_stress = (scenario.duration_days as f32 / 30.0).min(2.0); // Normalize to months, cap at 2

        // Weighted combination of stress factors
        (market_stress * 0.3 + liquidity_stress * 0.3 + panic_stress * 0.2 + duration_stress * 0.2).min(1.0)
    }

    fn assess_mitigation_capabilities(&self) -> f32 {
        let mut mitigation_score = 0.0f32;

        // Emergency functions
        if self.has_emergency_functions() {
            mitigation_score += 0.3;
        }

        // Oracle infrastructure
        if self.has_oracle_functions() {
            mitigation_score += 0.2;
        }

        // Governance capabilities
        if self.has_governance_functions() {
            mitigation_score += 0.2;
        }

        // Circuit breakers
        if !self.circuit_breaker_thresholds.is_empty() {
            mitigation_score += 0.3;
        }

        mitigation_score.min(1.0f32)
    }

    fn assess_governance_response_capability(&self, scenario: &BlackSwanScenario) -> f32 {
        let mut response_adequacy = 0.5f32; // Base 50%

        // Governance functions available
        if self.has_governance_functions() {
            response_adequacy += 0.2;
        }

        // Emergency functions available
        if self.has_emergency_functions() {
            response_adequacy += 0.2;
        }

        // Time sensitivity adjustment
        let time_pressure_factor = match scenario.duration_days {
            1..=7 => 0.3f32,    // Very fast crisis = reduced governance effectiveness
            8..=30 => 0.7f32,   // Medium crisis = moderate governance effectiveness
            _ => 1.0f32,        // Slow crisis = full governance effectiveness
        };

        (response_adequacy * time_pressure_factor).min(1.0f32)
    }

    fn generate_survival_recommendations(&self, results: &[StressTestResult]) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Analyze worst-case scenarios
        let worst_survival = results.iter()
            .map(|r| r.protocol_survival_probability)
            .fold(1.0f32, |min, val| min.min(val));

        if worst_survival < 0.5 {
            recommendations.push("CRITICAL: Increase reserve ratios to 300%+ for extreme scenarios".to_string());
        }

        // Check liquidity exhaustion
        let min_liquidity_time = results.iter()
            .map(|r| r.liquidity_exhaustion_time_hours)
            .min()
            .unwrap_or(0);

        if min_liquidity_time < 24 {
            recommendations.push("Implement emergency liquidity facilities".to_string());
            recommendations.push("Add progressive withdrawal limits during stress".to_string());
        }

        // Check drawdown risk
        let max_drawdown = results.iter()
            .map(|r| r.max_drawdown_percent)
            .fold(0.0f32, |max, val| max.max(val));

        if max_drawdown > 50.0 {
            recommendations.push("Diversify collateral base to reduce correlated risk".to_string());
            recommendations.push("Implement maximum drawdown circuit breakers".to_string());
        }

        // Check cascade risk
        let max_cascade_risk = results.iter()
            .map(|r| r.cascade_propagation_risk)
            .fold(0.0f32, |max, val| max.max(val));

        if max_cascade_risk > 0.7 {
            recommendations.push("Isolate protocol from systemic contagion vectors".to_string());
            recommendations.push("Implement cross-protocol firewall mechanisms".to_string());
        }

        recommendations
    }

    // Helper methods
    fn has_emergency_functions(&self) -> bool {
        self.emergency_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_oracle_functions(&self) -> bool {
        self.oracle_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_governance_functions(&self) -> bool {
        self.governance_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn has_function_signature(&self, signature: &[u8; 4]) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(4) {
            let sig = [self.bytecode[i], self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3]];
            if sig == *signature {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_crash_simulation() {
        let bytecode = vec![
            // Emergency functions
            0x8d, 0xa5, 0xcb, 0x5b, // pause()
            // Oracle functions
            0x50, 0xd2, 0x5b, 0xcd, // latestAnswer()
        ];

        let simulator = BlackSwanSimulator::new(bytecode)
            .with_reserve_ratio(2.0); // 200% over-collateralization

        let results = simulator.simulate_black_swan_events();
        assert!(!results.is_empty());

        // Should have better survival with higher reserves
        let crash_results: Vec<_> = results.iter()
            .filter(|r| matches!(r.scenario.event_type, BlackSwanEventType::CryptoMarketCrash50Percent))
            .collect();
        
        assert!(!crash_results.is_empty());
        assert!(crash_results[0].protocol_survival_probability > 0.5);
    }

    #[test]
    fn test_diversification_benefits() {
        let bytecode = vec![0x8d, 0xa5, 0xcb, 0x5b]; // pause()

        let mut diversified_collateral = HashMap::new();
        diversified_collateral.insert("ETH".to_string(), 0.25);
        diversified_collateral.insert("BTC".to_string(), 0.25);
        diversified_collateral.insert("USDC".to_string(), 0.25);
        diversified_collateral.insert("Gold".to_string(), 0.25);

        let simulator = BlackSwanSimulator::new(bytecode)
            .with_collateral_composition(diversified_collateral);

        let results = simulator.simulate_black_swan_events();
        
        // Diversified portfolio should have better survival rates
        let avg_survival: f32 = results.iter()
            .map(|r| r.protocol_survival_probability)
            .sum::<f32>() / results.len() as f32;
        
        assert!(avg_survival > 0.4); // Should have decent survival with diversification
    }
}
