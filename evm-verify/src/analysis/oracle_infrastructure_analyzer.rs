use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use crate::circuits::execution_trace::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleFailureMode {
    OracleFeedManipulation,
    NetworkPartitioning,
    ValidatorSetAttack,
    DataFeedCorruption,
    ConsensusBreakdown,
    CircuitBreakerFailure,
    TimestampManipulation,
    PriceDeviationAttack,
    OracleGovernanceAttack,
    CrossChainOracleAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleInfrastructureVulnerability {
    pub failure_mode: OracleFailureMode,
    pub severity: SecuritySeverity,
    pub oracle_system: String,
    pub attack_cost_eth: f64,
    pub manipulation_window_seconds: u64,
    pub economic_impact_eth: f64,
    pub success_probability: f32,
    pub detection_confidence: f32,
    pub affected_protocols: Vec<String>,
    pub mitigation_strategies: Vec<String>,
    pub failure_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleHealthMetrics {
    pub price_deviation_threshold: f32,
    pub update_frequency_seconds: u32,
    pub validator_count: u32,
    pub consensus_threshold: f32,
    pub circuit_breaker_enabled: bool,
    pub multi_oracle_aggregation: bool,
    pub timestamp_validation: bool,
}

pub struct OracleInfrastructureAnalyzer {
    bytecode: Vec<u8>,
    oracle_functions: HashSet<[u8; 4]>,
    chainlink_functions: HashSet<[u8; 4]>,
    band_functions: HashSet<[u8; 4]>,
    tellor_functions: HashSet<[u8; 4]>,
    execution_trace: Option<EVMExecutionTrace>,
    known_oracle_addresses: HashMap<String, String>,
}

impl OracleInfrastructureAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut oracle_functions = HashSet::new();
        oracle_functions.insert([0x50, 0xd2, 0x5b, 0xcd]); // latestAnswer()
        oracle_functions.insert([0xfe, 0xaf, 0x96, 0x8c]); // latestRoundData()
        oracle_functions.insert([0x9a, 0x6f, 0xc8, 0xf5]); // getRoundData()
        oracle_functions.insert([0x31, 0x39, 0x84, 0x72]); // latestTimestamp()

        let mut chainlink_functions = HashSet::new();
        chainlink_functions.insert([0x31, 0x39, 0x84, 0x72]); // latestTimestamp()
        chainlink_functions.insert([0x54, 0xfd, 0x4d, 0x50]); // version()
        chainlink_functions.insert([0x66, 0x8a, 0x0f, 0x03]); // decimals()

        let mut band_functions = HashSet::new();
        band_functions.insert([0x7b, 0xd7, 0x03, 0xe2]); // getReferenceData()
        band_functions.insert([0xa3, 0x94, 0x44, 0xea]); // getReferenceDataBulk()

        let mut tellor_functions = HashSet::new();
        tellor_functions.insert([0x1f, 0x37, 0x9a, 0xcc]); // getDataBefore()
        tellor_functions.insert([0x77, 0xfc, 0xd7, 0xc3]); // getCurrentValue()

        // NEUTRAL: No hardcoded oracle addresses - detect by pattern
        let known_oracle_addresses = HashMap::new();

        Self {
            bytecode,
            oracle_functions,
            chainlink_functions,
            band_functions,
            tellor_functions,
            execution_trace: None,
            known_oracle_addresses,
        }
    }

    pub fn with_execution_trace(mut self, trace: EVMExecutionTrace) -> Self {
        self.execution_trace = Some(trace);
        self
    }

    pub fn analyze_oracle_infrastructure(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_oracle_manipulation_attacks());
        vulnerabilities.extend(self.detect_single_oracle_dependency());
        vulnerabilities.extend(self.detect_price_deviation_vulnerabilities());
        vulnerabilities.extend(self.detect_timestamp_manipulation_risks());
        vulnerabilities.extend(self.detect_oracle_governance_risks());
        vulnerabilities.extend(self.detect_circuit_breaker_failures());

        vulnerabilities
    }

    fn detect_oracle_manipulation_attacks(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_oracle_dependencies() && self.lacks_manipulation_protection() {
            vulnerabilities.push(OracleInfrastructureVulnerability {
                failure_mode: OracleFailureMode::OracleFeedManipulation,
                severity: SecuritySeverity::Critical,
                oracle_system: self.identify_oracle_system(),
                attack_cost_eth: self.estimate_manipulation_cost(),
                manipulation_window_seconds: 3600, // 1 hour manipulation window
                economic_impact_eth: 10_000_000.0, // Potential $10M+ impact
                success_probability: 0.7,
                detection_confidence: 0.85,
                affected_protocols: vec!["Primary Protocol".to_string()],
                mitigation_strategies: vec![
                    "Implement multi-oracle aggregation".to_string(),
                    "Add price deviation circuit breakers".to_string(),
                    "Use time-weighted average pricing".to_string(),
                    "Implement oracle staking/slashing".to_string(),
                ],
                failure_description: "Oracle price feeds can be manipulated through economic attacks".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_single_oracle_dependency(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_single_oracle_dependency() {
            vulnerabilities.push(OracleInfrastructureVulnerability {
                failure_mode: OracleFailureMode::NetworkPartitioning,
                severity: SecuritySeverity::High,
                oracle_system: "Single Oracle System".to_string(),
                attack_cost_eth: 100.0, // Low cost to attack single oracle
                manipulation_window_seconds: 86400, // 24 hour potential downtime
                economic_impact_eth: 50_000_000.0, // Massive impact from oracle failure
                success_probability: 0.9,
                detection_confidence: 0.95,
                affected_protocols: vec!["All dependent protocols".to_string()],
                mitigation_strategies: vec![
                    "Implement redundant oracle systems".to_string(),
                    "Add fallback price mechanisms".to_string(),
                    "Use decentralized oracle networks".to_string(),
                ],
                failure_description: "Single point of failure in oracle infrastructure".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_price_deviation_vulnerabilities(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.lacks_price_deviation_protection() {
            vulnerabilities.push(OracleInfrastructureVulnerability {
                failure_mode: OracleFailureMode::PriceDeviationAttack,
                severity: SecuritySeverity::High,
                oracle_system: self.identify_oracle_system(),
                attack_cost_eth: 1_000.0,
                manipulation_window_seconds: 900, // 15 minute window
                economic_impact_eth: 5_000_000.0,
                success_probability: 0.6,
                detection_confidence: 0.8,
                affected_protocols: vec!["Price-dependent protocols".to_string()],
                mitigation_strategies: vec![
                    "Implement maximum price deviation limits".to_string(),
                    "Add price change velocity limits".to_string(),
                    "Use confidence intervals for price data".to_string(),
                ],
                failure_description: "No protection against extreme price deviations".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_timestamp_manipulation_risks(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_timestamp_dependencies() && self.lacks_timestamp_validation() {
            vulnerabilities.push(OracleInfrastructureVulnerability {
                failure_mode: OracleFailureMode::TimestampManipulation,
                severity: SecuritySeverity::Medium,
                oracle_system: self.identify_oracle_system(),
                attack_cost_eth: 50.0,
                manipulation_window_seconds: 1800, // 30 minute window
                economic_impact_eth: 1_000_000.0,
                success_probability: 0.5,
                detection_confidence: 0.7,
                affected_protocols: vec!["Time-dependent protocols".to_string()],
                mitigation_strategies: vec![
                    "Validate oracle timestamp freshness".to_string(),
                    "Implement maximum staleness thresholds".to_string(),
                    "Use multiple timestamp sources".to_string(),
                ],
                failure_description: "Oracle timestamps can be manipulated or stale".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_oracle_governance_risks(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_centralized_oracle_governance() {
            vulnerabilities.push(OracleInfrastructureVulnerability {
                failure_mode: OracleFailureMode::OracleGovernanceAttack,
                severity: SecuritySeverity::Critical,
                oracle_system: "Centralized Oracle Governance".to_string(),
                attack_cost_eth: 10_000.0, // Cost to compromise governance
                manipulation_window_seconds: 604800, // 1 week governance delay
                economic_impact_eth: 100_000_000.0, // Entire ecosystem impact
                success_probability: 0.3,
                detection_confidence: 0.85,
                affected_protocols: vec!["All oracle-dependent protocols".to_string()],
                mitigation_strategies: vec![
                    "Decentralize oracle governance".to_string(),
                    "Implement time delays for governance changes".to_string(),
                    "Add community override mechanisms".to_string(),
                ],
                failure_description: "Centralized control over oracle infrastructure".to_string(),
            });
        }

        vulnerabilities
    }

    fn detect_circuit_breaker_failures(&self) -> Vec<OracleInfrastructureVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.lacks_circuit_breakers() {
            vulnerabilities.push(OracleInfrastructureVulnerability {
                failure_mode: OracleFailureMode::CircuitBreakerFailure,
                severity: SecuritySeverity::High,
                oracle_system: self.identify_oracle_system(),
                attack_cost_eth: 500.0,
                manipulation_window_seconds: 7200, // 2 hour window
                economic_impact_eth: 20_000_000.0,
                success_probability: 0.8,
                detection_confidence: 0.9,
                affected_protocols: vec!["All dependent protocols".to_string()],
                mitigation_strategies: vec![
                    "Implement automatic circuit breakers".to_string(),
                    "Add manual emergency stops".to_string(),
                    "Use gradual price adjustment mechanisms".to_string(),
                ],
                failure_description: "No circuit breakers to halt operations during oracle failures".to_string(),
            });
        }

        vulnerabilities
    }

    // Helper methods
    fn has_oracle_dependencies(&self) -> bool {
        self.oracle_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_manipulation_protection(&self) -> bool {
        // Look for common manipulation protection patterns
        !self.has_multi_oracle_aggregation() && !self.has_price_deviation_checks()
    }

    fn has_single_oracle_dependency(&self) -> bool {
        let oracle_count = self.count_unique_oracle_calls();
        oracle_count <= 1
    }

    fn lacks_price_deviation_protection(&self) -> bool {
        !self.has_price_deviation_checks()
    }

    fn has_timestamp_dependencies(&self) -> bool {
        let timestamp_functions = [[0x31, 0x39, 0x84, 0x72]]; // latestTimestamp()
        timestamp_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_timestamp_validation(&self) -> bool {
        // Look for timestamp freshness checks (simplified heuristic)
        !self.has_timestamp_freshness_checks()
    }

    fn has_centralized_oracle_governance(&self) -> bool {
        // Heuristic: if only Chainlink functions, likely centralized
        self.chainlink_functions.iter().any(|sig| self.has_function_signature(sig)) &&
        !self.band_functions.iter().any(|sig| self.has_function_signature(sig)) &&
        !self.tellor_functions.iter().any(|sig| self.has_function_signature(sig))
    }

    fn lacks_circuit_breakers(&self) -> bool {
        // Look for pause/emergency stop functions
        let circuit_breaker_sigs = [
            [0x8d, 0xa5, 0xcb, 0x5b], // pause()
            [0x3f, 0x4b, 0xa8, 0x3a], // emergencyStop()
        ];
        !circuit_breaker_sigs.iter().any(|sig| self.has_function_signature(sig))
    }

    fn identify_oracle_system(&self) -> String {
        if self.chainlink_functions.iter().any(|sig| self.has_function_signature(sig)) {
            "Chainlink".to_string()
        } else if self.band_functions.iter().any(|sig| self.has_function_signature(sig)) {
            "Band Protocol".to_string()
        } else if self.tellor_functions.iter().any(|sig| self.has_function_signature(sig)) {
            "Tellor".to_string()
        } else {
            "Unknown Oracle System".to_string()
        }
    }

    fn estimate_manipulation_cost(&self) -> f64 {
        match self.identify_oracle_system().as_str() {
            "Chainlink" => 50_000.0, // High cost to manipulate Chainlink
            "Band Protocol" => 10_000.0, // Medium cost
            "Tellor" => 5_000.0, // Lower cost for smaller networks
            _ => 1_000.0, // Unknown/custom oracles easier to manipulate
        }
    }

    fn has_multi_oracle_aggregation(&self) -> bool {
        // Count different oracle types
        let mut oracle_types = 0;
        if self.chainlink_functions.iter().any(|sig| self.has_function_signature(sig)) {
            oracle_types += 1;
        }
        if self.band_functions.iter().any(|sig| self.has_function_signature(sig)) {
            oracle_types += 1;
        }
        if self.tellor_functions.iter().any(|sig| self.has_function_signature(sig)) {
            oracle_types += 1;
        }
        oracle_types >= 2
    }

    fn has_price_deviation_checks(&self) -> bool {
        // Look for comparison operations that might be price deviation checks
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT/GT
                if i + 3 < self.bytecode.len() && self.bytecode[i + 3] == 0x57 { // JUMPI
                    return true; // Found conditional jump after comparison
                }
            }
        }
        false
    }

    fn count_unique_oracle_calls(&self) -> usize {
        self.oracle_functions.iter()
            .filter(|sig| self.has_function_signature(sig))
            .count()
    }

    fn has_timestamp_freshness_checks(&self) -> bool {
        // Look for timestamp comparison patterns
        for i in 0..self.bytecode.len().saturating_sub(6) {
            if self.bytecode[i] == 0x42 && // TIMESTAMP
               i + 5 < self.bytecode.len() && 
               (self.bytecode[i + 5] == 0x10 || self.bytecode[i + 5] == 0x11) { // LT/GT
                return true;
            }
        }
        false
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
    fn test_oracle_manipulation_detection() {
        let bytecode = vec![
            // latestAnswer() signature
            0x50, 0xd2, 0x5b, 0xcd,
            // No multi-oracle aggregation
        ];

        let analyzer = OracleInfrastructureAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.analyze_oracle_infrastructure();

        assert!(!vulnerabilities.is_empty());
        assert!(vulnerabilities.iter().any(|v| matches!(v.failure_mode, OracleFailureMode::OracleFeedManipulation)));
    }

    #[test]
    fn test_single_oracle_dependency_detection() {
        let bytecode = vec![
            // Only one oracle function
            0x50, 0xd2, 0x5b, 0xcd, // latestAnswer()
        ];

        let analyzer = OracleInfrastructureAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.analyze_oracle_infrastructure();

        assert!(vulnerabilities.iter().any(|v| matches!(v.failure_mode, OracleFailureMode::NetworkPartitioning)));
    }
}
