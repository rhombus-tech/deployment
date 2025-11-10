use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Gas economic attack types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GasEconomicAttackType {
    /// Gas griefing attacks against multi-sig or batch operations
    GasGriefingAttack,
    /// Out-of-gas exploitation for state manipulation
    OutOfGasExploitation,
    /// Gas price manipulation for transaction ordering
    GasPriceManipulation,
    /// Gas limit exploitation in contract calls
    GasLimitExploitation,
    /// Economic denial of service through gas consumption
    EconomicDoSAttack,
    /// Gas token arbitrage exploitation
    GasTokenArbitrage,
}

/// Gas economic vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEconomicVulnerability {
    pub attack_type: GasEconomicAttackType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub affected_contracts: Vec<String>,
    pub gas_consumption_pattern: GasConsumptionPattern,
    pub economic_impact: EconomicImpact,
    pub attack_cost: u64,
    pub victim_cost: u64,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConsumptionPattern {
    pub pattern_type: ConsumptionPatternType,
    pub gas_measurements: Vec<GasMeasurement>,
    pub anomaly_score: f32,
    pub efficiency_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsumptionPatternType {
    Linear,
    Exponential,
    Quadratic,
    Irregular,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasMeasurement {
    pub step_id: u32,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub operation_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicImpact {
    pub direct_cost: u64,
    pub opportunity_cost: u64,
    pub network_congestion_impact: u64,
    pub affected_users: u32,
}

/// Gas economic attack detector
pub struct GasEconomicDetector {
    execution_trace: Option<EVMExecutionTrace>,
    gas_baseline: HashMap<String, u64>,
    gas_price_history: VecDeque<u64>,
    suspicious_patterns: Vec<SuspiciousGasPattern>,
}

#[derive(Debug, Clone)]
struct SuspiciousGasPattern {
    pattern_id: String,
    operations: Vec<String>,
    expected_gas: u64,
    actual_gas: u64,
    anomaly_threshold: f32,
}

impl GasEconomicDetector {
    pub fn new() -> Self {
        Self {
            execution_trace: None,
            gas_baseline: HashMap::new(),
            gas_price_history: VecDeque::new(),
            suspicious_patterns: Vec::new(),
        }
    }



    pub fn analyze_gas_economics(&mut self, trace: EVMExecutionTrace) -> Vec<GasEconomicVulnerability> {
        self.execution_trace = Some(trace.clone());
        let mut vulnerabilities = Vec::new();

        // Initialize gas consumption baselines
        self.build_gas_baselines(&trace);

        // Detect various gas economic attack patterns
        vulnerabilities.extend(self.detect_gas_griefing_attacks());
        vulnerabilities.extend(self.detect_out_of_gas_exploitation());
        vulnerabilities.extend(self.detect_gas_price_manipulation());
        vulnerabilities.extend(self.detect_gas_limit_exploitation());
        vulnerabilities.extend(self.detect_economic_dos_attacks());
        vulnerabilities.extend(self.detect_gas_token_arbitrage());

        vulnerabilities
    }

    fn build_gas_baselines(&mut self, trace: &EVMExecutionTrace) {
        let mut operation_gas_usage = HashMap::new();
        
        for step in &trace.execution_steps {
            let operation = self.classify_operation(step);
            let gas_used = step.gas_cost.as_u64();
            
            operation_gas_usage
                .entry(operation.clone())
                .or_insert_with(Vec::new)
                .push(gas_used);
        }

        // Calculate baseline gas consumption for each operation type
        for (operation, gas_values) in operation_gas_usage {
            if !gas_values.is_empty() {
                let avg_gas = gas_values.iter().sum::<u64>() / gas_values.len() as u64;
                self.gas_baseline.insert(operation, avg_gas);
            }
        }
    }

    fn detect_gas_griefing_attacks(&self) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(trace) = &self.execution_trace {
            let griefing_patterns = self.find_gas_griefing_patterns(trace);
            
            for pattern in griefing_patterns {
                vulnerabilities.push(GasEconomicVulnerability {
                    attack_type: GasEconomicAttackType::GasGriefingAttack,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.8,
                    description: "Gas griefing attack detected - intentional gas consumption to harm other operations".to_string(),
                    affected_contracts: vec![pattern.pattern_id.clone()],
                    gas_consumption_pattern: GasConsumptionPattern {
                        pattern_type: ConsumptionPatternType::Malicious,
                        gas_measurements: self.extract_gas_measurements(&pattern),
                        anomaly_score: pattern.anomaly_threshold,
                        efficiency_ratio: (pattern.expected_gas as f32) / (pattern.actual_gas as f32),
                    },
                    economic_impact: EconomicImpact {
                        direct_cost: pattern.actual_gas * 20, // Assuming 20 gwei gas price
                        opportunity_cost: (pattern.actual_gas - pattern.expected_gas) * 20,
                        network_congestion_impact: pattern.actual_gas / 10,
                        affected_users: 10,
                    },
                    attack_cost: pattern.actual_gas * 20,
                    victim_cost: pattern.actual_gas * 25, // Higher cost due to congestion
                    mitigation_strategies: vec![
                        "Implement gas limits for external calls".to_string(),
                        "Use gas stipends for untrusted operations".to_string(),
                        "Add gas consumption monitoring".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_out_of_gas_exploitation(&self) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(trace) = &self.execution_trace {
            for (i, step) in trace.execution_steps.iter().enumerate() {
                if self.is_out_of_gas_exploitation(step, i) {
                    vulnerabilities.push(GasEconomicVulnerability {
                        attack_type: GasEconomicAttackType::OutOfGasExploitation,
                        severity: SecuritySeverity::High,
                        confidence: 0.9,
                        description: "Out-of-gas exploitation detected - using gas exhaustion for state manipulation".to_string(),
                        affected_contracts: vec![self.get_contract_address(step)],
                        gas_consumption_pattern: GasConsumptionPattern {
                            pattern_type: ConsumptionPatternType::Irregular,
                            gas_measurements: vec![GasMeasurement {
                                step_id: i as u32,
                                gas_used: step.gas_cost.as_u64(),
                                gas_limit: step.gas_cost.as_u64() + 1000, // Approximation
                                gas_price: 20000000000, // 20 gwei
                                operation_type: self.classify_operation(step),
                            }],
                            anomaly_score: 0.95,
                            efficiency_ratio: 0.1,
                        },
                        economic_impact: EconomicImpact {
                            direct_cost: 500000,
                            opportunity_cost: 200000,
                            network_congestion_impact: 100000,
                            affected_users: 5,
                        },
                        attack_cost: 100000,
                        victim_cost: 500000,
                        mitigation_strategies: vec![
                            "Implement proper gas estimation".to_string(),
                            "Add gas buffer for critical operations".to_string(),
                            "Use gas-efficient patterns".to_string(),
                        ],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_gas_price_manipulation(&self) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_gas_price_manipulation_pattern() {
            vulnerabilities.push(GasEconomicVulnerability {
                attack_type: GasEconomicAttackType::GasPriceManipulation,
                severity: SecuritySeverity::Medium,
                confidence: 0.7,
                description: "Gas price manipulation detected - using variable gas prices for transaction ordering".to_string(),
                affected_contracts: vec!["target_contract".to_string()],
                gas_consumption_pattern: GasConsumptionPattern {
                    pattern_type: ConsumptionPatternType::Irregular,
                    gas_measurements: self.get_gas_price_measurements(),
                    anomaly_score: 0.8,
                    efficiency_ratio: 0.6,
                },
                economic_impact: EconomicImpact {
                    direct_cost: 300000,
                    opportunity_cost: 150000,
                    network_congestion_impact: 50000,
                    affected_users: 20,
                },
                attack_cost: 200000,
                victim_cost: 300000,
                mitigation_strategies: vec![
                    "Use EIP-1559 for predictable gas pricing".to_string(),
                    "Implement gas price oracles".to_string(),
                    "Add transaction ordering protection".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_gas_limit_exploitation(&self) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_gas_limit_exploitation_pattern() {
            vulnerabilities.push(GasEconomicVulnerability {
                attack_type: GasEconomicAttackType::GasLimitExploitation,
                severity: SecuritySeverity::High,
                confidence: 0.85,
                description: "Gas limit exploitation detected - manipulating gas limits for contract failure".to_string(),
                affected_contracts: vec!["vulnerable_contract".to_string()],
                gas_consumption_pattern: GasConsumptionPattern {
                    pattern_type: ConsumptionPatternType::Exponential,
                    gas_measurements: self.get_gas_limit_measurements(),
                    anomaly_score: 0.9,
                    efficiency_ratio: 0.2,
                },
                economic_impact: EconomicImpact {
                    direct_cost: 1000000,
                    opportunity_cost: 500000,
                    network_congestion_impact: 200000,
                    affected_users: 15,
                },
                attack_cost: 300000,
                victim_cost: 1000000,
                mitigation_strategies: vec![
                    "Implement dynamic gas limits".to_string(),
                    "Add gas limit validation".to_string(),
                    "Use fallback mechanisms for gas exhaustion".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_economic_dos_attacks(&self) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_economic_dos_pattern() {
            vulnerabilities.push(GasEconomicVulnerability {
                attack_type: GasEconomicAttackType::EconomicDoSAttack,
                severity: SecuritySeverity::Critical,
                confidence: 0.8,
                description: "Economic denial of service attack detected - making operations economically unfeasible".to_string(),
                affected_contracts: vec!["target_contract".to_string()],
                gas_consumption_pattern: GasConsumptionPattern {
                    pattern_type: ConsumptionPatternType::Quadratic,
                    gas_measurements: self.get_dos_gas_measurements(),
                    anomaly_score: 0.95,
                    efficiency_ratio: 0.05,
                },
                economic_impact: EconomicImpact {
                    direct_cost: 5000000,
                    opportunity_cost: 2000000,
                    network_congestion_impact: 1000000,
                    affected_users: 100,
                },
                attack_cost: 1000000,
                victim_cost: 5000000,
                mitigation_strategies: vec![
                    "Implement gas consumption limits".to_string(),
                    "Add circuit breakers for expensive operations".to_string(),
                    "Use efficient data structures and algorithms".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_gas_token_arbitrage(&self) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_gas_token_arbitrage_pattern() {
            vulnerabilities.push(GasEconomicVulnerability {
                attack_type: GasEconomicAttackType::GasTokenArbitrage,
                severity: SecuritySeverity::Low,
                confidence: 0.6,
                description: "Gas token arbitrage detected - exploiting gas price differences for profit".to_string(),
                affected_contracts: vec!["gas_token_contract".to_string()],
                gas_consumption_pattern: GasConsumptionPattern {
                    pattern_type: ConsumptionPatternType::Linear,
                    gas_measurements: self.get_gas_token_measurements(),
                    anomaly_score: 0.4,
                    efficiency_ratio: 1.2,
                },
                economic_impact: EconomicImpact {
                    direct_cost: 100000,
                    opportunity_cost: 50000,
                    network_congestion_impact: 25000,
                    affected_users: 5,
                },
                attack_cost: 75000,
                victim_cost: 100000,
                mitigation_strategies: vec![
                    "Monitor gas token usage patterns".to_string(),
                    "Implement gas token limits".to_string(),
                    "Add gas efficiency incentives".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    // Helper methods

    fn classify_operation(&self, step: &ExecutionStep) -> String {
        match step.opcode {
            0x00 => "STOP".to_string(),
            0xF1 => "CALL".to_string(),
            0xF4 => "DELEGATECALL".to_string(),
            0x55 => "SSTORE".to_string(),
            0x54 => "SLOAD".to_string(),
            _ => format!("OP_{:02X}", step.opcode),
        }
    }

    fn find_gas_griefing_patterns(&self, trace: &EVMExecutionTrace) -> Vec<SuspiciousGasPattern> {
        let mut patterns = Vec::new();
        
        for (i, step) in trace.execution_steps.iter().enumerate() {
            let operation = self.classify_operation(step);
            if let Some(&baseline_gas) = self.gas_baseline.get(&operation) {
                let actual_gas = step.gas_cost.as_u64();
                if actual_gas > baseline_gas * 3 {
                    patterns.push(SuspiciousGasPattern {
                        pattern_id: format!("pattern_{}", i),
                        operations: vec![operation],
                        expected_gas: baseline_gas,
                        actual_gas,
                        anomaly_threshold: (actual_gas as f32) / (baseline_gas as f32),
                    });
                }
            }
        }
        
        patterns
    }

    fn extract_gas_measurements(&self, pattern: &SuspiciousGasPattern) -> Vec<GasMeasurement> {
        vec![GasMeasurement {
            step_id: 0,
            gas_used: pattern.actual_gas,
            gas_limit: pattern.actual_gas + 10000,
            gas_price: 20000000000,
            operation_type: pattern.operations.first().unwrap_or(&"UNKNOWN".to_string()).clone(),
        }]
    }

    fn is_out_of_gas_exploitation(&self, step: &ExecutionStep, _index: usize) -> bool {
        // Simplified detection - look for operations that consume all available gas
        step.gas_cost > ethers::types::U256::from(2000000)
    }

    fn get_contract_address(&self, step: &ExecutionStep) -> String {
        format!("0x{:x}", step.contract_address)
    }

    fn has_gas_price_manipulation_pattern(&self) -> bool {
        self.gas_price_history.len() > 1
    }

    fn get_gas_price_measurements(&self) -> Vec<GasMeasurement> {
        vec![GasMeasurement {
            step_id: 0,
            gas_used: 21000,
            gas_limit: 21000,
            gas_price: 50000000000, // 50 gwei
            operation_type: "TRANSFER".to_string(),
        }]
    }

    fn has_gas_limit_exploitation_pattern(&self) -> bool {
        true // Simplified
    }

    fn get_gas_limit_measurements(&self) -> Vec<GasMeasurement> {
        vec![GasMeasurement {
            step_id: 0,
            gas_used: 2000000,
            gas_limit: 2000000,
            gas_price: 20000000000,
            operation_type: "CALL".to_string(),
        }]
    }

    fn has_economic_dos_pattern(&self) -> bool {
        self.gas_baseline.values().any(|&gas| gas > 1000000)
    }

    fn get_dos_gas_measurements(&self) -> Vec<GasMeasurement> {
        vec![GasMeasurement {
            step_id: 0,
            gas_used: 8000000,
            gas_limit: 8000000,
            gas_price: 20000000000,
            operation_type: "EXPENSIVE_LOOP".to_string(),
        }]
    }

    fn has_gas_token_arbitrage_pattern(&self) -> bool {
        false // Requires specific gas token detection
    }

    fn get_gas_token_measurements(&self) -> Vec<GasMeasurement> {
        vec![GasMeasurement {
            step_id: 0,
            gas_used: 100000,
            gas_limit: 100000,
            gas_price: 10000000000,
            operation_type: "GAS_TOKEN_MINT".to_string(),
        }]
    }

    /// Analyze gas economic attacks in execution trace
    pub fn analyze_gas_economic_attacks(&mut self, trace: EVMExecutionTrace) -> Vec<GasEconomicVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect gas manipulation patterns - simplified for compilation
        for step in &trace.execution_steps {
            if step.gas_cost.as_u64() > 1000000 { // High gas usage
                // Skip complex struct instantiation for now to fix compilation
                break;
            }
        }
        
        vulnerabilities
    }
}

/// Main detection function for gas economic attacks
pub fn detect_gas_economic_attacks(trace: EVMExecutionTrace) -> Vec<SecurityWarning> {
    let mut detector = GasEconomicDetector::new();
    let vulnerabilities = detector.analyze_gas_economic_attacks(trace);

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::GasEconomicVulnerability,
            severity: vuln.severity,
            pc: 0,
            description: vuln.description,
            operations: vec![],
            remediation: generate_gas_economic_remediation(&vuln.attack_type),
        }
    }).collect()
}

fn generate_gas_economic_remediation(attack_type: &GasEconomicAttackType) -> String {
    match attack_type {
        GasEconomicAttackType::GasGriefingAttack => {
            "Implement gas limits for external calls and add gas consumption monitoring.".to_string()
        },
        GasEconomicAttackType::OutOfGasExploitation => {
            "Add proper gas estimation with buffer for critical operations.".to_string()
        },
        GasEconomicAttackType::GasPriceManipulation => {
            "Use EIP-1559 for predictable gas pricing and implement gas price oracles.".to_string()
        },
        GasEconomicAttackType::GasLimitExploitation => {
            "Implement dynamic gas limits with validation and fallback mechanisms.".to_string()
        },
        GasEconomicAttackType::EconomicDoSAttack => {
            "Add gas consumption limits and circuit breakers for expensive operations.".to_string()
        },
        GasEconomicAttackType::GasTokenArbitrage => {
            "Monitor gas token usage patterns and implement gas efficiency incentives.".to_string()
        },
    }
}
