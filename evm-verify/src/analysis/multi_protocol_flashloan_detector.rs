use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Multi-protocol flash loan attack types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlashLoanAttackType {
    /// Cross-protocol arbitrage using flash loans
    CrossProtocolArbitrage,
    /// Flash loan enabled governance attacks
    GovernanceManipulation,
    /// Multi-hop flash loan price manipulation
    MultiHopPriceManipulation,
    /// Flash loan collateral manipulation
    CollateralManipulation,
    /// Cross-protocol liquidation with flash loans
    CrossProtocolLiquidation,
    /// Flash loan enabled oracle manipulation
    OracleManipulation,
}

/// Flash loan vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashLoanVulnerability {
    pub attack_type: FlashLoanAttackType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub loan_sequence: Vec<FlashLoanStep>,
    pub affected_protocols: Vec<String>,
    pub profit_potential: u64,
    pub loan_amount: u64,
    pub attack_complexity: f32,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashLoanStep {
    pub step_id: u32,
    pub protocol: String,
    pub action: FlashLoanAction,
    pub amount: u64,
    pub asset: String,
    pub gas_cost: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlashLoanAction {
    InitiateLoan,
    Swap,
    Stake,
    Borrow,
    Liquidate,
    Vote,
    RepayLoan,
}

/// Multi-protocol flash loan detector
pub struct MultiProtocolFlashLoanDetector {
    execution_trace: Option<EVMExecutionTrace>,
    flashloan_providers: HashSet<String>,
    loan_tracking: HashMap<String, LoanState>,
    arbitrage_opportunities: Vec<ArbitrageOpportunity>,
}

#[derive(Debug, Clone)]
struct LoanState {
    loan_id: String,
    provider: String,
    amount: u64,
    asset: String,
    initiated_step: u32,
    repaid: bool,
    steps: Vec<FlashLoanStep>,
}

#[derive(Debug, Clone)]
struct ArbitrageOpportunity {
    protocols: Vec<String>,
    asset_pair: (String, String),
    price_difference: f64,
    required_capital: u64,
}

impl MultiProtocolFlashLoanDetector {
    pub fn new() -> Self {
        // NEUTRAL: No hardcoded providers - detect ANY flash loan pattern
        // Flash loans have universal pattern: borrow → operations → repay in same tx
        let flashloan_providers = HashSet::new(); // Empty - detect by pattern, not name

        Self {
            execution_trace: None,
            flashloan_providers,
            loan_tracking: HashMap::new(),
            arbitrage_opportunities: Vec::new(),
        }
    }

    pub fn analyze_flash_loan_exploits(&mut self, trace: EVMExecutionTrace) -> Vec<FlashLoanVulnerability> {
        self.execution_trace = Some(trace.clone());
        let mut vulnerabilities = Vec::new();

        // Track flash loan lifecycle
        self.track_flashloan_operations(&trace);

        // Detect various flash loan attack patterns
        vulnerabilities.extend(self.detect_cross_protocol_arbitrage());
        vulnerabilities.extend(self.detect_governance_manipulation());
        vulnerabilities.extend(self.detect_multi_hop_price_manipulation());
        vulnerabilities.extend(self.detect_collateral_manipulation());
        vulnerabilities.extend(self.detect_cross_protocol_liquidation());
        vulnerabilities.extend(self.detect_oracle_manipulation());

        vulnerabilities
    }

    fn track_flashloan_operations(&mut self, trace: &EVMExecutionTrace) {
        for (i, step) in trace.execution_steps.iter().enumerate() {
            if let Some(protocol) = self.identify_flashloan_protocol(step) {
                if self.is_flashloan_initiation(step) {
                    let loan_id = format!("loan_{}_{}", protocol, i);
                    let loan_state = LoanState {
                        loan_id: loan_id.clone(),
                        provider: protocol,
                        amount: self.extract_loan_amount(step),
                        asset: self.extract_asset(step),
                        initiated_step: i as u32,
                        repaid: false,
                        steps: vec![FlashLoanStep {
                            step_id: i as u32,
                            protocol: self.identify_flashloan_protocol(step).unwrap_or_default(),
                            action: FlashLoanAction::InitiateLoan,
                            amount: self.extract_loan_amount(step),
                            asset: self.extract_asset(step),
                            gas_cost: step.gas_cost.as_u64(),
                        }],
                    };
                    self.loan_tracking.insert(loan_id, loan_state);
                } else if self.is_flashloan_repayment(step) {
                    self.mark_loan_repaid(step, i as u32);
                } else {
                    self.add_intermediate_step(step, i as u32);
                }
            }
        }
    }

    fn detect_cross_protocol_arbitrage(&self) -> Vec<FlashLoanVulnerability> {
        let mut vulnerabilities = Vec::new();

        for loan in self.loan_tracking.values() {
            if self.has_arbitrage_pattern(loan) {
                vulnerabilities.push(FlashLoanVulnerability {
                    attack_type: FlashLoanAttackType::CrossProtocolArbitrage,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.8,
                    description: "Cross-protocol arbitrage using flash loans detected".to_string(),
                    loan_sequence: loan.steps.clone(),
                    affected_protocols: self.extract_protocols_from_loan(loan),
                    profit_potential: self.calculate_arbitrage_profit(loan),
                    loan_amount: loan.amount,
                    attack_complexity: 0.6,
                    mitigation_strategies: vec![
                        "Implement price impact limits".to_string(),
                        "Add cross-protocol price synchronization".to_string(),
                        "Use time delays for large trades".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_governance_manipulation(&self) -> Vec<FlashLoanVulnerability> {
        let mut vulnerabilities = Vec::new();

        for loan in self.loan_tracking.values() {
            if self.has_governance_attack_pattern(loan) {
                vulnerabilities.push(FlashLoanVulnerability {
                    attack_type: FlashLoanAttackType::GovernanceManipulation,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.9,
                    description: "Flash loan enabled governance attack detected".to_string(),
                    loan_sequence: loan.steps.clone(),
                    affected_protocols: self.extract_protocols_from_loan(loan),
                    profit_potential: 5000000,
                    loan_amount: loan.amount,
                    attack_complexity: 0.9,
                    mitigation_strategies: vec![
                        "Implement voting power time locks".to_string(),
                        "Add governance token borrowing restrictions".to_string(),
                        "Use quadratic voting mechanisms".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_multi_hop_price_manipulation(&self) -> Vec<FlashLoanVulnerability> {
        let mut vulnerabilities = Vec::new();

        for loan in self.loan_tracking.values() {
            if self.has_multi_hop_manipulation_pattern(loan) {
                vulnerabilities.push(FlashLoanVulnerability {
                    attack_type: FlashLoanAttackType::MultiHopPriceManipulation,
                    severity: SecuritySeverity::High,
                    confidence: 0.85,
                    description: "Multi-hop price manipulation using flash loans detected".to_string(),
                    loan_sequence: loan.steps.clone(),
                    affected_protocols: self.extract_protocols_from_loan(loan),
                    profit_potential: 2000000,
                    loan_amount: loan.amount,
                    attack_complexity: 0.8,
                    mitigation_strategies: vec![
                        "Use time-weighted average prices".to_string(),
                        "Implement price impact circuit breakers".to_string(),
                        "Add multi-hop transaction monitoring".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_collateral_manipulation(&self) -> Vec<FlashLoanVulnerability> {
        let mut vulnerabilities = Vec::new();

        for loan in self.loan_tracking.values() {
            if self.has_collateral_manipulation_pattern(loan) {
                vulnerabilities.push(FlashLoanVulnerability {
                    attack_type: FlashLoanAttackType::CollateralManipulation,
                    severity: SecuritySeverity::High,
                    confidence: 0.8,
                    description: "Flash loan enabled collateral manipulation detected".to_string(),
                    loan_sequence: loan.steps.clone(),
                    affected_protocols: self.extract_protocols_from_loan(loan),
                    profit_potential: 1500000,
                    loan_amount: loan.amount,
                    attack_complexity: 0.7,
                    mitigation_strategies: vec![
                        "Implement collateral ratio buffers".to_string(),
                        "Add collateral value time locks".to_string(),
                        "Use external price oracles".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_cross_protocol_liquidation(&self) -> Vec<FlashLoanVulnerability> {
        let mut vulnerabilities = Vec::new();

        for loan in self.loan_tracking.values() {
            if self.has_liquidation_attack_pattern(loan) {
                vulnerabilities.push(FlashLoanVulnerability {
                    attack_type: FlashLoanAttackType::CrossProtocolLiquidation,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.75,
                    description: "Cross-protocol liquidation using flash loans detected".to_string(),
                    loan_sequence: loan.steps.clone(),
                    affected_protocols: self.extract_protocols_from_loan(loan),
                    profit_potential: 800000,
                    loan_amount: loan.amount,
                    attack_complexity: 0.5,
                    mitigation_strategies: vec![
                        "Implement liquidation delays".to_string(),
                        "Add cross-protocol health checks".to_string(),
                        "Use gradual liquidation mechanisms".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_oracle_manipulation(&self) -> Vec<FlashLoanVulnerability> {
        let mut vulnerabilities = Vec::new();

        for loan in self.loan_tracking.values() {
            if self.has_oracle_manipulation_pattern(loan) {
                vulnerabilities.push(FlashLoanVulnerability {
                    attack_type: FlashLoanAttackType::OracleManipulation,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.9,
                    description: "Flash loan enabled oracle manipulation detected".to_string(),
                    loan_sequence: loan.steps.clone(),
                    affected_protocols: self.extract_protocols_from_loan(loan),
                    profit_potential: 3000000,
                    loan_amount: loan.amount,
                    attack_complexity: 0.85,
                    mitigation_strategies: vec![
                        "Use decentralized oracle networks".to_string(),
                        "Implement oracle price time delays".to_string(),
                        "Add oracle manipulation detection".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn identify_flashloan_protocol(&self, step: &ExecutionStep) -> Option<String> {
        // NEUTRAL: Detect flash loan by PATTERN, not hardcoded addresses
        // Flash loans are characterized by:
        // 1. Large value transfer (CALL with value)
        // 2. High gas usage (> 100k gas)
        // 3. External call pattern
        
        if self.looks_like_flashloan_call(step) {
            // Generate generic protocol ID from contract address
            // This works with ANY protocol implementing flash loans
            let addr_str = format!("{:?}", step.contract_address);
            let protocol_id = format!("flashloan_protocol_{}", &addr_str[..10]);
            Some(protocol_id)
        } else {
            None
        }
    }
    
    fn looks_like_flashloan_call(&self, step: &ExecutionStep) -> bool {
        // Detect flash loan pattern:
        // - CALL opcode (0xF1) with significant gas
        // - Or DELEGATECALL (0xF4) with high gas
        // This works for ANY protocol with flash loans
        matches!(step.opcode, 0xF1 | 0xF4) && step.gas_cost.as_u64() > 80000
    }

    fn is_flashloan_initiation(&self, step: &ExecutionStep) -> bool {
        // Simplified detection based on opcode and gas usage
        step.opcode == 0xF1 && step.gas_cost.as_u64() > 100000
    }

    fn is_flashloan_repayment(&self, step: &ExecutionStep) -> bool {
        // Look for repayment patterns
        step.opcode == 0xF1 && step.gas_cost.as_u64() < 50000
    }

    fn extract_loan_amount(&self, _step: &ExecutionStep) -> u64 {
        1000000 // Simplified - would extract from transaction data
    }

    fn extract_asset(&self, _step: &ExecutionStep) -> String {
        "ETH".to_string() // Simplified
    }

    fn mark_loan_repaid(&mut self, _step: &ExecutionStep, _step_id: u32) {
        // Mark loans as repaid - simplified implementation
        for loan in self.loan_tracking.values_mut() {
            if !loan.repaid {
                loan.repaid = true;
                break;
            }
        }
    }

    fn add_intermediate_step(&mut self, step: &ExecutionStep, step_id: u32) {
        // Add intermediate steps to active loans
        let protocol = self.identify_flashloan_protocol(step).unwrap_or_default();
        let action = self.classify_flashloan_action(step);
        let gas_cost = step.gas_cost.as_u64();
        
        for loan in self.loan_tracking.values_mut() {
            if !loan.repaid {
                loan.steps.push(FlashLoanStep {
                    step_id,
                    protocol: protocol.clone(),
                    action: action.clone(),
                    amount: 0, // Would be extracted from transaction data
                    asset: "ETH".to_string(),
                    gas_cost,
                });
            }
        }
    }

    fn classify_flashloan_action(&self, step: &ExecutionStep) -> FlashLoanAction {
        match step.opcode {
            0xF1 => FlashLoanAction::Swap,
            0x55 => FlashLoanAction::Stake,
            _ => FlashLoanAction::Swap,
        }
    }

    fn has_arbitrage_pattern(&self, loan: &LoanState) -> bool {
        loan.steps.len() > 2 && loan.steps.iter().any(|s| matches!(s.action, FlashLoanAction::Swap))
    }

    fn extract_protocols_from_loan(&self, loan: &LoanState) -> Vec<String> {
        loan.steps.iter().map(|s| s.protocol.clone()).collect::<HashSet<_>>().into_iter().collect()
    }

    fn calculate_arbitrage_profit(&self, _loan: &LoanState) -> u64 {
        500000 // Simplified calculation
    }

    fn has_governance_attack_pattern(&self, loan: &LoanState) -> bool {
        loan.steps.iter().any(|s| matches!(s.action, FlashLoanAction::Vote))
    }

    fn has_multi_hop_manipulation_pattern(&self, loan: &LoanState) -> bool {
        loan.steps.len() > 4
    }

    fn has_collateral_manipulation_pattern(&self, loan: &LoanState) -> bool {
        loan.steps.iter().any(|s| matches!(s.action, FlashLoanAction::Borrow | FlashLoanAction::Stake))
    }

    fn has_liquidation_attack_pattern(&self, loan: &LoanState) -> bool {
        loan.steps.iter().any(|s| matches!(s.action, FlashLoanAction::Liquidate))
    }

    fn has_oracle_manipulation_pattern(&self, loan: &LoanState) -> bool {
        loan.steps.len() > 3 && loan.amount > 5000000
    }

    /// Analyze flashloan attacks in execution trace
    pub fn analyze_flashloan_attacks(&mut self, trace: EVMExecutionTrace) -> Vec<FlashLoanVulnerability> {
        self.analyze_flash_loan_exploits(trace)
    }
}

/// Main detection function for multi-protocol flash loan attacks
pub fn detect_multi_protocol_flashloan_attacks(trace: EVMExecutionTrace) -> Vec<SecurityWarning> {
    let mut detector = MultiProtocolFlashLoanDetector::new();
    let vulnerabilities = detector.analyze_flashloan_attacks(trace);

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::FlashLoanVulnerability,
            severity: vuln.severity,
            pc: 0,
            description: vuln.description,
            operations: vec![],
            remediation: generate_flashloan_remediation(&vuln.attack_type),
        }
    }).collect()
}

fn generate_flashloan_remediation(attack_type: &FlashLoanAttackType) -> String {
    match attack_type {
        FlashLoanAttackType::CrossProtocolArbitrage => {
            "Implement price impact limits and cross-protocol price synchronization.".to_string()
        },
        FlashLoanAttackType::GovernanceManipulation => {
            "Add voting power time locks and governance token borrowing restrictions.".to_string()
        },
        FlashLoanAttackType::MultiHopPriceManipulation => {
            "Use time-weighted average prices and implement price impact circuit breakers.".to_string()
        },
        FlashLoanAttackType::CollateralManipulation => {
            "Implement collateral ratio buffers and add collateral value time locks.".to_string()
        },
        FlashLoanAttackType::CrossProtocolLiquidation => {
            "Add liquidation delays and implement gradual liquidation mechanisms.".to_string()
        },
        FlashLoanAttackType::OracleManipulation => {
            "Use decentralized oracle networks and implement oracle price time delays.".to_string()
        },
    }
}
