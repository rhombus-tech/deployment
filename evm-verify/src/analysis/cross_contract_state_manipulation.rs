use crate::bytecode::security::SecuritySeverity;
use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use ethers::types::U256;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

/// Advanced cross-contract state manipulation detection
/// 
/// This module detects sophisticated attacks that manipulate state across multiple contracts
/// to exploit protocol invariants, pricing mechanisms, and financial relationships.
/// 
/// Key attack vectors detected:
/// - Flash loan manipulation chains
/// - Cross-DEX price manipulation
/// - Multi-protocol state poisoning
/// - Coordinated liquidity attacks
/// - Cross-contract invariant violations
#[derive(Debug, Clone)]
pub struct CrossContractStateManipulator {
    execution_trace: EVMExecutionTrace,
    state_changes: HashMap<String, Vec<StateChange>>,
    manipulation_patterns: ManipulationPatternDetector,
    flash_loan_tracker: FlashLoanTracker,
    price_oracle_monitor: PriceOracleMonitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateManipulationVulnerability {
    pub attack_type: StateManipulationType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f64,
    pub affected_contracts: Vec<String>,
    pub manipulation_chain: Vec<ManipulationStep>,
    pub financial_impact: FinancialImpact,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StateManipulationType {
    FlashLoanManipulation,
    CrossDexPriceManipulation,
    LiquidityDrainAttack,
    GovernanceStatePoison,
    OracleManipulationChain,
    CollateralRatioManipulation,
    ReserveDepletionAttack,
    CrossProtocolInvariantViolation,
    CoordinatedLiquidationAttack,
    MultiStepArbitrageExploit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManipulationStep {
    pub contract_address: String,
    pub step_type: ManipulationStepType,
    pub state_before: HashMap<String, String>,
    pub state_after: HashMap<String, String>,
    pub impact_severity: f64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManipulationStepType {
    StateSetup,
    Manipulation,
    Exploitation,
    Cleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialImpact {
    pub estimated_value_at_risk: f64,
    pub affected_protocols: Vec<String>,
    pub attack_profitability: f64,
    pub systemic_risk_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub contract_address: String,
    pub storage_slot: String,
    pub old_value: String,
    pub new_value: String,
    pub change_magnitude: f64,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct ManipulationPatternDetector {
    // Pattern matching for known manipulation sequences
    pub flash_loan_patterns: Vec<FlashLoanPattern>,
    pub price_manipulation_patterns: Vec<PriceManipulationPattern>,
    pub liquidity_attack_patterns: Vec<LiquidityAttackPattern>,
    pub governance_attack_patterns: Vec<GovernanceAttackPattern>,
}

#[derive(Debug, Clone)]
pub struct FlashLoanPattern {
    pub loan_signature: [u8; 4],
    pub repayment_signature: [u8; 4],
    pub typical_manipulation_window: u64,
    pub common_target_protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PriceManipulationPattern {
    pub oracle_read_signatures: Vec<[u8; 4]>,
    pub swap_signatures: Vec<[u8; 4]>,
    pub price_deviation_threshold: f64,
    pub manipulation_timeframe: u64,
}

#[derive(Debug, Clone)]
pub struct LiquidityAttackPattern {
    pub withdrawal_signatures: Vec<[u8; 4]>,
    pub deposit_signatures: Vec<[u8; 4]>,
    pub threshold_manipulation_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct GovernanceAttackPattern {
    pub voting_signatures: Vec<[u8; 4]>,
    pub proposal_signatures: Vec<[u8; 4]>,
    pub execution_signatures: Vec<[u8; 4]>,
}

#[derive(Debug, Clone)]
pub struct FlashLoanTracker {
    pub active_loans: HashMap<String, FlashLoanInstance>,
    pub loan_patterns: Vec<FlashLoanPattern>,
    pub suspicious_loan_chains: Vec<SuspiciousLoanChain>,
}

#[derive(Debug, Clone)]
pub struct FlashLoanInstance {
    pub lender_contract: String,
    pub borrower_contract: String,
    pub loan_amount: U256,
    pub loan_token: String,
    pub initiation_block: u64,
    pub expected_repayment_block: u64,
    pub manipulation_activities: Vec<ManipulationActivity>,
}

#[derive(Debug, Clone)]
pub struct SuspiciousLoanChain {
    pub loan_sequence: Vec<FlashLoanInstance>,
    pub cross_protocol_manipulation: bool,
    pub estimated_profit: f64,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct ManipulationActivity {
    pub target_contract: String,
    pub activity_type: ActivityType,
    pub state_changes: Vec<StateChange>,
    pub severity_score: f64,
}

#[derive(Debug, Clone)]
pub enum ActivityType {
    PriceOracle,
    LiquidityPool,
    GovernanceToken,
    CollateralRatio,
    ReserveBalance,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PriceOracleMonitor {
    pub oracle_contracts: HashSet<String>,
    pub price_feeds: HashMap<String, PriceFeed>,
    pub manipulation_alerts: Vec<PriceManipulationAlert>,
}

#[derive(Debug, Clone)]
pub struct PriceFeed {
    pub oracle_address: String,
    pub asset_pair: (String, String),
    pub last_price: f64,
    pub price_history: VecDeque<PricePoint>,
    pub deviation_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct PricePoint {
    pub price: f64,
    pub timestamp: u64,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct PriceManipulationAlert {
    pub oracle_address: String,
    pub manipulation_type: PriceManipulationType,
    pub severity: SecuritySeverity,
    pub price_deviation: f64,
    pub manipulation_timeframe: u64,
}

#[derive(Debug, Clone)]
pub enum PriceManipulationType {
    FlashLoanPriceSpike,
    CrossDexArbitrage,
    OracleDelayExploit,
    LiquidityDrainManipulation,
    CoordinatedPriceAttack,
}

impl CrossContractStateManipulator {
    pub fn new(execution_trace: EVMExecutionTrace) -> Self {
        Self {
            execution_trace,
            state_changes: HashMap::new(),
            manipulation_patterns: ManipulationPatternDetector::new(),
            flash_loan_tracker: FlashLoanTracker::new(),
            price_oracle_monitor: PriceOracleMonitor::new(),
        }
    }

    /// Primary vulnerability detection method
    pub fn detect_vulnerabilities(&mut self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Extract state changes from execution trace
        self.extract_state_changes();
        
        // Detect different types of manipulation attacks
        vulnerabilities.extend(self.detect_flash_loan_manipulation());
        vulnerabilities.extend(self.detect_cross_dex_price_manipulation());
        vulnerabilities.extend(self.detect_liquidity_drain_attacks());
        vulnerabilities.extend(self.detect_governance_state_poison());
        vulnerabilities.extend(self.detect_oracle_manipulation_chains());
        vulnerabilities.extend(self.detect_collateral_ratio_manipulation());
        vulnerabilities.extend(self.detect_reserve_depletion_attacks());
        vulnerabilities.extend(self.detect_cross_protocol_invariant_violations());
        vulnerabilities.extend(self.detect_coordinated_liquidation_attacks());
        vulnerabilities.extend(self.detect_multi_step_arbitrage_exploits());

        vulnerabilities
    }

    /// Alias method for comprehensive analyzer compatibility
    pub fn detect_state_manipulation(&mut self) -> Vec<StateManipulationVulnerability> {
        self.detect_vulnerabilities()
    }

    fn extract_state_changes(&mut self) {
        for step in &self.execution_trace.execution_steps {
            for storage_change in &step.storage_changes {
                let slot = &storage_change.slot;
                let old_val = &storage_change.previous_value;
                let new_val = &storage_change.new_value;
                    let change = StateChange {
                        contract_address: format!("{:?}", step.contract_address),
                        storage_slot: format!("{:?}", slot),
                        old_value: format!("{:?}", old_val),
                        new_value: format!("{:?}", new_val),
                        change_magnitude: self.calculate_change_magnitude(&format!("{:?}", old_val), &format!("{:?}", new_val)),
                        timestamp: step.execution_time_ns / 1_000_000, // Convert nanoseconds to milliseconds
                    };

                    self.state_changes
                        .entry(format!("{:?}", step.contract_address))
                        .or_insert_with(Vec::new)
                        .push(change);
            }
        }
    }

    fn detect_flash_loan_manipulation(&mut self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect flash loan initiation patterns
        let flash_loans = self.identify_flash_loan_instances();
        
        for loan in flash_loans {
            if self.is_suspicious_flash_loan(&loan) {
                let manipulation_chain = self.trace_manipulation_chain(&loan);
                let financial_impact = self.assess_financial_impact(&manipulation_chain);

                if financial_impact.attack_profitability > 0.1 { // 10% profit threshold
                    vulnerabilities.push(StateManipulationVulnerability {
                        attack_type: StateManipulationType::FlashLoanManipulation,
                        severity: self.determine_severity(&financial_impact),
                        description: format!(
                            "Flash loan manipulation detected: {} manipulating {} contracts with estimated profit of {:.2}%",
                            loan.borrower_contract,
                            manipulation_chain.len(),
                            financial_impact.attack_profitability * 100.0
                        ),
                        confidence: self.calculate_flash_loan_confidence(&loan, &manipulation_chain),
                        affected_contracts: manipulation_chain.iter()
                            .map(|step| step.contract_address.clone())
                            .collect(),
                        manipulation_chain,
                        financial_impact,
                        mitigation_strategies: vec![
                            "Implement flash loan detection".to_string(),
                            "Add price manipulation protection".to_string(),
                            "Use time-weighted average pricing".to_string(),
                            "Implement emergency pause mechanisms".to_string(),
                        ],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_cross_dex_price_manipulation(&self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        let dex_interactions = self.identify_dex_interactions();
        let price_manipulations = self.detect_coordinated_price_changes(&dex_interactions);

        for manipulation in price_manipulations {
            if manipulation.price_deviation > 0.05 { // 5% deviation threshold
                let manipulation_chain = self.build_price_manipulation_chain(&manipulation);
                let financial_impact = self.assess_financial_impact(&manipulation_chain);

                vulnerabilities.push(StateManipulationVulnerability {
                    attack_type: StateManipulationType::CrossDexPriceManipulation,
                    severity: if manipulation.price_deviation > 0.2 { 
                        SecuritySeverity::Critical 
                    } else { 
                        SecuritySeverity::High 
                    },
                    description: format!(
                        "Cross-DEX price manipulation detected: {:.1}% price deviation across {} protocols",
                        manipulation.price_deviation * 100.0,
                        manipulation.affected_dexes.len()
                    ),
                    confidence: self.calculate_price_manipulation_confidence(&manipulation),
                    affected_contracts: manipulation.affected_dexes,
                    manipulation_chain,
                    financial_impact,
                    mitigation_strategies: vec![
                        "Implement multi-oracle price validation".to_string(),
                        "Add slippage protection".to_string(),
                        "Use circuit breakers for large price movements".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_liquidity_drain_attacks(&self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect large coordinated withdrawals
        let drain_patterns = self.identify_liquidity_drain_patterns();

        for pattern in drain_patterns {
            if pattern.drain_percentage > 0.3 { // 30% liquidity drain threshold
                vulnerabilities.push(StateManipulationVulnerability {
                    attack_type: StateManipulationType::LiquidityDrainAttack,
                    severity: SecuritySeverity::Critical,
                    description: format!(
                        "Liquidity drain attack detected: {:.1}% of liquidity removed from {} pools",
                        pattern.drain_percentage * 100.0,
                        pattern.affected_pools.len()
                    ),
                    confidence: 0.95,
                    affected_contracts: pattern.affected_pools,
                    manipulation_chain: pattern.drain_steps,
                    financial_impact: FinancialImpact {
                        estimated_value_at_risk: pattern.total_value_drained,
                        affected_protocols: pattern.affected_protocols,
                        attack_profitability: pattern.estimated_profit,
                        systemic_risk_level: 0.8,
                    },
                    mitigation_strategies: vec![
                        "Implement withdrawal limits".to_string(),
                        "Add liquidity protection mechanisms".to_string(),
                        "Use graduated withdrawal penalties".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_governance_state_poison(&self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        let governance_manipulations = self.identify_governance_manipulations();

        for manipulation in governance_manipulations {
            vulnerabilities.push(StateManipulationVulnerability {
                attack_type: StateManipulationType::GovernanceStatePoison,
                severity: SecuritySeverity::High,
                description: format!(
                    "Governance state poisoning detected: Coordinated manipulation of {} governance contracts",
                    manipulation.affected_contracts.len()
                ),
                confidence: 0.85,
                affected_contracts: manipulation.affected_contracts,
                manipulation_chain: manipulation.steps,
                financial_impact: manipulation.impact,
                mitigation_strategies: vec![
                    "Implement governance delay mechanisms".to_string(),
                    "Add cross-protocol governance validation".to_string(),
                    "Use multi-signature governance approvals".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_oracle_manipulation_chains(&mut self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        self.update_oracle_monitoring();
        let manipulation_chains = self.identify_oracle_manipulation_chains();

        for chain in manipulation_chains {
            vulnerabilities.push(StateManipulationVulnerability {
                attack_type: StateManipulationType::OracleManipulationChain,
                severity: SecuritySeverity::Critical,
                description: format!(
                    "Oracle manipulation chain detected: {} oracles compromised in coordinated attack",
                    chain.compromised_oracles.len()
                ),
                confidence: 0.9,
                affected_contracts: chain.compromised_oracles,
                manipulation_chain: chain.manipulation_steps,
                financial_impact: chain.estimated_impact,
                mitigation_strategies: vec![
                    "Implement decentralized oracle networks".to_string(),
                    "Add oracle deviation monitoring".to_string(),
                    "Use multiple independent price sources".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_collateral_ratio_manipulation(&self) -> Vec<StateManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        let collateral_manipulations = self.identify_collateral_manipulations();

        for manipulation in collateral_manipulations {
            if manipulation.ratio_deviation > 0.15 { // 15% deviation threshold
                vulnerabilities.push(StateManipulationVulnerability {
                    attack_type: StateManipulationType::CollateralRatioManipulation,
                    severity: SecuritySeverity::High,
                    description: format!(
                        "Collateral ratio manipulation detected: {:.1}% deviation in {} lending protocols",
                        manipulation.ratio_deviation * 100.0,
                        manipulation.affected_protocols.len()
                    ),
                    confidence: 0.8,
                    affected_contracts: manipulation.affected_contracts,
                    manipulation_chain: manipulation.steps,
                    financial_impact: manipulation.impact,
                    mitigation_strategies: vec![
                        "Implement collateral ratio monitoring".to_string(),
                        "Add liquidation protection mechanisms".to_string(),
                        "Use time-averaged collateral valuations".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_reserve_depletion_attacks(&self) -> Vec<StateManipulationVulnerability> {
        // Implementation for detecting attacks that deplete protocol reserves
        Vec::new() // Placeholder
    }

    fn detect_cross_protocol_invariant_violations(&self) -> Vec<StateManipulationVulnerability> {
        // Implementation for detecting violations of cross-protocol invariants
        Vec::new() // Placeholder
    }

    fn detect_coordinated_liquidation_attacks(&self) -> Vec<StateManipulationVulnerability> {
        // Implementation for detecting coordinated liquidation attacks
        Vec::new() // Placeholder
    }

    fn detect_multi_step_arbitrage_exploits(&self) -> Vec<StateManipulationVulnerability> {
        // Implementation for detecting complex multi-step arbitrage exploits
        Vec::new() // Placeholder
    }

    // Helper methods (abbreviated for brevity)
    fn calculate_change_magnitude(&self, old_val: &str, new_val: &str) -> f64 {
        // Calculate the magnitude of state change
        1.0 // Placeholder
    }

    fn identify_flash_loan_instances(&mut self) -> Vec<FlashLoanInstance> {
        // Identify flash loan patterns in execution trace
        Vec::new() // Placeholder
    }

    fn is_suspicious_flash_loan(&self, _loan: &FlashLoanInstance) -> bool {
        // Determine if flash loan is suspicious
        true // Placeholder
    }

    fn trace_manipulation_chain(&self, _loan: &FlashLoanInstance) -> Vec<ManipulationStep> {
        // Trace the manipulation chain for a flash loan
        Vec::new() // Placeholder
    }

    fn assess_financial_impact(&self, _chain: &[ManipulationStep]) -> FinancialImpact {
        // Assess the financial impact of manipulation
        FinancialImpact {
            estimated_value_at_risk: 100000.0,
            affected_protocols: vec!["Protocol1".to_string()],
            attack_profitability: 0.15,
            systemic_risk_level: 0.6,
        }
    }

    fn determine_severity(&self, impact: &FinancialImpact) -> SecuritySeverity {
        if impact.estimated_value_at_risk > 1_000_000.0 {
            SecuritySeverity::Critical
        } else if impact.estimated_value_at_risk > 100_000.0 {
            SecuritySeverity::High
        } else {
            SecuritySeverity::Medium
        }
    }

    fn calculate_flash_loan_confidence(&self, _loan: &FlashLoanInstance, _chain: &[ManipulationStep]) -> f64 {
        0.85 // Placeholder
    }

    fn identify_dex_interactions(&self) -> Vec<DexInteraction> {
        Vec::new() // Placeholder
    }

    fn detect_coordinated_price_changes(&self, _interactions: &[DexInteraction]) -> Vec<PriceManipulationEvent> {
        Vec::new() // Placeholder
    }

    fn build_price_manipulation_chain(&self, _manipulation: &PriceManipulationEvent) -> Vec<ManipulationStep> {
        Vec::new() // Placeholder
    }

    fn calculate_price_manipulation_confidence(&self, _manipulation: &PriceManipulationEvent) -> f64 {
        0.8 // Placeholder
    }

    fn identify_liquidity_drain_patterns(&self) -> Vec<LiquidityDrainPattern> {
        Vec::new() // Placeholder
    }

    fn identify_governance_manipulations(&self) -> Vec<GovernanceManipulation> {
        Vec::new() // Placeholder
    }

    fn update_oracle_monitoring(&mut self) {
        // Update oracle price monitoring
    }

    fn identify_oracle_manipulation_chains(&self) -> Vec<OracleManipulationChain> {
        Vec::new() // Placeholder
    }

    fn identify_collateral_manipulations(&self) -> Vec<CollateralManipulation> {
        Vec::new() // Placeholder
    }
}

// Helper structs and implementations
impl ManipulationPatternDetector {
    fn new() -> Self {
        Self {
            flash_loan_patterns: Self::load_flash_loan_patterns(),
            price_manipulation_patterns: Self::load_price_patterns(),
            liquidity_attack_patterns: Self::load_liquidity_patterns(),
            governance_attack_patterns: Self::load_governance_patterns(),
        }
    }

    fn load_flash_loan_patterns() -> Vec<FlashLoanPattern> {
        vec![
            FlashLoanPattern {
                loan_signature: [0xa9, 0x05, 0x9c, 0xbb], // flashLoan()
                repayment_signature: [0x23, 0xb8, 0x72, 0xdd], // repayFlashLoan()
                typical_manipulation_window: 100, // blocks
                common_target_protocols: vec!["Aave".to_string(), "dYdX".to_string()],
            }
        ]
    }

    fn load_price_patterns() -> Vec<PriceManipulationPattern> {
        vec![
            PriceManipulationPattern {
                oracle_read_signatures: vec![[0x50, 0xd2, 0x5b, 0xcd]], // latestRoundData()
                swap_signatures: vec![[0x38, 0xed, 0x17, 0x39]], // swapExactTokensForTokens()
                price_deviation_threshold: 0.05,
                manipulation_timeframe: 10,
            }
        ]
    }

    fn load_liquidity_patterns() -> Vec<LiquidityAttackPattern> {
        vec![
            LiquidityAttackPattern {
                withdrawal_signatures: vec![[0x2e, 0x1a, 0x7d, 0x4d]], // withdraw()
                deposit_signatures: vec![[0xd0, 0xe3, 0x0d, 0xb0]], // deposit()
                threshold_manipulation_ratio: 0.3,
            }
        ]
    }

    fn load_governance_patterns() -> Vec<GovernanceAttackPattern> {
        vec![
            GovernanceAttackPattern {
                voting_signatures: vec![[0x15, 0x37, 0x3e, 0x3d]], // castVote()
                proposal_signatures: vec![[0xda, 0x95, 0x69, 0x1a]], // propose()
                execution_signatures: vec![[0xfe, 0x0d, 0x94, 0xc1]], // execute()
            }
        ]
    }
}

impl FlashLoanTracker {
    fn new() -> Self {
        Self {
            active_loans: HashMap::new(),
            loan_patterns: Vec::new(),
            suspicious_loan_chains: Vec::new(),
        }
    }
}

impl PriceOracleMonitor {
    fn new() -> Self {
        Self {
            oracle_contracts: HashSet::new(),
            price_feeds: HashMap::new(),
            manipulation_alerts: Vec::new(),
        }
    }
}

// Additional helper structs
#[derive(Debug, Clone)]
struct DexInteraction {
    dex_address: String,
    interaction_type: String,
    token_in: String,
    token_out: String,
    amount_in: f64,
    amount_out: f64,
    price_impact: f64,
}

#[derive(Debug, Clone)]
struct PriceManipulationEvent {
    affected_dexes: Vec<String>,
    price_deviation: f64,
    manipulation_timeframe: u64,
}

#[derive(Debug, Clone)]
struct LiquidityDrainPattern {
    affected_pools: Vec<String>,
    drain_percentage: f64,
    total_value_drained: f64,
    estimated_profit: f64,
    affected_protocols: Vec<String>,
    drain_steps: Vec<ManipulationStep>,
}

#[derive(Debug, Clone)]
struct GovernanceManipulation {
    affected_contracts: Vec<String>,
    steps: Vec<ManipulationStep>,
    impact: FinancialImpact,
}

#[derive(Debug, Clone)]
struct OracleManipulationChain {
    compromised_oracles: Vec<String>,
    manipulation_steps: Vec<ManipulationStep>,
    estimated_impact: FinancialImpact,
}

#[derive(Debug, Clone)]
struct CollateralManipulation {
    affected_contracts: Vec<String>,
    affected_protocols: Vec<String>,
    ratio_deviation: f64,
    steps: Vec<ManipulationStep>,
    impact: FinancialImpact,
}

impl fmt::Display for StateManipulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateManipulationType::FlashLoanManipulation => write!(f, "Flash Loan Manipulation"),
            StateManipulationType::CrossDexPriceManipulation => write!(f, "Cross-DEX Price Manipulation"),
            StateManipulationType::LiquidityDrainAttack => write!(f, "Liquidity Drain Attack"),
            StateManipulationType::GovernanceStatePoison => write!(f, "Governance State Poisoning"),
            StateManipulationType::OracleManipulationChain => write!(f, "Oracle Manipulation Chain"),
            StateManipulationType::CollateralRatioManipulation => write!(f, "Collateral Ratio Manipulation"),
            StateManipulationType::ReserveDepletionAttack => write!(f, "Reserve Depletion Attack"),
            StateManipulationType::CrossProtocolInvariantViolation => write!(f, "Cross-Protocol Invariant Violation"),
            StateManipulationType::CoordinatedLiquidationAttack => write!(f, "Coordinated Liquidation Attack"),
            StateManipulationType::MultiStepArbitrageExploit => write!(f, "Multi-Step Arbitrage Exploit"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_manipulation_detection() {
        let trace = EVMExecutionTrace::new();
        let mut analyzer = CrossContractStateManipulator::new(trace);
        let vulnerabilities = analyzer.detect_vulnerabilities();
        
        // Should detect various manipulation patterns
        assert!(!vulnerabilities.is_empty());
    }

    #[test]
    fn test_flash_loan_pattern_matching() {
        let patterns = ManipulationPatternDetector::new();
        assert!(!patterns.flash_loan_patterns.is_empty());
    }

    #[test]
    fn test_financial_impact_assessment() {
        let trace = EVMExecutionTrace::new();
        let analyzer = CrossContractStateManipulator::new(trace);
        let chain = vec![];
        let impact = analyzer.assess_financial_impact(&chain);
        
        assert!(impact.estimated_value_at_risk >= 0.0);
    }
}
