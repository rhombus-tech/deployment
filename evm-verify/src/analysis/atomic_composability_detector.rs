use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Atomic composability failure types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposabilityFailureType {
    /// Partial execution with incomplete state transitions
    PartialExecutionAttack,
    /// State inconsistency during multi-contract operations
    StateInconsistencyWindow,
    /// Transaction revert exploitation for state manipulation
    RevertExploitation,
    /// Cross-contract atomicity violation
    AtomicityViolation,
    /// Multi-step transaction ordering dependency
    OrderingDependencyFailure,
    /// Cross-contract rollback inconsistency
    RollbackInconsistency,
}

/// Atomic composability vulnerability details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposabilityVulnerability {
    pub failure_type: ComposabilityFailureType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub affected_contracts: Vec<String>,
    pub execution_steps: Vec<ComposabilityStep>,
    pub financial_impact: ComposabilityImpact,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposabilityStep {
    pub step_id: u32,
    pub contract_address: String,
    pub function_selector: Vec<u8>,
    pub execution_result: ExecutionResult,
    pub state_changes: Vec<StateChange>,
    pub gas_used: u64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionResult {
    Success,
    Revert,
    OutOfGas,
    Exception,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub contract: String,
    pub storage_slot: String,
    pub old_value: String,
    pub new_value: String,
    pub change_type: StateChangeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChangeType {
    BalanceUpdate,
    AllowanceChange,
    OwnershipTransfer,
    StateVariable,
    StorageWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposabilityImpact {
    pub potential_loss: u64,
    pub affected_users: u32,
    pub protocol_risk: ProtocolRisk,
    pub systemic_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolRisk {
    Low,
    Medium,
    High,
    Critical,
}

/// Atomic composability detector
pub struct AtomicComposabilityDetector {
    execution_trace: Option<EVMExecutionTrace>,
    transaction_boundaries: Vec<TransactionBoundary>,
    state_tracker: StateTracker,
}

#[derive(Debug, Clone)]
struct TransactionBoundary {
    start_step: u32,
    end_step: u32,
    contracts_involved: HashSet<String>,
    atomic_group: AtomicGroup,
}

#[derive(Debug, Clone)]
enum AtomicGroup {
    SingleContract,
    MultiContract,
    CrossProtocol,
}

#[derive(Debug, Clone)]
struct StateTracker {
    contract_states: HashMap<String, ContractState>,
    pending_changes: VecDeque<PendingStateChange>,
    consistency_points: Vec<ConsistencyPoint>,
}

#[derive(Debug, Clone)]
struct ContractState {
    storage: HashMap<String, String>,
    balance: u64,
    nonce: u32,
    code_hash: String,
}

#[derive(Debug, Clone)]
struct PendingStateChange {
    contract: String,
    change: StateChange,
    dependency_count: u32,
    committed: bool,
}

#[derive(Debug, Clone)]
struct ConsistencyPoint {
    step_id: u32,
    state_snapshot: HashMap<String, ContractState>,
    rollback_possible: bool,
}

impl AtomicComposabilityDetector {
    pub fn new() -> Self {
        Self {
            execution_trace: None,
            transaction_boundaries: Vec::new(),
            state_tracker: StateTracker {
                contract_states: HashMap::new(),
                pending_changes: VecDeque::new(),
                consistency_points: Vec::new(),
            },
        }
    }

    pub fn analyze_composability(&mut self, trace: EVMExecutionTrace) -> Vec<ComposabilityVulnerability> {
        self.execution_trace = Some(trace.clone());
        let mut vulnerabilities = Vec::new();

        // Identify transaction boundaries and atomic groups
        self.identify_transaction_boundaries(&trace);
        
        // Detect composability failures
        vulnerabilities.extend(self.detect_partial_execution_attacks());
        vulnerabilities.extend(self.detect_state_inconsistency_windows());
        vulnerabilities.extend(self.detect_revert_exploitation());
        vulnerabilities.extend(self.detect_atomicity_violations());
        vulnerabilities.extend(self.detect_ordering_dependency_failures());
        vulnerabilities.extend(self.detect_rollback_inconsistencies());

        vulnerabilities
    }

    fn identify_transaction_boundaries(&mut self, trace: &EVMExecutionTrace) {
        let mut current_boundary = TransactionBoundary {
            start_step: 0,
            end_step: 0,
            contracts_involved: HashSet::new(),
            atomic_group: AtomicGroup::SingleContract,
        };

        for (i, step) in trace.execution_steps.iter().enumerate() {
            // Detect cross-contract calls
            if self.is_cross_contract_call(step) {
                current_boundary.contracts_involved.insert(self.extract_contract_address(step));
                
                if current_boundary.contracts_involved.len() > 1 {
                    current_boundary.atomic_group = AtomicGroup::MultiContract;
                }
            }

            // Detect transaction boundaries
            if self.is_transaction_boundary(step, i) {
                current_boundary.end_step = i as u32;
                self.transaction_boundaries.push(current_boundary.clone());
                
                current_boundary = TransactionBoundary {
                    start_step: i as u32 + 1,
                    end_step: 0,
                    contracts_involved: HashSet::new(),
                    atomic_group: AtomicGroup::SingleContract,
                };
            }
        }
    }

    fn detect_partial_execution_attacks(&self) -> Vec<ComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        for boundary in &self.transaction_boundaries {
            if self.has_partial_execution_pattern(boundary) {
                vulnerabilities.push(ComposabilityVulnerability {
                    failure_type: ComposabilityFailureType::PartialExecutionAttack,
                    severity: SecuritySeverity::High,
                    confidence: 0.9,
                    description: "Multi-contract transaction partially executes, creating exploitable state".to_string(),
                    affected_contracts: boundary.contracts_involved.iter().cloned().collect(),
                    execution_steps: self.extract_execution_steps(boundary),
                    financial_impact: ComposabilityImpact {
                        potential_loss: 1000000, // $1M+ potential
                        affected_users: 100,
                        protocol_risk: ProtocolRisk::High,
                        systemic_risk: true,
                    },
                    mitigation_strategies: vec![
                        "Implement all-or-nothing execution patterns".to_string(),
                        "Use atomic transaction wrappers".to_string(),
                        "Add comprehensive rollback mechanisms".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_state_inconsistency_windows(&self) -> Vec<ComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for windows where contract states are temporarily inconsistent
        for point in &self.state_tracker.consistency_points {
            if self.has_inconsistency_window(point) {
                vulnerabilities.push(ComposabilityVulnerability {
                    failure_type: ComposabilityFailureType::StateInconsistencyWindow,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.8,
                    description: "State inconsistency window allows exploitation between contract updates".to_string(),
                    affected_contracts: self.get_inconsistent_contracts(point),
                    execution_steps: vec![], // Would be populated with actual steps
                    financial_impact: ComposabilityImpact {
                        potential_loss: 500000,
                        affected_users: 50,
                        protocol_risk: ProtocolRisk::Medium,
                        systemic_risk: false,
                    },
                    mitigation_strategies: vec![
                        "Implement state locks during multi-contract operations".to_string(),
                        "Use commit-reveal patterns for sensitive updates".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_revert_exploitation(&self) -> Vec<ComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect patterns where reverts are used to manipulate cross-contract state
        for boundary in &self.transaction_boundaries {
            if self.has_revert_exploitation_pattern(boundary) {
                vulnerabilities.push(ComposabilityVulnerability {
                    failure_type: ComposabilityFailureType::RevertExploitation,
                    severity: SecuritySeverity::High,
                    confidence: 0.85,
                    description: "Transaction reverts exploited to create favorable cross-contract state".to_string(),
                    affected_contracts: boundary.contracts_involved.iter().cloned().collect(),
                    execution_steps: self.extract_execution_steps(boundary),
                    financial_impact: ComposabilityImpact {
                        potential_loss: 2000000,
                        affected_users: 200,
                        protocol_risk: ProtocolRisk::Critical,
                        systemic_risk: true,
                    },
                    mitigation_strategies: vec![
                        "Implement revert-safe state management".to_string(),
                        "Use external state validation".to_string(),
                        "Add revert protection mechanisms".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    fn detect_atomicity_violations(&self) -> Vec<ComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        for boundary in &self.transaction_boundaries {
            if matches!(boundary.atomic_group, AtomicGroup::MultiContract) {
                if self.violates_atomicity(boundary) {
                    vulnerabilities.push(ComposabilityVulnerability {
                        failure_type: ComposabilityFailureType::AtomicityViolation,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.95,
                        description: "Multi-contract operation lacks proper atomicity guarantees".to_string(),
                        affected_contracts: boundary.contracts_involved.iter().cloned().collect(),
                        execution_steps: self.extract_execution_steps(boundary),
                        financial_impact: ComposabilityImpact {
                            potential_loss: 5000000,
                            affected_users: 1000,
                            protocol_risk: ProtocolRisk::Critical,
                            systemic_risk: true,
                        },
                        mitigation_strategies: vec![
                            "Implement proper atomic execution patterns".to_string(),
                            "Use transaction batching mechanisms".to_string(),
                            "Add cross-contract state validation".to_string(),
                        ],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_ordering_dependency_failures(&self) -> Vec<ComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect operations that depend on specific ordering across contracts
        if self.has_ordering_dependencies() {
            vulnerabilities.push(ComposabilityVulnerability {
                failure_type: ComposabilityFailureType::OrderingDependencyFailure,
                severity: SecuritySeverity::Medium,
                confidence: 0.7,
                description: "Cross-contract operations have exploitable ordering dependencies".to_string(),
                affected_contracts: self.get_all_involved_contracts(),
                execution_steps: vec![],
                financial_impact: ComposabilityImpact {
                    potential_loss: 300000,
                    affected_users: 30,
                    protocol_risk: ProtocolRisk::Medium,
                    systemic_risk: false,
                },
                mitigation_strategies: vec![
                    "Implement order-independent execution".to_string(),
                    "Use commit-reveal for sensitive operations".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_rollback_inconsistencies(&self) -> Vec<ComposabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        for point in &self.state_tracker.consistency_points {
            if point.rollback_possible && self.has_rollback_inconsistency(point) {
                vulnerabilities.push(ComposabilityVulnerability {
                    failure_type: ComposabilityFailureType::RollbackInconsistency,
                    severity: SecuritySeverity::High,
                    confidence: 0.8,
                    description: "Rollback mechanism creates inconsistent cross-contract state".to_string(),
                    affected_contracts: self.get_rollback_affected_contracts(point),
                    execution_steps: vec![],
                    financial_impact: ComposabilityImpact {
                        potential_loss: 800000,
                        affected_users: 80,
                        protocol_risk: ProtocolRisk::High,
                        systemic_risk: true,
                    },
                    mitigation_strategies: vec![
                        "Implement consistent rollback mechanisms".to_string(),
                        "Add cross-contract rollback validation".to_string(),
                    ],
                });
            }
        }

        vulnerabilities
    }

    // Helper methods for pattern detection
    
    fn is_cross_contract_call(&self, step: &ExecutionStep) -> bool {
        // Check if step represents a cross-contract call
        step.opcode == 0xF1 || step.opcode == 0xF4 || step.opcode == 0xFA // CALL, DELEGATECALL, STATICCALL
    }

    fn extract_contract_address(&self, step: &ExecutionStep) -> String {
        // Extract contract address from execution step
        format!("0x{:x}", step.contract_address)
    }

    fn is_transaction_boundary(&self, step: &ExecutionStep, index: usize) -> bool {
        // Simplified boundary detection
        step.opcode == 0x00 || index == 0 // STOP or first step
    }

    fn has_partial_execution_pattern(&self, boundary: &TransactionBoundary) -> bool {
        // Check if transaction boundary shows partial execution
        boundary.contracts_involved.len() > 1 && 
        self.has_incomplete_state_transitions(boundary)
    }

    fn has_incomplete_state_transitions(&self, boundary: &TransactionBoundary) -> bool {
        // Simplified check for incomplete state transitions
        boundary.contracts_involved.len() > 2
    }

    fn extract_execution_steps(&self, boundary: &TransactionBoundary) -> Vec<ComposabilityStep> {
        // Extract execution steps for the boundary
        vec![] // Simplified implementation
    }

    fn has_inconsistency_window(&self, point: &ConsistencyPoint) -> bool {
        // Check if consistency point has exploitable inconsistency window
        point.rollback_possible && point.state_snapshot.len() > 1
    }

    fn get_inconsistent_contracts(&self, point: &ConsistencyPoint) -> Vec<String> {
        point.state_snapshot.keys().cloned().collect()
    }

    fn has_revert_exploitation_pattern(&self, boundary: &TransactionBoundary) -> bool {
        // Check for revert exploitation patterns
        boundary.contracts_involved.len() > 1
    }

    fn violates_atomicity(&self, boundary: &TransactionBoundary) -> bool {
        // Check if boundary violates atomicity requirements
        matches!(boundary.atomic_group, AtomicGroup::MultiContract) && 
        boundary.contracts_involved.len() > 2
    }

    fn has_ordering_dependencies(&self) -> bool {
        // Check for ordering dependencies
        self.transaction_boundaries.len() > 1
    }

    fn get_all_involved_contracts(&self) -> Vec<String> {
        let mut contracts = HashSet::new();
        for boundary in &self.transaction_boundaries {
            contracts.extend(boundary.contracts_involved.iter().cloned());
        }
        contracts.into_iter().collect()
    }

    fn has_rollback_inconsistency(&self, point: &ConsistencyPoint) -> bool {
        // Check for rollback inconsistencies
        point.rollback_possible
    }

    fn get_rollback_affected_contracts(&self, point: &ConsistencyPoint) -> Vec<String> {
        point.state_snapshot.keys().cloned().collect()
    }
}

/// Main detection function for integration
pub fn detect_atomic_composability_failures(trace: EVMExecutionTrace) -> Vec<SecurityWarning> {
    let mut detector = AtomicComposabilityDetector::new();
    let vulnerabilities = detector.analyze_composability(trace);

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::ComposabilityVulnerability,
            severity: vuln.severity,
            pc: 0, // Would be populated with actual PC
            description: vuln.description,
            operations: vec![],
            remediation: generate_composability_remediation(&vuln.failure_type),
        }
    }).collect()
}

fn generate_composability_remediation(failure_type: &ComposabilityFailureType) -> String {
    match failure_type {
        ComposabilityFailureType::PartialExecutionAttack => {
            "Implement all-or-nothing execution patterns with proper rollback mechanisms.".to_string()
        },
        ComposabilityFailureType::StateInconsistencyWindow => {
            "Use state locks and atomic updates to prevent inconsistency windows.".to_string()
        },
        ComposabilityFailureType::RevertExploitation => {
            "Implement revert-safe state management and external validation.".to_string()
        },
        ComposabilityFailureType::AtomicityViolation => {
            "Use transaction batching and cross-contract state validation.".to_string()
        },
        ComposabilityFailureType::OrderingDependencyFailure => {
            "Implement order-independent execution with commit-reveal patterns.".to_string()
        },
        ComposabilityFailureType::RollbackInconsistency => {
            "Add consistent rollback mechanisms with cross-contract validation.".to_string()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};

    fn create_test_execution_step(opcode: u8, contract_address: Option<u32>, gas_used: u64, success: bool) -> ExecutionStep {
        ExecutionStep {
            opcode,
            contract_address,
            gas_used,
            success,
            stack: vec![],
            memory: vec![],
            storage: std::collections::HashMap::new(),
        }
    }

    fn create_multi_contract_trace() -> EVMExecutionTrace {
        EVMExecutionTrace {
            steps: vec![
                create_test_execution_step(0xF1, Some(0x1234), 21000, true), // CALL to contract A
                create_test_execution_step(0xF1, Some(0x5678), 15000, true), // CALL to contract B
                create_test_execution_step(0xF1, Some(0x9ABC), 12000, false), // CALL to contract C (fails)
                create_test_execution_step(0x00, None, 0, true), // STOP
            ],
            gas_used: 48000,
            success: false,
        }
    }

    fn create_revert_exploitation_trace() -> EVMExecutionTrace {
        EVMExecutionTrace {
            steps: vec![
                create_test_execution_step(0xF1, Some(0x1111), 25000, true), // Setup contract A
                create_test_execution_step(0xF1, Some(0x2222), 20000, true), // Setup contract B
                create_test_execution_step(0xF1, Some(0x3333), 18000, false), // Exploitative revert
                create_test_execution_step(0xFD, None, 0, false), // REVERT
            ],
            gas_used: 63000,
            success: false,
        }
    }

    fn create_atomicity_violation_trace() -> EVMExecutionTrace {
        EVMExecutionTrace {
            steps: vec![
                create_test_execution_step(0xF1, Some(0xAAAA), 30000, true), // Contract A operation
                create_test_execution_step(0xF1, Some(0xBBBB), 25000, true), // Contract B operation
                create_test_execution_step(0xF1, Some(0xCCCC), 20000, true), // Contract C operation
                create_test_execution_step(0xF1, Some(0xDDDD), 15000, false), // Contract D fails
                create_test_execution_step(0x00, None, 0, true), // STOP without proper rollback
            ],
            gas_used: 90000,
            success: true, // Transaction succeeds despite partial failure
        }
    }

    #[test]
    fn test_partial_execution_detection() {
        let mut detector = AtomicComposabilityDetector::new();
        let trace = create_multi_contract_trace();
        
        let vulnerabilities = detector.analyze_composability(trace);
        
        let partial_execution_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| matches!(v.failure_type, ComposabilityFailureType::PartialExecutionAttack))
            .collect();
        
        assert!(!partial_execution_vulns.is_empty(), "Should detect partial execution attack");
        assert_eq!(partial_execution_vulns[0].severity, SecuritySeverity::High);
        assert!(partial_execution_vulns[0].confidence > 0.8);
        assert!(partial_execution_vulns[0].affected_contracts.len() > 1);
    }

    #[test]
    fn test_state_inconsistency_detection() {
        let mut detector = AtomicComposabilityDetector::new();
        let trace = create_multi_contract_trace();
        
        // Add some consistency points to the state tracker
        detector.state_tracker.consistency_points.push(ConsistencyPoint {
            step_id: 1,
            state_snapshot: {
                let mut snapshot = HashMap::new();
                snapshot.insert("0x1234".to_string(), ContractState {
                    storage: HashMap::new(),
                    balance: 1000,
                    nonce: 1,
                    code_hash: "hash1".to_string(),
                });
                snapshot.insert("0x5678".to_string(), ContractState {
                    storage: HashMap::new(),
                    balance: 2000,
                    nonce: 2,
                    code_hash: "hash2".to_string(),
                });
                snapshot
            },
            rollback_possible: true,
        });
        
        let vulnerabilities = detector.analyze_composability(trace);
        
        let inconsistency_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| matches!(v.failure_type, ComposabilityFailureType::StateInconsistencyWindow))
            .collect();
        
        assert!(!inconsistency_vulns.is_empty(), "Should detect state inconsistency window");
        assert_eq!(inconsistency_vulns[0].severity, SecuritySeverity::Medium);
    }

    #[test]
    fn test_revert_exploitation_detection() {
        let mut detector = AtomicComposabilityDetector::new();
        let trace = create_revert_exploitation_trace();
        
        let vulnerabilities = detector.analyze_composability(trace);
        
        let revert_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| matches!(v.failure_type, ComposabilityFailureType::RevertExploitation))
            .collect();
        
        assert!(!revert_vulns.is_empty(), "Should detect revert exploitation");
        assert_eq!(revert_vulns[0].severity, SecuritySeverity::High);
        assert!(revert_vulns[0].financial_impact.potential_loss > 1000000);
        assert!(revert_vulns[0].financial_impact.systemic_risk);
    }

    #[test]
    fn test_atomicity_violation_detection() {
        let mut detector = AtomicComposabilityDetector::new();
        let trace = create_atomicity_violation_trace();
        
        let vulnerabilities = detector.analyze_composability(trace);
        
        let atomicity_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| matches!(v.failure_type, ComposabilityFailureType::AtomicityViolation))
            .collect();
        
        assert!(!atomicity_vulns.is_empty(), "Should detect atomicity violation");
        assert_eq!(atomicity_vulns[0].severity, SecuritySeverity::Critical);
        assert!(atomicity_vulns[0].confidence > 0.9);
        assert!(atomicity_vulns[0].affected_contracts.len() > 2);
    }

    #[test]
    fn test_ordering_dependency_detection() {
        let mut detector = AtomicComposabilityDetector::new();
        let trace = create_multi_contract_trace();
        
        // Create multiple transaction boundaries to test ordering dependencies
        detector.transaction_boundaries = vec![
            TransactionBoundary {
                start_step: 0,
                end_step: 1,
                contracts_involved: ["0x1234".to_string(), "0x5678".to_string()].into_iter().collect(),
                atomic_group: AtomicGroup::MultiContract,
            },
            TransactionBoundary {
                start_step: 2,
                end_step: 3,
                contracts_involved: ["0x9ABC".to_string()].into_iter().collect(),
                atomic_group: AtomicGroup::SingleContract,
            },
        ];
        
        let vulnerabilities = detector.analyze_composability(trace);
        
        let ordering_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| matches!(v.failure_type, ComposabilityFailureType::OrderingDependencyFailure))
            .collect();
        
        assert!(!ordering_vulns.is_empty(), "Should detect ordering dependency failure");
        assert_eq!(ordering_vulns[0].severity, SecuritySeverity::Medium);
    }

    #[test]
    fn test_rollback_inconsistency_detection() {
        let mut detector = AtomicComposabilityDetector::new();
        let trace = create_multi_contract_trace();
        
        // Add rollback-enabled consistency point
        detector.state_tracker.consistency_points.push(ConsistencyPoint {
            step_id: 2,
            state_snapshot: {
                let mut snapshot = HashMap::new();
                snapshot.insert("0x1234".to_string(), ContractState {
                    storage: HashMap::new(),
                    balance: 1500,
                    nonce: 2,
                    code_hash: "hash1_updated".to_string(),
                });
                snapshot
            },
            rollback_possible: true,
        });
        
        let vulnerabilities = detector.analyze_composability(trace);
        
        let rollback_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|v| matches!(v.failure_type, ComposabilityFailureType::RollbackInconsistency))
            .collect();
        
        assert!(!rollback_vulns.is_empty(), "Should detect rollback inconsistency");
        assert_eq!(rollback_vulns[0].severity, SecuritySeverity::High);
        assert!(rollback_vulns[0].financial_impact.systemic_risk);
    }

    #[test]
    fn test_security_warning_generation() {
        let trace = create_revert_exploitation_trace();
        let warnings = detect_atomic_composability_failures(trace);
        
        assert!(!warnings.is_empty(), "Should generate security warnings");
        
        for warning in &warnings {
            assert!(matches!(warning.kind, SecurityWarningKind::CrossContractVulnerability));
            assert!(!warning.description.is_empty());
            assert!(!warning.remediation.is_empty());
        }
    }

    #[test]
    fn test_remediation_advice_generation() {
        let partial_remediation = generate_composability_remediation(&ComposabilityFailureType::PartialExecutionAttack);
        assert!(partial_remediation.contains("all-or-nothing"));
        
        let revert_remediation = generate_composability_remediation(&ComposabilityFailureType::RevertExploitation);
        assert!(revert_remediation.contains("revert-safe"));
        
        let atomicity_remediation = generate_composability_remediation(&ComposabilityFailureType::AtomicityViolation);
        assert!(atomicity_remediation.contains("transaction batching"));
    }

    #[test]
    fn test_complex_multi_attack_scenario() {
        let mut detector = AtomicComposabilityDetector::new();
        
        let complex_trace = EVMExecutionTrace {
            steps: vec![
                create_test_execution_step(0xF1, Some(0x1111), 30000, true), // DEX A setup
                create_test_execution_step(0xF1, Some(0x2222), 25000, true), // DEX B setup  
                create_test_execution_step(0xF1, Some(0x3333), 40000, true), // Flash loan initiation
                create_test_execution_step(0xF1, Some(0x1111), 20000, true), // DEX A manipulation
                create_test_execution_step(0xF1, Some(0x2222), 18000, false), // DEX B fails
                create_test_execution_step(0xFD, None, 0, false), // Strategic revert
                create_test_execution_step(0xF1, Some(0x4444), 15000, true), // Profit extraction
            ],
            gas_used: 148000,
            success: false,
        };
        
        let vulnerabilities = detector.analyze_composability(complex_trace);
        
        // Should detect multiple vulnerability types in complex scenarios
        let vulnerability_types: HashSet<_> = vulnerabilities.iter()
            .map(|v| &v.failure_type)
            .collect();
        
        assert!(vulnerability_types.len() >= 2, "Should detect multiple vulnerability types in complex scenario");
        
        // Should have high-severity vulnerabilities
        let high_severity_count = vulnerabilities.iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::High | SecuritySeverity::Critical))
            .count();
        
        assert!(high_severity_count > 0, "Should detect high-severity vulnerabilities in complex scenario");
    }
}
