use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Cross-contract data integrity attack types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataIntegrityAttackType {
    /// Stale data exploitation between contracts
    StaleDataExploitation,
    /// Cache poisoning attacks across protocols
    CachePoisoningAttack,
    /// Cross-contract state desynchronization
    StateDesynchronization,
    /// Data race conditions in multi-contract operations
    DataRaceCondition,
    /// Inconsistent data validation across contracts
    InconsistentValidation,
    /// Cross-contract timestamp manipulation
    TimestampManipulation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityVulnerability {
    pub attack_type: DataIntegrityAttackType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub affected_contracts: Vec<String>,
    pub data_dependencies: Vec<DataDependency>,
    pub integrity_violations: Vec<IntegrityViolation>,
    pub exploitation_conditions: Vec<String>,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDependency {
    pub source_contract: String,
    pub target_contract: String,
    pub data_type: DataType,
    pub freshness_requirement: u64,
    pub validation_method: ValidationMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    Price,
    Balance,
    Timestamp,
    State,
    Configuration,
    Authorization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationMethod {
    NoValidation,
    TimestampCheck,
    SignatureVerification,
    ConsensusValidation,
    CrossReference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityViolation {
    pub violation_type: ViolationType,
    pub source_location: u32,
    pub affected_data: String,
    pub impact_level: ImpactLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    StalenessViolation,
    ConsistencyViolation,
    ValidationBypass,
    RaceCondition,
    CacheCorruption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Cross-contract data integrity detector
pub struct DataIntegrityDetector {
    execution_trace: Option<EVMExecutionTrace>,
    data_flow_graph: HashMap<String, Vec<DataFlow>>,
    cache_operations: Vec<CacheOperation>,
    timestamp_dependencies: HashMap<String, Vec<TimestampDependency>>,
    validation_points: Vec<ValidationPoint>,
}

#[derive(Debug, Clone)]
struct DataFlow {
    from_contract: String,
    to_contract: String,
    data_type: DataType,
    operation_step: u32,
    validation_required: bool,
}

#[derive(Debug, Clone)]
struct CacheOperation {
    step_id: u32,
    contract: String,
    operation: CacheOpType,
    data_key: String,
    timestamp: u64,
}

#[derive(Debug, Clone)]
enum CacheOpType {
    Read,
    Write,
    Invalidate,
    Update,
}

#[derive(Debug, Clone)]
struct TimestampDependency {
    contract: String,
    dependent_operation: String,
    max_staleness: u64,
    validation_method: ValidationMethod,
}

#[derive(Debug, Clone)]
struct ValidationPoint {
    step_id: u32,
    contract: String,
    validation_type: ValidationType,
    passed: bool,
}

#[derive(Debug, Clone)]
enum ValidationType {
    TimestampCheck,
    DataFreshness,
    CrossContractConsistency,
    StateValidation,
}

impl DataIntegrityDetector {
    pub fn new() -> Self {
        Self {
            execution_trace: None,
            data_flow_graph: HashMap::new(),
            cache_operations: Vec::new(),
            timestamp_dependencies: HashMap::new(),
            validation_points: Vec::new(),
        }
    }

    pub fn analyze_data_integrity(&mut self, trace: EVMExecutionTrace) -> Vec<DataIntegrityVulnerability> {
        self.execution_trace = Some(trace.clone());
        let mut vulnerabilities = Vec::new();

        // Build data flow and dependency graphs
        self.build_data_flow_graph(&trace);
        self.track_cache_operations(&trace);
        self.identify_timestamp_dependencies(&trace);

        // Detect various data integrity vulnerabilities
        vulnerabilities.extend(self.detect_stale_data_exploitation());
        vulnerabilities.extend(self.detect_cache_poisoning_attacks());
        vulnerabilities.extend(self.detect_state_desynchronization());
        vulnerabilities.extend(self.detect_data_race_conditions());
        vulnerabilities.extend(self.detect_inconsistent_validation());
        vulnerabilities.extend(self.detect_timestamp_manipulation());

        vulnerabilities
    }

    fn build_data_flow_graph(&mut self, trace: &EVMExecutionTrace) {
        for (i, step) in trace.execution_steps.iter().enumerate() {
            if self.is_cross_contract_data_access(step) {
                let (source, target) = self.extract_data_flow_info(step);
                let data_type = self.classify_data_type(step);
                
                let flow = DataFlow {
                    from_contract: source.clone(),
                    to_contract: target.clone(),
                    data_type,
                    operation_step: i as u32,
                    validation_required: self.requires_validation(step),
                };

                self.data_flow_graph
                    .entry(source)
                    .or_insert_with(Vec::new)
                    .push(flow);
            }
        }
    }

    fn track_cache_operations(&mut self, trace: &EVMExecutionTrace) {
        for (i, step) in trace.execution_steps.iter().enumerate() {
            if self.is_cache_operation(step) {
                let cache_op = CacheOperation {
                    step_id: i as u32,
                    contract: self.get_contract_address(step),
                    operation: self.classify_cache_operation(step),
                    data_key: self.extract_cache_key(step),
                    timestamp: self.extract_timestamp(step),
                };
                self.cache_operations.push(cache_op);
            }
        }
    }

    fn identify_timestamp_dependencies(&mut self, trace: &EVMExecutionTrace) {
        for (i, step) in trace.execution_steps.iter().enumerate() {
            if self.has_timestamp_dependency(step) {
                let contract = self.get_contract_address(step);
                let dependency = TimestampDependency {
                    contract: contract.clone(),
                    dependent_operation: self.classify_operation(step),
                    max_staleness: self.calculate_max_staleness(step),
                    validation_method: self.determine_validation_method(step),
                };

                self.timestamp_dependencies
                    .entry(contract)
                    .or_insert_with(Vec::new)
                    .push(dependency);
            }
        }
    }

    fn detect_stale_data_exploitation(&self) -> Vec<DataIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        for flows in self.data_flow_graph.values() {
            for flow in flows {
                if self.has_stale_data_risk(flow) {
                    vulnerabilities.push(DataIntegrityVulnerability {
                        attack_type: DataIntegrityAttackType::StaleDataExploitation,
                        severity: SecuritySeverity::High,
                        confidence: 0.8,
                        description: format!("Stale data exploitation risk between {} and {}", flow.from_contract, flow.to_contract),
                        affected_contracts: vec![flow.from_contract.clone(), flow.to_contract.clone()],
                        data_dependencies: vec![DataDependency {
                            source_contract: flow.from_contract.clone(),
                            target_contract: flow.to_contract.clone(),
                            data_type: flow.data_type.clone(),
                            freshness_requirement: 300, // 5 minutes max staleness
                            validation_method: ValidationMethod::TimestampCheck,
                        }],
                        integrity_violations: vec![IntegrityViolation {
                            violation_type: ViolationType::StalenessViolation,
                            source_location: flow.operation_step,
                            affected_data: format!("{:?}", flow.data_type),
                            impact_level: ImpactLevel::High,
                        }],
                        exploitation_conditions: vec![
                            "Data not validated for freshness".to_string(),
                            "No timestamp checks implemented".to_string(),
                            "Cross-contract data dependency".to_string(),
                        ],
                        mitigation_strategies: vec![
                            "Implement timestamp validation for cross-contract data".to_string(),
                            "Add maximum staleness limits".to_string(),
                            "Use data versioning mechanisms".to_string(),
                        ],
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_cache_poisoning_attacks(&self) -> Vec<DataIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_cache_poisoning_pattern() {
            vulnerabilities.push(DataIntegrityVulnerability {
                attack_type: DataIntegrityAttackType::CachePoisoningAttack,
                severity: SecuritySeverity::Critical,
                confidence: 0.9,
                description: "Cross-contract cache poisoning attack vector detected".to_string(),
                affected_contracts: self.get_cache_affected_contracts(),
                data_dependencies: self.extract_cache_dependencies(),
                integrity_violations: vec![IntegrityViolation {
                    violation_type: ViolationType::CacheCorruption,
                    source_location: 0,
                    affected_data: "cached_price_data".to_string(),
                    impact_level: ImpactLevel::Critical,
                }],
                exploitation_conditions: vec![
                    "Shared cache between contracts".to_string(),
                    "Insufficient cache validation".to_string(),
                    "Cache write permissions too broad".to_string(),
                ],
                mitigation_strategies: vec![
                    "Implement cache access controls".to_string(),
                    "Add cache integrity verification".to_string(),
                    "Use contract-specific cache namespaces".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_state_desynchronization(&self) -> Vec<DataIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_state_desync_pattern() {
            vulnerabilities.push(DataIntegrityVulnerability {
                attack_type: DataIntegrityAttackType::StateDesynchronization,
                severity: SecuritySeverity::High,
                confidence: 0.85,
                description: "Cross-contract state desynchronization vulnerability detected".to_string(),
                affected_contracts: vec!["contract_a".to_string(), "contract_b".to_string()],
                data_dependencies: self.get_state_dependencies(),
                integrity_violations: vec![IntegrityViolation {
                    violation_type: ViolationType::ConsistencyViolation,
                    source_location: 0,
                    affected_data: "shared_state".to_string(),
                    impact_level: ImpactLevel::High,
                }],
                exploitation_conditions: vec![
                    "Shared state between contracts".to_string(),
                    "Asynchronous state updates".to_string(),
                    "No state synchronization mechanisms".to_string(),
                ],
                mitigation_strategies: vec![
                    "Implement atomic state updates".to_string(),
                    "Use state synchronization locks".to_string(),
                    "Add state consistency checks".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_data_race_conditions(&self) -> Vec<DataIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_data_race_pattern() {
            vulnerabilities.push(DataIntegrityVulnerability {
                attack_type: DataIntegrityAttackType::DataRaceCondition,
                severity: SecuritySeverity::Medium,
                confidence: 0.7,
                description: "Data race condition in cross-contract operations detected".to_string(),
                affected_contracts: vec!["racing_contract_a".to_string(), "racing_contract_b".to_string()],
                data_dependencies: self.get_race_dependencies(),
                integrity_violations: vec![IntegrityViolation {
                    violation_type: ViolationType::RaceCondition,
                    source_location: 0,
                    affected_data: "shared_counter".to_string(),
                    impact_level: ImpactLevel::Medium,
                }],
                exploitation_conditions: vec![
                    "Concurrent access to shared data".to_string(),
                    "No synchronization primitives".to_string(),
                    "Non-atomic read-modify-write operations".to_string(),
                ],
                mitigation_strategies: vec![
                    "Use atomic operations for shared data".to_string(),
                    "Implement proper locking mechanisms".to_string(),
                    "Add data access serialization".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_inconsistent_validation(&self) -> Vec<DataIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_inconsistent_validation_pattern() {
            vulnerabilities.push(DataIntegrityVulnerability {
                attack_type: DataIntegrityAttackType::InconsistentValidation,
                severity: SecuritySeverity::Medium,
                confidence: 0.75,
                description: "Inconsistent data validation across contracts detected".to_string(),
                affected_contracts: vec!["validator_a".to_string(), "validator_b".to_string()],
                data_dependencies: self.get_validation_dependencies(),
                integrity_violations: vec![IntegrityViolation {
                    violation_type: ViolationType::ValidationBypass,
                    source_location: 0,
                    affected_data: "input_parameters".to_string(),
                    impact_level: ImpactLevel::Medium,
                }],
                exploitation_conditions: vec![
                    "Different validation rules across contracts".to_string(),
                    "Validation bypass opportunities".to_string(),
                    "Inconsistent input sanitization".to_string(),
                ],
                mitigation_strategies: vec![
                    "Standardize validation rules across contracts".to_string(),
                    "Use shared validation libraries".to_string(),
                    "Implement comprehensive input validation".to_string(),
                ],
            });
        }

        vulnerabilities
    }

    fn detect_timestamp_manipulation(&self) -> Vec<DataIntegrityVulnerability> {
        let mut vulnerabilities = Vec::new();

        for deps in self.timestamp_dependencies.values() {
            for dep in deps {
                if self.has_timestamp_manipulation_risk(dep) {
                    vulnerabilities.push(DataIntegrityVulnerability {
                        attack_type: DataIntegrityAttackType::TimestampManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.8,
                        description: format!("Timestamp manipulation vulnerability in {}", dep.contract),
                        affected_contracts: vec![dep.contract.clone()],
                        data_dependencies: vec![DataDependency {
                            source_contract: "block_timestamp".to_string(),
                            target_contract: dep.contract.clone(),
                            data_type: DataType::Timestamp,
                            freshness_requirement: dep.max_staleness,
                            validation_method: dep.validation_method.clone(),
                        }],
                        integrity_violations: vec![IntegrityViolation {
                            violation_type: ViolationType::ValidationBypass,
                            source_location: 0,
                            affected_data: "timestamp".to_string(),
                            impact_level: ImpactLevel::High,
                        }],
                        exploitation_conditions: vec![
                            "Dependency on block.timestamp".to_string(),
                            "No timestamp validation".to_string(),
                            "Miner timestamp manipulation possible".to_string(),
                        ],
                        mitigation_strategies: vec![
                            "Use external time oracles".to_string(),
                            "Implement timestamp range validation".to_string(),
                            "Add timestamp consensus mechanisms".to_string(),
                        ],
                    });
                }
            }
        }

        vulnerabilities
    }

    // Helper methods

    fn is_cross_contract_data_access(&self, step: &ExecutionStep) -> bool {
        step.opcode == 0xF1 || step.opcode == 0xF4 // CALL or DELEGATECALL
    }

    fn extract_data_flow_info(&self, step: &ExecutionStep) -> (String, String) {
        let source = format!("0x{:x}", u64::from_be_bytes(step.contract_address.to_fixed_bytes()[12..20].try_into().unwrap_or([0u8; 8])) >> 16);
        let target = format!("0x{:x}", u64::from_be_bytes(step.contract_address.to_fixed_bytes()[12..20].try_into().unwrap_or([0u8; 8])) & 0xFFFF);
        (source, target)
    }

    fn classify_data_type(&self, step: &ExecutionStep) -> DataType {
        match step.opcode {
            0x54 => DataType::State,    // SLOAD
            0x55 => DataType::State,    // SSTORE
            0x42 => DataType::Timestamp, // TIMESTAMP
            _ => DataType::Configuration,
        }
    }

    fn requires_validation(&self, _step: &ExecutionStep) -> bool {
        true // Conservative approach
    }

    fn is_cache_operation(&self, step: &ExecutionStep) -> bool {
        matches!(step.opcode, 0x54 | 0x55) // SLOAD or SSTORE
    }

    fn classify_cache_operation(&self, step: &ExecutionStep) -> CacheOpType {
        match step.opcode {
            0x54 => CacheOpType::Read,
            0x55 => CacheOpType::Write,
            _ => CacheOpType::Update,
        }
    }

    fn extract_cache_key(&self, _step: &ExecutionStep) -> String {
        "cache_key".to_string() // Simplified
    }

    fn extract_timestamp(&self, _step: &ExecutionStep) -> u64 {
        1234567890 // Simplified
    }

    fn has_timestamp_dependency(&self, step: &ExecutionStep) -> bool {
        step.opcode == 0x42 // TIMESTAMP
    }

    fn classify_operation(&self, step: &ExecutionStep) -> String {
        match step.opcode {
            0x42 => "TIMESTAMP".to_string(),
            0xF1 => "CALL".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    fn calculate_max_staleness(&self, _step: &ExecutionStep) -> u64 {
        300 // 5 minutes default
    }

    fn determine_validation_method(&self, _step: &ExecutionStep) -> ValidationMethod {
        ValidationMethod::TimestampCheck
    }

    fn get_contract_address(&self, step: &ExecutionStep) -> String {
        format!("0x{:x}", step.contract_address)
    }

    fn has_stale_data_risk(&self, flow: &DataFlow) -> bool {
        !flow.validation_required || matches!(flow.data_type, DataType::Price | DataType::Balance)
    }

    fn has_cache_poisoning_pattern(&self) -> bool {
        self.cache_operations.len() > 2
    }

    fn get_cache_affected_contracts(&self) -> Vec<String> {
        self.cache_operations.iter().map(|op| op.contract.clone()).collect::<HashSet<_>>().into_iter().collect()
    }

    fn extract_cache_dependencies(&self) -> Vec<DataDependency> {
        vec![DataDependency {
            source_contract: "cache_provider".to_string(),
            target_contract: "cache_consumer".to_string(),
            data_type: DataType::Price,
            freshness_requirement: 60,
            validation_method: ValidationMethod::CrossReference,
        }]
    }

    fn has_state_desync_pattern(&self) -> bool {
        self.data_flow_graph.len() > 1
    }

    fn get_state_dependencies(&self) -> Vec<DataDependency> {
        vec![DataDependency {
            source_contract: "state_owner".to_string(),
            target_contract: "state_reader".to_string(),
            data_type: DataType::State,
            freshness_requirement: 0,
            validation_method: ValidationMethod::ConsensusValidation,
        }]
    }

    fn has_data_race_pattern(&self) -> bool {
        self.cache_operations.iter().filter(|op| matches!(op.operation, CacheOpType::Write)).count() > 1
    }

    fn get_race_dependencies(&self) -> Vec<DataDependency> {
        vec![DataDependency {
            source_contract: "writer_a".to_string(),
            target_contract: "writer_b".to_string(),
            data_type: DataType::State,
            freshness_requirement: 0,
            validation_method: ValidationMethod::NoValidation,
        }]
    }

    fn has_inconsistent_validation_pattern(&self) -> bool {
        self.validation_points.iter().any(|vp| !vp.passed)
    }

    fn get_validation_dependencies(&self) -> Vec<DataDependency> {
        vec![DataDependency {
            source_contract: "input_source".to_string(),
            target_contract: "validator".to_string(),
            data_type: DataType::Configuration,
            freshness_requirement: 0,
            validation_method: ValidationMethod::SignatureVerification,
        }]
    }

    fn has_timestamp_manipulation_risk(&self, dep: &TimestampDependency) -> bool {
        matches!(dep.validation_method, ValidationMethod::NoValidation) && dep.max_staleness > 900
    }
}

/// Main detection function for cross-contract data integrity
pub fn detect_cross_contract_data_integrity_attacks(trace: EVMExecutionTrace) -> Vec<SecurityWarning> {
    let mut detector = DataIntegrityDetector::new();
    let vulnerabilities = detector.analyze_data_integrity(trace);

    vulnerabilities.into_iter().map(|vuln| {
        SecurityWarning {
            kind: SecurityWarningKind::DataIntegrityVulnerability,
            severity: vuln.severity,
            pc: 0,
            description: vuln.description,
            operations: vec![],
            remediation: generate_data_integrity_remediation(&vuln.attack_type),
        }
    }).collect()
}

fn generate_data_integrity_remediation(attack_type: &DataIntegrityAttackType) -> String {
    match attack_type {
        DataIntegrityAttackType::StaleDataExploitation => {
            "Implement timestamp validation and maximum staleness limits for cross-contract data.".to_string()
        },
        DataIntegrityAttackType::CachePoisoningAttack => {
            "Add cache access controls and integrity verification with contract-specific namespaces.".to_string()
        },
        DataIntegrityAttackType::StateDesynchronization => {
            "Implement atomic state updates and synchronization locks with consistency checks.".to_string()
        },
        DataIntegrityAttackType::DataRaceCondition => {
            "Use atomic operations and proper locking mechanisms for shared data access.".to_string()
        },
        DataIntegrityAttackType::InconsistentValidation => {
            "Standardize validation rules and use shared validation libraries across contracts.".to_string()
        },
        DataIntegrityAttackType::TimestampManipulation => {
            "Use external time oracles and implement timestamp range validation mechanisms.".to_string()
        },
    }
}
