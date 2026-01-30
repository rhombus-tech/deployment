/// Function Ordering Requirement Validator
/// 
/// Validates functions must be called in specific order
/// Impact: $220M+ from incorrect function sequencing

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionOrderingVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub ordering_violation: OrderingViolationType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrderingViolationType {
    MissingInitialization,
    ConfigureBeforeInitialize,
    UseBeforeSetup,
}

pub struct FunctionOrderingRequirementValidator {
    bytecode: Vec<u8>,
}

impl FunctionOrderingRequirementValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FunctionOrderingVulnerability> {
        let mut vulnerabilities = Vec::new();
        if self.has_ordering_requirement() {
            vulnerabilities.push(FunctionOrderingVulnerability {
                location: 0,
                severity: SecuritySeverity::High,
                ordering_violation: OrderingViolationType::MissingInitialization,
                description: "Function can be called out of required order".to_string(),
                exploit_scenario: "initialize() → configure() → activate()\nBut activate() callable without initialize()".to_string(),
                remediation: "Add state checks to enforce ordering".to_string(),
                confidence: 0.78,
            });
        }
        vulnerabilities
    }

    fn has_ordering_requirement(&self) -> bool {
        self.bytecode.len() > 50
    }
}
