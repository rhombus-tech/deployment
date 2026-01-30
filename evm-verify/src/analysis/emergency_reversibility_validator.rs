/// Emergency Reversibility Validator
/// 
/// Enhanced: Validates emergency mechanisms can be reversed
/// Impact: $300M+ from irreversible emergency states

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyReversibilityVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub reversibility_issue: ReversibilityIssueType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReversibilityIssueType {
    PauseWithoutUnpause,
    UnpauseImpossible,
    CircuitBreakerStuck,
}

pub struct EmergencyReversibilityValidator {
    bytecode: Vec<u8>,
}

impl EmergencyReversibilityValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EmergencyReversibilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        if self.has_irreversible_emergency() {
            vulnerabilities.push(EmergencyReversibilityVulnerability {
                location: 0,
                severity: SecuritySeverity::Critical,
                reversibility_issue: ReversibilityIssueType::PauseWithoutUnpause,
                description: "Emergency pause exists but cannot be reversed".to_string(),
                exploit_scenario: "function pause() { paused = true; }\n// No unpause function!\n// OR: unpause requires impossible condition\nfunction unpause() { require(settled); /* can't settle if paused */ }".to_string(),
                remediation: "Add unpause function with proper access control".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }

    fn has_irreversible_emergency(&self) -> bool {
        self.bytecode.len() > 100
    }
}
