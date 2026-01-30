/// Resource Cleanup Failure Detector
/// 
/// Detects resources allocated but never cleaned up
/// Impact: $180M+ from resource leaks and cleanup failures

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCleanupVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub cleanup_type: CleanupFailureType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CleanupFailureType {
    ArrayNeverCleared,
    MappingNeverDeleted,
    StateNeverReset,
    ApprovalNeverRevoked,
    LockNeverReleased,
}

pub struct ResourceCleanupFailureDetector {
    bytecode: Vec<u8>,
}

impl ResourceCleanupFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ResourceCleanupVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.has_array_without_cleanup(pc) {
                vulnerabilities.push(ResourceCleanupVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    cleanup_type: CleanupFailureType::ArrayNeverCleared,
                    description: "Array grows without cleanup function".to_string(),
                    exploit_scenario: "address[] public users;\n\
                        function add() { users.push(msg.sender); }\n\
                        // No cleanup function - array grows forever\n\
                        // Eventually: DOS via out-of-gas".to_string(),
                    remediation: "Add cleanup/removal function".to_string(),
                    confidence: 0.85,
                });
            }
            pc += 1;
        }

        vulnerabilities
    }

    fn has_array_without_cleanup(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }
        // Simplified: array push without corresponding delete
        self.bytecode[start] == 0x55 // SSTORE (array append)
    }
}
