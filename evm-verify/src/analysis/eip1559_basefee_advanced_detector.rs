/// EIP-1559 Base Fee Advanced Detector
/// Detects post-merge base fee manipulation and priority fee exploits

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP1559Vulnerability {
    pub vulnerability_type: EIP1559IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EIP1559IssueType {
    ValidatorBaseFeeControl,       // Validators can influence base fee
    PriorityFeeFrontrunning,       // Priority fee used for critical logic
    GasAuctionManipulation,        // Gas auction manipulable
    BaseFeeAsRandomness,           // Base fee used as randomness source
}

pub struct EIP1559BaseFeeAdvancedDetector {
    bytecode: Vec<u8>,
}

impl EIP1559BaseFeeAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EIP1559Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: BASEFEE used in critical logic
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x48 { // BASEFEE
                // Check if used for access control or randomness
                if i + 5 < self.bytecode.len() && (self.bytecode[i + 1] == 0x10 || self.bytecode[i + 1] == 0x11) {
                    vulnerabilities.push(EIP1559Vulnerability {
                        vulnerability_type: EIP1559IssueType::ValidatorBaseFeeControl,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: "BASEFEE used in comparison logic - validators have influence".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Contract uses BASEFEE for access control\n\
                            2. Validators can influence BASEFEE via block fullness\n\
                            3. Attacker collaborates with validator\n\
                            4. Manipulates BASEFEE to bypass checks\n\n\
                            Fix: Don't use BASEFEE for security-critical logic",
                            i
                        ),
                        location: i,
                    });
                }

                // Check if used with MOD (randomness)
                if i + 2 < self.bytecode.len() && self.bytecode[i + 1] == 0x06 {
                    vulnerabilities.push(EIP1559Vulnerability {
                        vulnerability_type: EIP1559IssueType::BaseFeeAsRandomness,
                        severity: SecuritySeverity::High,
                        confidence: 0.85,
                        description: "BASEFEE used as randomness source".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Contract uses BASEFEE for random selection\n\
                            2. Validators control BASEFEE via block construction\n\
                            3. Predictable 'randomness' for validators\n\n\
                            Fix: Use Chainlink VRF for randomness",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }
}
