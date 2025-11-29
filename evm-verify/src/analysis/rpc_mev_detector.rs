/// RPC-Level MEV Attack Detector
/// Detects vulnerabilities to RPC endpoint manipulation
/// Critical for: Infrastructure-level MEV protection

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RPCMEVVulnerability {
    pub vulnerability_type: RPCMEVIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RPCMEVIssueType {
    RPCFrontrunningVulnerability,  // RPC endpoint frontrunning
    PrivateRPCMEVVector,           // Private RPC as MEV attack
    RPCRevertInjection,            // Revert transaction injection
    RPCTimestampManipulation,      // RPC timestamp manipulation
    MempoolPrivacyBypass,          // Mempool privacy circumvention
}

pub struct RPCMEVDetector {
    bytecode: Vec<u8>,
}

impl RPCMEVDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RPCMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_rpc_exposure());
        vulnerabilities.extend(self.detect_timestamp_reliance());

        vulnerabilities
    }

    fn detect_rpc_exposure(&self) -> Vec<RPCMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_value_transaction(i) && !self.has_mev_protection(i) {
                vulnerabilities.push(RPCMEVVulnerability {
                    vulnerability_type: RPCMEVIssueType::RPCFrontrunningVulnerability,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    description: "High-value transaction without RPC-level MEV protection".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. User sends transaction via public RPC\n\
                        2. RPC provider sees transaction first\n\
                        3. RPC provider frontruns transaction\n\
                        4. User receives worse execution\n\n\
                        Fix: Use private RPC or commit-reveal pattern",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_timestamp_reliance(&self) -> Vec<RPCMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.relies_on_timestamp(i) {
                vulnerabilities.push(RPCMEVVulnerability {
                    vulnerability_type: RPCMEVIssueType::RPCTimestampManipulation,
                    severity: SecuritySeverity::Low,
                    confidence: 0.60,
                    description: "Critical logic depends on block.timestamp (RPC manipulable)".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Contract logic depends on block.timestamp\n\
                        2. RPC can influence transaction inclusion timing\n\
                        3. RPC delays transaction to favorable timestamp\n\
                        4. Timing-based exploit via RPC control\n\n\
                        Fix: Use block.number or reduce timestamp sensitivity",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn has_value_transaction(&self, pos: usize) -> bool {
        pos + 5 < self.bytecode.len() && self.bytecode[pos] == 0xF1 // CALL with value
    }

    fn has_mev_protection(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x20 { // KECCAK256 (commit-reveal)
                return true;
            }
        }
        false
    }

    fn relies_on_timestamp(&self, pos: usize) -> bool {
        pos < self.bytecode.len() && self.bytecode[pos] == 0x42 && // TIMESTAMP
        pos + 10 < self.bytecode.len() && self.bytecode[pos+5] == 0x57 // JUMPI (conditional)
    }
}
