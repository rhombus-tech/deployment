/// ERC-6909 Multi-Token Detector
/// Detects vulnerabilities in new ERC-6909 minimal multi-token standard

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERC6909Vulnerability {
    pub vulnerability_type: ERC6909IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC6909IssueType {
    TransferWithoutApproval,       // Transfer in same block without approval check
    OperatorBypassVulnerability,   // Operator permissions bypassable
    BatchOperationAtomicity,       // Batch operations not atomic
    InconsistentBalanceUpdates,    // Balance updates inconsistent
}

pub struct ERC6909Detector {
    bytecode: Vec<u8>,
}

impl ERC6909Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ERC6909Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_erc6909() {
            return vulnerabilities;
        }

        // Pattern: transfer without checking operator/approval
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let transfer_selector = [0x46, 0x95, 0xf1, 0xea]; // transfer
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &transfer_selector {
                if !self.has_approval_check(i) {
                    vulnerabilities.push(ERC6909Vulnerability {
                        vulnerability_type: ERC6909IssueType::TransferWithoutApproval,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "ERC-6909 transfer without operator approval check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker calls transfer on behalf of victim\n\
                            2. No operator check performed\n\
                            3. Tokens transferred without permission\n\n\
                            Fix: Check isOperator[owner][msg.sender]",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_erc6909(&self) -> bool {
        let transfer = [0x46, 0x95, 0xf1, 0xea];
        self.bytecode.windows(4).any(|w| w == transfer)
    }

    fn has_approval_check(&self, pos: usize) -> bool {
        // Look for SLOAD (checking isOperator mapping)
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD
                return true;
            }
        }
        false
    }
}
