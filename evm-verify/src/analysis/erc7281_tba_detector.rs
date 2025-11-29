/// ERC-7281 Token Bound Accounts Detector  
/// Detects vulnerabilities in NFT-owned account patterns

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TBAVulnerability {
    pub vulnerability_type: TBAIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TBAIssueType {
    CircularOwnership,             // NFT owns account owns NFT
    AccessControlBypassViaTransfer, // Access control bypassed by NFT transfer
    ExecutionDelegationVulnerability, // Delegation can be exploited
    UnauthorizedExecute,           // Execute without proper authorization
}

pub struct ERC7281TBADetector {
    bytecode: Vec<u8>,
}

impl ERC7281TBADetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TBAVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_tba_contract() {
            return vulnerabilities;
        }

        // Pattern: execute() without ownerOf check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let execute_selector = [0x61, 0x46, 0x1c, 0xd4]; // execute
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &execute_selector {
                if !self.has_ownership_check(i) {
                    vulnerabilities.push(TBAVulnerability {
                        vulnerability_type: TBAIssueType::UnauthorizedExecute,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: "TBA execute() without NFT ownership validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker calls execute() on token bound account\n\
                            2. No check that msg.sender owns controlling NFT\n\
                            3. Attacker drains account funds\n\n\
                            Fix: require(ownerOf(tokenId) == msg.sender)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_tba_contract(&self) -> bool {
        let execute = [0x61, 0x46, 0x1c, 0xd4];
        self.bytecode.windows(4).any(|w| w == execute)
    }

    fn has_ownership_check(&self, pos: usize) -> bool {
        // Look for STATICCALL to NFT contract ownerOf
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFA { // STATICCALL
                return true;
            }
        }
        false
    }
}
