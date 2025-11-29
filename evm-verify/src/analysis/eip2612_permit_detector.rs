/// EIP-2612 Permit Frontrunning Detector
/// Detects generic permit() frontrunning vulnerabilities beyond Permit2
/// Critical for: All ERC20 tokens with permit(), DeFi integrations

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP2612Vulnerability {
    pub vulnerability_type: EIP2612IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EIP2612IssueType {
    PermitFrontrunning,            // permit() + transferFrom() can be frontrun
    NonceMismatchNoCheck,          // Nonce not checked properly
    DeadlineNotEnforced,           // Deadline check missing
    SignatureReplayWithPermit,     // Signature can be replayed
    PermitWithoutProtection,       // Using permit without frontrun protection
}

pub struct EIP2612PermitDetector {
    bytecode: Vec<u8>,
    permit_selectors: HashSet<[u8; 4]>,
}

impl EIP2612PermitDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut permit_selectors = HashSet::new();
        permit_selectors.insert([0xd5, 0x05, 0xac, 0xcf]); // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
        permit_selectors.insert([0x84, 0x21, 0x04, 0x2e]); // permitTransfer
        
        Self { bytecode, permit_selectors }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EIP2612Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.has_permit() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_permit_frontrunning());
        vulnerabilities.extend(self.detect_deadline_issues());

        vulnerabilities
    }

    fn detect_permit_frontrunning(&self) -> Vec<EIP2612Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: permit() followed closely by transferFrom()
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_permit_call(i) {
                // Check if transferFrom happens soon after
                let has_unsafe_transfer = self.has_transferfrom_nearby(i);
                
                if has_unsafe_transfer {
                    vulnerabilities.push(EIP2612Vulnerability {
                        vulnerability_type: EIP2612IssueType::PermitFrontrunning,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "permit() + transferFrom() pattern vulnerable to frontrunning".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User signs permit for spender A\n\
                            2. Attacker sees permit signature in mempool\n\
                            3. Attacker frontruns with permit call\n\
                            4. Attacker becomes approved spender\n\
                            5. transferFrom() executes with attacker as spender\n\n\
                            Fix: Use Permit2 or atomic permit+action in single tx",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_deadline_issues(&self) -> Vec<EIP2612Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_permit_call(i) {
                // Check for deadline validation (TIMESTAMP comparison)
                if !self.has_deadline_check(i) {
                    vulnerabilities.push(EIP2612Vulnerability {
                        vulnerability_type: EIP2612IssueType::DeadlineNotEnforced,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: "Permit deadline not properly enforced".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User signs permit with deadline in past\n\
                            2. No deadline check allows expired permit\n\
                            3. Old signatures can be replayed indefinitely\n\
                            4. User loses control over approvals\n\n\
                            Fix: require(block.timestamp <= deadline)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_permit(&self) -> bool {
        for selector in &self.permit_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        false
    }

    fn is_permit_call(&self, pos: usize) -> bool {
        if pos + 4 > self.bytecode.len() {
            return false;
        }
        for selector in &self.permit_selectors {
            if &self.bytecode[pos..pos+4] == selector {
                return true;
            }
        }
        false
    }

    fn has_transferfrom_nearby(&self, pos: usize) -> bool {
        let transferfrom = [0x23, 0xb8, 0x72, 0xdd]; // transferFrom selector
        for i in pos..pos.saturating_add(100).min(self.bytecode.len().saturating_sub(4)) {
            if &self.bytecode[i..i+4] == &transferfrom {
                return true;
            }
        }
        false
    }

    fn has_deadline_check(&self, pos: usize) -> bool {
        // Look for TIMESTAMP (0x42) comparison
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }
}
