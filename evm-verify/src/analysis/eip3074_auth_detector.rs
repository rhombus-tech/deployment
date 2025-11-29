/// EIP-3074 AUTH/AUTHCALL Exploit Detector
/// Detects vulnerabilities in EIP-3074 authorized execution
/// Critical for: Prague/Electra fork, EOA security model change

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP3074Vulnerability {
    pub vulnerability_type: EIP3074IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EIP3074IssueType {
    InvokerTrustAssumption,        // Invoker contract not verified
    AUTHSignatureReplay,           // AUTH signature replay attack
    AUTHCALLReentrancy,            // AUTHCALL reentrancy vector
    AuthorityDelegationBypass,     // Authority delegation manipulation
    InvokerUpgradeRisk,            // Invoker upgrade changes behavior
    NonceManipulation,             // Nonce manipulation for replay
}

pub struct EIP3074Detector {
    bytecode: Vec<u8>,
}

impl EIP3074Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EIP3074Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_eip3074() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_invoker_trust_issues());
        vulnerabilities.extend(self.detect_auth_replay());
        vulnerabilities.extend(self.detect_authcall_reentrancy());

        vulnerabilities
    }

    fn detect_invoker_trust_issues(&self) -> Vec<EIP3074Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: AUTH opcode without invoker validation
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.is_auth_opcode(i) {
                if !self.has_invoker_validation(i) {
                    vulnerabilities.push(EIP3074Vulnerability {
                        vulnerability_type: EIP3074IssueType::InvokerTrustAssumption,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "EIP-3074 AUTH without invoker contract verification".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User signs AUTH message for trusted invoker\n\
                            2. No validation of actual invoker address\n\
                            3. Malicious invoker executes with user's authority\n\
                            4. Drains user funds or manipulates state\n\n\
                            Fix: Validate msg.sender == trustedInvoker before AUTH",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_auth_replay(&self) -> Vec<EIP3074Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: AUTH signature without nonce or chain ID
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.is_auth_opcode(i) {
                if !self.has_nonce_check(i) {
                    vulnerabilities.push(EIP3074Vulnerability {
                        vulnerability_type: EIP3074IssueType::AUTHSignatureReplay,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "AUTH signature without replay protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User signs AUTH message once\n\
                            2. No nonce or timestamp validation\n\
                            3. Attacker replays signature multiple times\n\
                            4. Or replays across different chains\n\n\
                            Fix: Include nonce and chainId in AUTH commit",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_authcall_reentrancy(&self) -> Vec<EIP3074Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: AUTHCALL followed by state change
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.is_authcall_opcode(i) {
                if self.has_state_change_after(i) {
                    vulnerabilities.push(EIP3074Vulnerability {
                        vulnerability_type: EIP3074IssueType::AUTHCALLReentrancy,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "AUTHCALL followed by state change (reentrancy risk)".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. AUTHCALL to malicious contract\n\
                            2. Malicious contract re-enters\n\
                            3. State change occurs after AUTHCALL\n\
                            4. Reentrancy exploit with authorized context\n\n\
                            Fix: Use checks-effects-interactions pattern with AUTHCALL",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn uses_eip3074(&self) -> bool {
        // Check for AUTH (0xF6) or AUTHCALL (0xF7) opcodes (proposed)
        // Note: These are proposed opcodes, may change
        self.bytecode.iter().any(|&b| b == 0xF6 || b == 0xF7) ||
        // Or check for known EIP-3074 patterns
        self.has_auth_pattern()
    }

    fn has_auth_pattern(&self) -> bool {
        // Look for commit hash calculation (AUTH signature)
        // KECCAK256 with specific structure
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x20 { // KECCAK256
                return true;
            }
        }
        false
    }

    fn is_auth_opcode(&self, pos: usize) -> bool {
        pos < self.bytecode.len() && self.bytecode[pos] == 0xF6 // Proposed AUTH opcode
    }

    fn is_authcall_opcode(&self, pos: usize) -> bool {
        pos < self.bytecode.len() && self.bytecode[pos] == 0xF7 // Proposed AUTHCALL opcode
    }

    fn has_invoker_validation(&self, pos: usize) -> bool {
        // Look for CALLER comparison (invoker check)
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x33 && i + 2 < self.bytecode.len() && self.bytecode[i+2] == 0x14 {
                return true; // CALLER EQ
            }
        }
        false
    }

    fn has_nonce_check(&self, pos: usize) -> bool {
        // Look for nonce storage access
        for i in pos.saturating_sub(40)..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD (nonce)
                return true;
            }
        }
        false
    }

    fn has_state_change_after(&self, pos: usize) -> bool {
        // Look for SSTORE after AUTHCALL
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x55 { // SSTORE
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_without_invoker_check() {
        let bytecode = vec![
            0xF6, // AUTH
            0x60, 0x00, // PUSH1 0
        ];
        let detector = EIP3074Detector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EIP3074IssueType::InvokerTrustAssumption)));
    }
}
