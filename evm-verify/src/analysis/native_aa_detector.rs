/// Native Account Abstraction (RIP-7560) Detector
/// Detects vulnerabilities in native AA (alternative to ERC-4337)
/// Critical for: RIP-7560 if adopted (protocol-level AA)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeAAVulnerability {
    pub vulnerability_type: NativeAAIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NativeAAIssueType {
    ProtocolValidationBypass,      // Protocol-level validation exploit
    ConsensusGasSponsorship,       // Gas sponsorship at consensus layer
    ProtocolNonceManipulation,     // Nonce management exploit
    ValidationExecutionGap,        // Gap between validation and execution
    CrossChainAACoordination,      // Cross-chain AA manipulation
}

pub struct NativeAADetector {
    bytecode: Vec<u8>,
}

impl NativeAADetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NativeAAVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.uses_native_aa() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_validation_issues());
        vulnerabilities.extend(self.detect_nonce_issues());

        vulnerabilities
    }

    fn detect_validation_issues(&self) -> Vec<NativeAAVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_validation_function(i) && !self.has_strict_validation(i) {
                vulnerabilities.push(NativeAAVulnerability {
                    vulnerability_type: NativeAAIssueType::ProtocolValidationBypass,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.75,
                    description: "Native AA validation without strict checks".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Account implements native AA validation\n\
                        2. Validation too permissive\n\
                        3. Attacker bypasses protocol-level checks\n\
                        4. Unauthorized transaction execution\n\n\
                        Fix: Implement strict validation per RIP-7560",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_nonce_issues(&self) -> Vec<NativeAAVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.manages_nonce(i) && !self.has_nonce_protection(i) {
                vulnerabilities.push(NativeAAVulnerability {
                    vulnerability_type: NativeAAIssueType::ProtocolNonceManipulation,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    description: "Native AA nonce management without replay protection".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        1. Account manages nonces at protocol level\n\
                        2. Nonce increment not atomic\n\
                        3. Replay or reordering attack\n\
                        4. Duplicate transaction execution\n\n\
                        Fix: Use atomic nonce increment",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn uses_native_aa(&self) -> bool {
        // Heuristic: Look for validation-related patterns
        let validate = [0x9a, 0x15, 0xb7, 0x42]; // validateTransaction (hypothetical)
        self.bytecode.windows(4).any(|w| w == validate)
    }

    fn has_validation_function(&self, pos: usize) -> bool {
        pos + 10 < self.bytecode.len()
    }

    fn has_strict_validation(&self, pos: usize) -> bool {
        // Look for multiple checks (signature, balance, nonce)
        let check_count = self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())]
            .iter()
            .filter(|&&b| b == 0x14 || b == 0x10 || b == 0x11) // EQ, LT, GT
            .count();
        check_count >= 3
    }

    fn manages_nonce(&self, pos: usize) -> bool {
        // SLOAD + ADD + SSTORE (nonce increment)
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x54 && // SLOAD
        self.bytecode[pos+5] == 0x01 // ADD
    }

    fn has_nonce_protection(&self, pos: usize) -> bool {
        // Check if nonce verification happens before increment
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x14 { // EQ
                return true;
            }
        }
        false
    }
}
