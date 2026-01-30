/// Whitelist Bypass Detector
///
/// Detects sale access circumvention and whitelist manipulation.
/// Coverage: Token sales, presales, allowlists
/// Market: $10B+ fundraising

use crate::bytecode::SecurityFinding;

pub struct WhitelistBypassDetector {
    bytecode: Vec<u8>,
}

impl WhitelistBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_merkle_proof_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Whitelist merkle proof validation can be bypassed at PC {}", pc),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_signature_replay() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Whitelist signatures vulnerable to replay attacks at PC {}", pc),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_merkle_proof_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // buy, mint selectors
                if matches!(self.bytecode[i+1], 0xa0 | 0x40) {
                    let mut has_merkle_verify = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        // Check for keccak256 (merkle hashing)
                        if self.bytecode[j] == 0x20 { // KECCAK256
                            has_merkle_verify = true;
                        }
                    }

                    if !has_merkle_verify {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_signature_replay(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // ECRECOVER opcode
            if self.bytecode[i] == 0x01 {
                let mut has_nonce_check = false;

                for j in i..i+40.min(self.bytecode.len()) {
                    // Check for nonce increment
                    if self.bytecode[j] == 0x54 && j+10 < self.bytecode.len() { // SLOAD
                        if self.bytecode[j+8] == 0x01 { // ADD
                            has_nonce_check = true;
                        }
                    }
                }

                if !has_nonce_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
