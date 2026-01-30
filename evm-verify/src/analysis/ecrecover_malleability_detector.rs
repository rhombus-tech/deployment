/// Ecrecover Malleability Detector
/// Detects signature verification bypass through signature malleability
/// Vulnerable pattern: Using ecrecover without checking for signature malleability

use crate::bytecode::SecurityFinding;

pub struct EcrecoverMalleabilityDetector {
    bytecode: Vec<u8>,
}

impl EcrecoverMalleabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // Check for ecrecover usage without proper s-value validation
        if let Some(location) = self.has_ecrecover_without_malleability_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Signature malleability vulnerability at PC {}. ecrecover used without checking s-value <= secp256k1n/2, allowing signature forgery",
                    location
                ),
                pc: location,
                confidence: 0.90,
            });
        }

        findings
    }

    fn has_ecrecover_without_malleability_check(&self) -> Option<usize> {
        // Pattern: Look for STATICCALL to ecrecover (address 0x01) without prior s-value check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Check for PUSH1 0x01 (ecrecover precompile address)
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() && self.bytecode[i + 1] == 0x01 {
                // Look ahead for STATICCALL (0xfa) or CALL (0xf1)
                for j in (i + 2)..(i + 30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xfa || self.bytecode[j] == 0xf1 {
                        // Check if there's s-value validation before ecrecover
                        // Valid s must be: 0 < s <= secp256k1n / 2
                        // This is checked by: PUSH32 secp256k1n/2, s-value, GT, ISZERO, PUSH REVERT, JUMPI
                        let has_s_validation = self.has_s_value_check_before(i);
                        
                        if !has_s_validation {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_s_value_check_before(&self, ecrecover_pos: usize) -> bool {
        let start = ecrecover_pos.saturating_sub(100);
        
        // Look for pattern: PUSH32 <secp256k1n/2>, value, GT
        for i in start..ecrecover_pos {
            if i + 33 < self.bytecode.len() && self.bytecode[i] == 0x7f { // PUSH32
                // Check for GT (0x11) or LT (0x10) comparison
                if i + 34 < self.bytecode.len() {
                    let opcode_after = self.bytecode[i + 34];
                    if opcode_after == 0x11 || opcode_after == 0x10 {
                        return true;
                    }
                }
            }
        }
        false
    }
}
