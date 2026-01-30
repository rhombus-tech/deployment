use crate::bytecode::SecurityFinding;

pub struct StealthAddressLinkabilityDetector {
    bytecode: Vec<u8>,
}

impl StealthAddressLinkabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_weak_stealth_derivation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Stealth address derivation uses weak randomness or predictable nonce at PC {}. \
                    Addresses can be linked, breaking privacy guarantees.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_missing_view_key_validation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Stealth address generation missing view key validation at PC {}. \
                    Allows creation of unspendable addresses.",
                    pc
                ),
                pc,
                confidence: 0.83,
            });
        }

        if let Some(pc) = self.detect_ephemeral_key_reuse() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Ephemeral key reuse detected in stealth address generation at PC {}. \
                    Completely breaks unlinkability and reveals all related transactions.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        findings
    }

    fn detect_weak_stealth_derivation(&self) -> Option<usize> {
        // Look for stealth address generation patterns using TIMESTAMP or BLOCKHASH for randomness
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Check for stealth address function selector patterns (generate, computeStealthAddress)
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // Common stealth address generation selectors
                if matches!(selector, [0x8f, 0x4f, _, _] | [0xa4, 0x2d, _, _]) {
                    // Check for TIMESTAMP (0x42) or BLOCKHASH (0x40) usage for nonce
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 || self.bytecode[j] == 0x40 {
                            // Look for subsequent KECCAK256 (0x20)
                            for k in j..j.saturating_add(10).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x20 {
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_missing_view_key_validation(&self) -> Option<usize> {
        // Look for stealth address generation without proper EC point validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // generateStealthAddress or similar
                if matches!(selector, [0x8f, 0x4f, _, _] | [0xa4, 0x2d, _, _]) {
                    let mut has_ecrecover = false;
                    let mut has_validation = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for ecrecover precompile (0x01) or EC validation
                        if j + 1 < self.bytecode.len() && self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x01 {
                            has_ecrecover = true;
                        }
                        // Check for validation (ISZERO + REVERT pattern)
                        if j + 2 < self.bytecode.len() && self.bytecode[j] == 0x15 && self.bytecode[j + 1] == 0xfd {
                            has_validation = true;
                        }
                    }
                    
                    if has_ecrecover && !has_validation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_ephemeral_key_reuse(&self) -> Option<usize> {
        // Look for ephemeral key storage (SSTORE) without unique nonce generation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                if matches!(selector, [0x8f, 0x4f, _, _] | [0xa4, 0x2d, _, _]) {
                    let mut has_sstore = false;
                    let mut has_unique_nonce = false;
                    
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE
                            has_sstore = true;
                        }
                        // Look for proper nonce generation (KECCAK256 with multiple inputs)
                        if j + 5 < self.bytecode.len() && self.bytecode[j] == 0x20 { // KECCAK256
                            // Check if multiple values are hashed (CALLER, TIMESTAMP, etc.)
                            let mut input_count = 0;
                            for k in j.saturating_sub(20)..j {
                                if matches!(self.bytecode[k], 0x33 | 0x42 | 0x43 | 0x44) {
                                    input_count += 1;
                                }
                            }
                            if input_count >= 2 {
                                has_unique_nonce = true;
                            }
                        }
                    }
                    
                    if has_sstore && !has_unique_nonce {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
