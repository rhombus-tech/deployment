/// Cross-Chain Message Forgery Detector
use crate::bytecode::SecurityFinding;

pub struct CrossChainMessageForgeDetector {
    bytecode: Vec<u8>,
}

impl CrossChainMessageForgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Cross-chain message forgery vulnerability at PC {}", location),
                pc: location,
                confidence: 0.90,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.check_message_forge(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_message_forge(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for message processing without cryptographic signature verification
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // executeMessage, processPayload selectors
            if matches!(self.bytecode[pos+1], 0x41 | 0x8c | 0xb4) {
                let mut has_signature_check = false;
                let mut has_nonce_check = false;
                
                if pos + 50 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        // Look for ECRECOVER (0x01) via STATICCALL
                        if self.bytecode[j] == 0xfa && j > 5 {
                            if self.bytecode[j-3] == 0x60 && self.bytecode[j-2] == 0x01 {
                                has_signature_check = true;
                            }
                        }
                        
                        // Look for nonce increment (SSTORE after SLOAD + ADD)
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() {
                            if self.bytecode[j + 3] == 0x01 && self.bytecode[j + 6] == 0x55 {
                                has_nonce_check = true;
                            }
                        }
                    }
                }
                return !has_signature_check || !has_nonce_check;
            }
        }
        false
    }
}
