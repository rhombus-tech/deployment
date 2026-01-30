/// Cross-Chain Finality Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct CrossChainFinalityDetector {
    bytecode: Vec<u8>,
}

impl CrossChainFinalityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Cross-chain finality exploit vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_finality_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_finality_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for cross-chain message processing without finality confirmation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // receiveMessage, processMessage selectors
            if matches!(self.bytecode[pos+1], 0x57 | 0x8c | 0xa4) {
                let mut has_block_confirmation_check = false;
                let mut has_finality_delay = false;
                
                if pos + 45 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        // Check for block number validation (NUMBER opcode + comparison)
                        if self.bytecode[j] == 0x43 { // NUMBER
                            if j + 5 < self.bytecode.len() {
                                // SUB + GT to check confirmations
                                if self.bytecode[j + 2] == 0x03 && matches!(self.bytecode[j + 4], 0x10 | 0x11) {
                                    has_block_confirmation_check = true;
                                }
                            }
                        }
                        
                        // Check for timestamp delay (TIMESTAMP + ADD + GT)
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            if j + 8 < self.bytecode.len() {
                                if self.bytecode[j + 3] == 0x01 && matches!(self.bytecode[j + 6], 0x10 | 0x11) {
                                    has_finality_delay = true;
                                }
                            }
                        }
                    }
                }
                return !has_block_confirmation_check && !has_finality_delay;
            }
        }
        false
    }
}
