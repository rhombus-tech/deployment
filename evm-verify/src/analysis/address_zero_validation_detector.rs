/// Address Zero Validation Detector
use crate::bytecode::SecurityFinding;

pub struct AddressZeroValidationDetector {
    bytecode: Vec<u8>,
}

impl AddressZeroValidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Missing address(0) validation at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.check_address_storage(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_address_storage(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for address being stored without zero check
        if self.bytecode[pos] == 0x55 { // SSTORE
            if pos > 20 {
                let mut loads_address = false;
                let mut checks_zero = false;
                
                // Look backwards for address loading
                for j in pos.saturating_sub(20)..pos {
                    // CALLDATALOAD, CALLER, ADDRESS opcodes
                    if matches!(self.bytecode[j], 0x35 | 0x33 | 0x30) {
                        loads_address = true;
                    }
                    // Check for zero comparison (EQ with zero or ISZERO)
                    if self.bytecode[j] == 0x15 { // ISZERO
                        checks_zero = true;
                    }
                    if self.bytecode[j] == 0x14 { // EQ
                        // Check if comparing with zero
                        if j > 0 && self.bytecode[j - 1] == 0x60 { // PUSH1 0
                            if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0x00 {
                                checks_zero = true;
                            }
                        }
                    }
                }
                
                return loads_address && !checks_zero;
            }
        }
        false
    }
}
