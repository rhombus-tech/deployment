/// zkSync Era System Contract Detector
use crate::bytecode::SecurityFinding;

pub struct ZksyncEraSystemContractDetector {
    bytecode: Vec<u8>,
}

impl ZksyncEraSystemContractDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("zkSync Era system contract bypass at PC {}", location),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_system_contract_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_system_contract_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for DELEGATECALL to system contracts without validation
        if self.bytecode[pos] == 0xf4 && pos + 30 < self.bytecode.len() {
            // Check if address is loaded and validated
            let mut has_address_validation = false;
            for j in pos.saturating_sub(15)..pos {
                // Look for address comparison (EQ with known system contract address)
                if self.bytecode[j] == 0x14 && j + 5 < self.bytecode.len() {
                    if matches!(self.bytecode[j + 3], 0x57 | 0xfd) {
                        has_address_validation = true;
                        break;
                    }
                }
            }
            return !has_address_validation;
        }
        false
    }
}
