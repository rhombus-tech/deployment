/// NFT Ownership Validation Detector
use crate::bytecode::SecurityFinding;

pub struct NftOwnershipValidationDetector {
    bytecode: Vec<u8>,
}

impl NftOwnershipValidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("NFT ownership validation bypass at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_ownership_validation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_ownership_validation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for ownerOf() or balanceOf() selector: 0x6352211e, 0x70a08231
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 { // PUSH4
            let is_ownerof = self.bytecode[pos+1] == 0x63 && self.bytecode[pos+2] == 0x52 && 
                           self.bytecode[pos+3] == 0x21 && self.bytecode[pos+4] == 0x1e;
            let is_balanceof = self.bytecode[pos+1] == 0x70 && self.bytecode[pos+2] == 0xa0 && 
                             self.bytecode[pos+3] == 0x82 && self.bytecode[pos+4] == 0x31;
            
            if is_ownerof || is_balanceof {
                // Check if return value is validated
                if pos + 30 < self.bytecode.len() {
                    let mut has_validation = false;
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        // Look for CALLER comparison or other ownership checks
                        if self.bytecode[j] == 0x33 { // CALLER
                            if j + 5 < self.bytecode.len() {
                                if self.bytecode[j + 3] == 0x14 { // EQ
                                    has_validation = true;
                                    break;
                                }
                            }
                        }
                        // Check for REVERT on failure
                        if matches!(self.bytecode[j], 0xfd | 0x57) {
                            has_validation = true;
                            break;
                        }
                    }
                    return !has_validation;
                }
            }
        }
        false
    }
}
