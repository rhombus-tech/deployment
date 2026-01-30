/// Missing Zero Address Check Detector
/// Detects transfers/assignments without zero address validation
/// Vulnerable pattern: Allows burning funds by sending to address(0)

use crate::bytecode::SecurityFinding;

pub struct MissingZeroAddressCheckDetector {
    bytecode: Vec<u8>,
}

impl MissingZeroAddressCheckDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_missing_zero_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Missing zero address check at PC {}. Transfer to address(0) burns funds permanently",
                    location
                ),
                pc: location,
                confidence: 0.86,
            });
        }

        findings
    }

    fn has_missing_zero_check(&self) -> Option<usize> {
        // Look for transfer/transferFrom patterns
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1], self.bytecode[i + 2],
                    self.bytecode[i + 3], self.bytecode[i + 4],
                ]);
                
                // transfer: 0xa9059cbb, transferFrom: 0x23b872dd, transferOwnership: 0xf2fde38b
                if selector == 0xa9059cbb || selector == 0x23b872dd || selector == 0xf2fde38b {
                    // Check if there's zero address validation
                    if !self.has_zero_address_check_after(i) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_zero_address_check_after(&self, pos: usize) -> bool {
        let end = (pos + 100).min(self.bytecode.len());
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            // Pattern: CALLDATALOAD (address), ISZERO, conditional REVERT
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                for j in (i + 1)..(i + 10).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x15 { // ISZERO
                        for k in (j + 1)..(j + 5).min(self.bytecode.len()) {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0xfd || self.bytecode[k] == 0x57 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}
