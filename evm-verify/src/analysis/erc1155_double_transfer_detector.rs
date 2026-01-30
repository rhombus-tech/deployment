/// ERC1155 Double Transfer Detector
use crate::bytecode::SecurityFinding;

pub struct Erc1155DoubleTransferDetector {
    bytecode: Vec<u8>,
}

impl Erc1155DoubleTransferDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("ERC1155 double transfer vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_double_transfer(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_double_transfer(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // safeTransferFrom: 0xf242432a, safeBatchTransferFrom: 0x2eb2c2d6
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if (self.bytecode[pos+1] == 0xf2 && self.bytecode[pos+2] == 0x42) ||
               (self.bytecode[pos+1] == 0x2e && self.bytecode[pos+2] == 0xb2) {
                if pos + 50 < self.bytecode.len() {
                    let mut transfer_count = 0;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE
                            transfer_count += 1;
                        }
                    }
                    return transfer_count > 2; // Multiple balance updates suggest double transfer
                }
            }
        }
        false
    }
}
