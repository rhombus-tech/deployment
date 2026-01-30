/// Priority Gas Auction Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct PriorityGasAuctionDetector {
    bytecode: Vec<u8>,
}

impl PriorityGasAuctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Priority gas auction vulnerability at PC {}", location),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_gas_auction(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_gas_auction(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for priority actions without gas price validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // mint, claim, execute priority functions
            if matches!(self.bytecode[pos+1], 0x40 | 0x4e | 0xa9) {
                let mut has_gas_check = false;
                
                if pos + 35 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        // GASPRICE opcode check
                        if self.bytecode[j] == 0x3a && j + 5 < self.bytecode.len() {
                            // Followed by comparison
                            if matches!(self.bytecode[j + 3], 0x10 | 0x11) {
                                has_gas_check = true;
                                break;
                            }
                        }
                    }
                }
                return !has_gas_check;
            }
        }
        false
    }
}
