/// Flash Loan Arbitrage Detector
use crate::bytecode::SecurityFinding;

pub struct FlashLoanArbitrageDetector {
    bytecode: Vec<u8>,
}

impl FlashLoanArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Flash loan arbitrage vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.check_flash_arbitrage(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_flash_arbitrage(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for flashLoan pattern followed by multiple swaps
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if self.bytecode[pos+1] == 0x5c && self.bytecode[pos+2] == 0xc8 { // flashLoan selector
                if pos + 70 < self.bytecode.len() {
                    let mut swap_count = 0;
                    for j in (pos + 5)..(pos + 70).min(self.bytecode.len()) {
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            // Check for swap selectors
                            if (self.bytecode[j+1] == 0x38 && self.bytecode[j+2] == 0xed) ||
                               (self.bytecode[j+1] == 0x88 && self.bytecode[j+2] == 0x03) {
                                swap_count += 1;
                            }
                        }
                    }
                    return swap_count >= 2; // Multiple swaps indicate arbitrage
                }
            }
        }
        false
    }
}
