/// Cyclic Arbitrage Extraction Detector
use crate::bytecode::SecurityFinding;

pub struct CyclicArbitrageDetector {
    bytecode: Vec<u8>,
}

impl CyclicArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Cyclic arbitrage vulnerability at PC {}", location),
                pc: location,
                confidence: 0.80,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_cyclic_arbitrage(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_cyclic_arbitrage(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Detect multiple consecutive external calls (multi-hop swap)
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if matches!(self.bytecode[pos+1], 0x38 | 0xfb) {
                let mut call_count = 0;
                let mut has_profit_check = false;
                
                if pos + 65 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        // Count CALL opcodes (external swaps)
                        if matches!(self.bytecode[j], 0xf1 | 0xfa) {
                            call_count += 1;
                        }
                        // Check for profit verification (final balance > initial)
                        if self.bytecode[j] == 0x10 && call_count >= 2 {
                            has_profit_check = true;
                        }
                    }
                }
                // Vulnerable if multi-hop without profit check
                return call_count >= 3 && !has_profit_check;
            }
        }
        false
    }
}
