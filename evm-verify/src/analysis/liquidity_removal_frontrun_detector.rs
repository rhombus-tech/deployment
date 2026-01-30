/// Liquidity Removal Frontrunning Detector
use crate::bytecode::SecurityFinding;

pub struct LiquidityRemovalFrontrunDetector {
    bytecode: Vec<u8>,
}

impl LiquidityRemovalFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Liquidity removal frontrunning vulnerability at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_liquidity_frontrun(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_liquidity_frontrun(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for removeLiquidity without timelock or withdrawal delay
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // removeLiquidity, removeLiquidityETH selectors
            if matches!(self.bytecode[pos+1], 0xba | 0x02 | 0x27) {
                let mut has_timelock = false;
                let mut has_withdrawal_delay = false;
                
                if pos + 45 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        // Check for timestamp-based delay
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() {
                            if self.bytecode[j + 2] == 0x01 && matches!(self.bytecode[j + 4], 0x10 | 0x11) {
                                has_withdrawal_delay = true;
                            }
                        }
                        
                        // Check for withdrawal request mapping (SLOAD check)
                        if self.bytecode[j] == 0x54 && j + 4 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 2] == 0x15 { // ISZERO check
                                has_timelock = true;
                            }
                        }
                    }
                }
                
                return !has_timelock && !has_withdrawal_delay;
            }
        }
        false
    }
}
