/// First Depositor Inflation Detector
use crate::bytecode::SecurityFinding;

pub struct FirstDepositorInflationDetector {
    bytecode: Vec<u8>,
}

impl FirstDepositorInflationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("First depositor share inflation attack at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_share_calculation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_share_calculation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for share calculation pattern: shares = assets * totalSupply / totalAssets
        if self.bytecode[pos] == 0x02 { // MUL
            if pos + 40 < self.bytecode.len() {
                let mut has_div = false;
                let mut has_zero_check = false;
                
                // Look for DIV after MUL
                for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 { // DIV
                        has_div = true;
                        
                        // Check if denominator (totalAssets) is validated against zero
                        for k in pos.saturating_sub(20)..j {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0x15 { // ISZERO
                                has_zero_check = true;
                                break;
                            }
                            if self.bytecode[k] == 0x14 { // EQ with zero check
                                has_zero_check = true;
                                break;
                            }
                        }
                        break;
                    }
                }
                
                // Vulnerable if division without zero/small value check
                if has_div && !has_zero_check {
                    return true;
                }
            }
        }
        
        // Check for deposit() function without minimum share check
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 { // PUSH4
            // deposit selector: 0xb6b55f25 or similar
            if self.bytecode[pos+1] == 0xb6 && self.bytecode[pos+2] == 0xb5 {
                if pos + 50 < self.bytecode.len() {
                    let mut has_minimum_check = false;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        // Check for minimum share requirement
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT
                            if j + 5 < self.bytecode.len() {
                                if matches!(self.bytecode[j + 3], 0xfd | 0x57) {
                                    has_minimum_check = true;
                                    break;
                                }
                            }
                        }
                    }
                    return !has_minimum_check;
                }
            }
        }
        
        false
    }
}
