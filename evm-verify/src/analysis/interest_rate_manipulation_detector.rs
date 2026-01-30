/// Interest Rate Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct InterestRateManipulationDetector {
    bytecode: Vec<u8>,
}

impl InterestRateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Interest rate manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.check_rate_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_rate_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for interest rate calculation vulnerable to manipulation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getBorrowRate, getSupplyRate, utilizationRate selectors
            if matches!(self.bytecode[pos+1], 0x15 | 0x96 | 0xc3 | 0xf2) {
                let mut uses_spot_utilization = false;
                let mut has_rate_bounds = false;
                
                if pos + 50 < self.bytecode.len() {
                    // Check for utilization calculation (borrowed/total)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 { // DIV for utilization
                            uses_spot_utilization = true;
                            break;
                        }
                    }
                    
                    // Check for rate bounds (min/max checks)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) && j + 8 < self.bytecode.len() {
                            // Check for both upper and lower bound
                            for k in (j+1)..(j+8).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {
                                    has_rate_bounds = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                
                // Vulnerable if uses spot without bounds that can be manipulated
                return uses_spot_utilization && !has_rate_bounds;
            }
        }
        false
    }
}
