/// Pendle Yield Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct PendleYieldManipulationDetector {
    bytecode: Vec<u8>,
}

impl PendleYieldManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Pendle yield token manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_yield_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_yield_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for swapExactTokensForPt/swapExactPtForTokens without TWAP oracle
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            let selector_bytes = &self.bytecode[pos+1..pos+4];
            
            // Pendle swap selectors (simplified check)
            if (selector_bytes[0] == 0x1c || selector_bytes[0] == 0x2f) {
                // Check if there's oracle validation
                let mut has_oracle_check = false;
                if pos + 40 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        // Look for STATICCALL to oracle
                        if self.bytecode[j] == 0xfa {
                            has_oracle_check = true;
                            break;
                        }
                    }
                }
                return !has_oracle_check;
            }
        }
        false
    }
}
