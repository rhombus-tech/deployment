/// Slippage Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct SlippageManipulationDetector {
    bytecode: Vec<u8>,
}

impl SlippageManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Slippage manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_slippage_protection(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_slippage_protection(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for swap functions
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 { // PUSH4
            // swapExactTokensForTokens: 0x38ed1739
            // swapTokensForExactTokens: 0x8803dbee
            let is_swap = (self.bytecode[pos+1] == 0x38 && self.bytecode[pos+2] == 0xed) ||
                         (self.bytecode[pos+1] == 0x88 && self.bytecode[pos+2] == 0x03);
            
            if is_swap {
                // Check for amountOutMin parameter validation
                if pos + 45 < self.bytecode.len() {
                    let mut has_min_output_check = false;
                    let mut has_comparison = false;
                    
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        // Look for LT or GT comparison (slippage check)
                        if matches!(self.bytecode[j], 0x10 | 0x11) { // LT, GT
                            has_comparison = true;
                            // Check if followed by REVERT on failure
                            if j + 4 < self.bytecode.len() {
                                if matches!(self.bytecode[j + 3], 0xfd | 0x57) {
                                    has_min_output_check = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    // Vulnerable if no proper slippage protection
                    if !has_min_output_check && !has_comparison {
                        return true;
                    }
                }
            }
        }
        
        // Check for direct price manipulation without slippage bounds
        if self.bytecode[pos] == 0x04 { // DIV (price calculation)
            if pos + 30 < self.bytecode.len() {
                let mut has_slippage_bound = false;
                
                for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                    // Look for bounds checking
                    if matches!(self.bytecode[j], 0x10 | 0x11) {
                        has_slippage_bound = true;
                        break;
                    }
                }
                
                // Check if result is used in transfer without validation
                if !has_slippage_bound {
                    for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0xf1 | 0xa9) { // CALL or LOG (transfer)
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
}
