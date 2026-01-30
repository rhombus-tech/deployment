/// Loss-Versus-Rebalancing (LVR) Extraction Detector
use crate::bytecode::SecurityFinding;

pub struct LvrExtractionDetector {
    bytecode: Vec<u8>,
}

impl LvrExtractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("LVR extraction vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_lvr_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_lvr_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for AMM swaps without price impact protection
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // swap, swapExactTokensForTokens selectors
            if matches!(self.bytecode[pos+1], 0x38 | 0xfb | 0x18) {
                let mut has_slippage_check = false;
                let mut has_price_oracle = false;
                
                if pos + 55 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        // Check for minimum output amount (slippage protection)
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // GT/LT
                            if j + 3 < self.bytecode.len() && matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_slippage_check = true;
                            }
                        }
                        
                        // Check for external price oracle call
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            has_price_oracle = true;
                        }
                    }
                }
                
                // Vulnerable if no slippage check OR no oracle price validation
                return !has_slippage_check || !has_price_oracle;
            }
        }
        false
    }
}
