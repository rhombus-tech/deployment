/// Uniswap V3 Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct UniswapV3ManipulationDetector {
    bytecode: Vec<u8>,
}

impl UniswapV3ManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Uniswap V3 price manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_pool_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_pool_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for slot0 reads without TWAP oracle validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            if self.bytecode[pos+1] == 0x38 && self.bytecode[pos+2] == 0x50 { // slot0 selector
                if pos + 50 < self.bytecode.len() {
                    let mut has_twap_check = false;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            // observe selector: 0x883bdbfd
                            if self.bytecode[j+1] == 0x88 && self.bytecode[j+2] == 0x3b {
                                has_twap_check = true;
                                break;
                            }
                        }
                    }
                    return !has_twap_check;
                }
            }
        }
        false
    }
}
