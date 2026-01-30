/// KyberSwap 2023 Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct Kyberswap2023Detector {
    bytecode: Vec<u8>,
}

impl Kyberswap2023Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("KyberSwap-style tick manipulation at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_tick_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_tick_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for tick updates without proper validation
        if self.bytecode[pos] == 0x55 { // SSTORE
            if pos > 30 {
                let mut updates_tick = false;
                let mut validates_bounds = false;
                
                for j in pos.saturating_sub(30)..pos {
                    if j >= self.bytecode.len() { break; }
                    // Check for tick-related arithmetic
                    if matches!(self.bytecode[j], 0x01 | 0x03) { // ADD, SUB
                        updates_tick = true;
                    }
                }
                
                // Check for bounds validation
                for j in pos.saturating_sub(20)..pos {
                    if j >= self.bytecode.len() { break; }
                    if matches!(self.bytecode[j], 0x10 | 0x11) {
                        validates_bounds = true;
                        break;
                    }
                }
                
                return updates_tick && !validates_bounds;
            }
        }
        false
    }
}
