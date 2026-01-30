/// Curve Reentrancy Detector
use crate::bytecode::SecurityFinding;

pub struct CurveReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CurveReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Curve pool reentrancy vulnerability at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_curve_reentrancy(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_curve_reentrancy(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        if matches!(self.bytecode[pos], 0xf1 | 0xfa) { // CALL, STATICCALL
            if pos + 40 < self.bytecode.len() {
                let mut updates_reserves = false;
                let mut has_reentrancy_guard = false;
                
                for j in (pos + 1)..(pos + 40).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { updates_reserves = true; }
                    // Check for nonReentrant modifier (SLOAD + check pattern)
                    if self.bytecode[j] == 0x54 {
                        if j + 8 < self.bytecode.len() && matches!(self.bytecode[j + 4], 0x14 | 0x15) {
                            has_reentrancy_guard = true;
                        }
                    }
                }
                return updates_reserves && !has_reentrancy_guard;
            }
        }
        false
    }
}
