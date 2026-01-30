/// Across Bridge Fee Detector
use crate::bytecode::SecurityFinding;

pub struct AcrossBridgeFeeDetector {
    bytecode: Vec<u8>,
}

impl AcrossBridgeFeeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Across bridge fee manipulation at PC {}", location),
                pc: location, confidence: 0.79,
            });
        }
        findings
    }
    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 && self.bytecode[i+1] == 0x26 {
                let mut has_fee_validation = false;
                if i + 25 < self.bytecode.len() {
                    for j in (i + 5)..(i + 25) {
                        if matches!(self.bytecode[j], 0x10 | 0x11) { has_fee_validation = true; break; }
                    }
                }
                if !has_fee_validation { return Some(i); }
            }
        }
        None
    }
}
