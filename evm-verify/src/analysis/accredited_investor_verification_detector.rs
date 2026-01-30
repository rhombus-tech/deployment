/// Accredited Investor Verification Detector
use crate::bytecode::SecurityFinding;
pub struct AccreditedInvestorVerificationDetector { bytecode: Vec<u8> }
impl AccreditedInvestorVerificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_accreditation_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Investment limit enforcement missing accreditation check at PC {}", pc),
                pc, confidence: 0.91
            });
        }
        findings
    }
    fn detect_accreditation_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xd0 | 0xe1) {
                    let mut has_accreditation_check = false;
                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa && j+5 < self.bytecode.len() {
                            if self.bytecode[j+4] == 0x15 { has_accreditation_check = true; }
                        }
                    }
                    if !has_accreditation_check { return Some(i); }
                }
            }
        }
        None
    }
}
