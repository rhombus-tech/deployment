/// Virtual Land Ownership Dispute Detector
use crate::bytecode::SecurityFinding;
pub struct VirtualLandOwnershipDisputeDetector { bytecode: Vec<u8> }
impl VirtualLandOwnershipDisputeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_overlapping_claims() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Land coordinate claims lack collision detection at PC {}", pc),
                pc, confidence: 0.90
            });
        }
        findings
    }
    fn detect_overlapping_claims(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xd4 | 0xe5) { // claimLand
                    let mut has_bounds_check = false;
                    for j in i..i+35.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j+10 < self.bytecode.len() {
                            if self.bytecode[j+8] == 0x15 { has_bounds_check = true; }
                        }
                    }
                    if !has_bounds_check { return Some(i); }
                }
            }
        }
        None
    }
}
