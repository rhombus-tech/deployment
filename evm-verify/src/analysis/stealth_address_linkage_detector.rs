/// Stealth Address Linkage Detector
use crate::bytecode::SecurityFinding;
pub struct StealthAddressLinkageDetector { bytecode: Vec<u8> }
impl StealthAddressLinkageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_weak_ephemeral_key() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Stealth address uses weak randomness, linkable at PC {}", pc),
                pc, confidence: 0.84
            });
        }
        findings
    }
    fn detect_weak_ephemeral_key(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x5c | 0x6d) {
                    let mut has_random = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x44 { has_random = true; }
                    }
                    if !has_random { return Some(i); }
                }
            }
        }
        None
    }
}
