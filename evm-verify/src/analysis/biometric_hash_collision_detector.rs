/// Biometric Hash Collision Detector
use crate::bytecode::SecurityFinding;
pub struct BiometricHashCollisionDetector { bytecode: Vec<u8> }
impl BiometricHashCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_weak_hash() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Biometric hash uses weak algorithm at PC {}", pc),
                pc, confidence: 0.83
            });
        }
        findings
    }
    fn detect_weak_hash(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xe9 | 0xfa) {
                    let mut has_strong_hash = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { has_strong_hash = true; }
                    }
                    if !has_strong_hash { return Some(i); }
                }
            }
        }
        None
    }
}
