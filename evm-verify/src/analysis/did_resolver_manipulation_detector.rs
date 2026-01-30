/// DID Resolver Manipulation Detector
use crate::bytecode::SecurityFinding;
pub struct DidResolverManipulationDetector { bytecode: Vec<u8> }
impl DidResolverManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_resolver_centralization() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("DID resolution uses single resolver, manipulable at PC {}", pc),
                pc, confidence: 0.82
            });
        }
        findings
    }
    fn detect_resolver_centralization(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xa5 | 0xb6) {
                    let mut resolver_calls = 0;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { resolver_calls += 1; }
                    }
                    if resolver_calls < 2 { return Some(i); }
                }
            }
        }
        None
    }
}
