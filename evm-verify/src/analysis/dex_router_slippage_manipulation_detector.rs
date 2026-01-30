/// DEX Router Slippage Manipulation Detector
use crate::bytecode::SecurityFinding;
pub struct DexRouterSlippageManipulationDetector { bytecode: Vec<u8> }
impl DexRouterSlippageManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_missing_slippage_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Swap lacks minimum output amount check at PC {}", pc),
                pc, confidence: 0.89
            });
        }
        findings
    }
    fn detect_missing_slippage_check(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x38 | 0x49) {
                    let mut has_min_check = false;
                    for j in i..i+25.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 { has_min_check = true; }
                    }
                    if !has_min_check { return Some(i); }
                }
            }
        }
        None
    }
}
