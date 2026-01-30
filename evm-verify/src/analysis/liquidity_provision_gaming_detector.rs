/// Liquidity Provision Gaming Detector
use crate::bytecode::SecurityFinding;
pub struct LiquidityProvisionGamingDetector { bytecode: Vec<u8> }
impl LiquidityProvisionGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_liquidity_timing_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Liquidity provision/removal lacks time lock, gaming possible at PC {}", pc),
                pc, confidence: 0.83
            });
        }
        findings
    }
    fn detect_liquidity_timing_exploit(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0xca | 0xdb) {
                    let mut has_delay = false;
                    for j in i..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { has_delay = true; }
                    }
                    if !has_delay { return Some(i); }
                }
            }
        }
        None
    }
}
