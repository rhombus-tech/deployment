/// Game Economy Inflation Detector
use crate::bytecode::SecurityFinding;
pub struct GameEconomyInflationDetector { bytecode: Vec<u8> }
impl GameEconomyInflationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(pc) = self.detect_unlimited_minting() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Game token minting lacks supply cap enforcement at PC {}", pc),
                pc, confidence: 0.91
            });
        }
        findings
    }
    fn detect_unlimited_minting(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                if matches!(self.bytecode[i+1], 0x40 | 0x51) { // mint
                    let mut has_supply_check = false;
                    for j in i..i+30.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j+8 < self.bytecode.len() {
                            if self.bytecode[j+6] == 0x10 { has_supply_check = true; }
                        }
                    }
                    if !has_supply_check { return Some(i); }
                }
            }
        }
        None
    }
}
