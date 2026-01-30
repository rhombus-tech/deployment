/// Oracle Free Option Detector - Exploits oracle lag for free optionality
use crate::bytecode::SecurityFinding;

pub struct OracleFreeOptionDetector {
    bytecode: Vec<u8>,
}

impl OracleFreeOptionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Oracle free option vulnerability at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(55) {
            if self.check_free_option(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_free_option(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for actions that can be reverted based on oracle price
        // Pattern: check oracle -> execute action -> can revert if unfavorable
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // swap/mint/borrow functions
            if matches!(self.bytecode[pos+1], 0x38 | 0x40 | 0xc6 | 0xe8) {
                let mut has_oracle_call = false;
                let mut has_revert_path = false;
                
                if pos + 50 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        // Oracle STATICCALL
                        if self.bytecode[j] == 0xfa { has_oracle_call = true; }
                        
                        // REVERT opcode that could be triggered by price check
                        if has_oracle_call && self.bytecode[j] == 0xfd {
                            // Check if preceded by comparison
                            if j > 5 && matches!(self.bytecode[j-3], 0x10 | 0x11 | 0x14) {
                                has_revert_path = true;
                                break;
                            }
                        }
                    }
                }
                
                // Vulnerable if can check oracle and revert without timestamp/deadline check
                if has_oracle_call && has_revert_path {
                    let mut has_deadline_check = false;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        // TIMESTAMP opcode
                        if self.bytecode[j] == 0x42 && j + 5 < self.bytecode.len() {
                            // Followed by comparison
                            if matches!(self.bytecode[j + 3], 0x10 | 0x11) {
                                has_deadline_check = true;
                                break;
                            }
                        }
                    }
                    return !has_deadline_check;
                }
            }
        }
        false
    }
}
