/// ERC-6551 Token Bound Account Reentrancy Detector
use crate::bytecode::SecurityFinding;

pub struct Erc6551ReentrancyDetector {
    bytecode: Vec<u8>,
}

impl Erc6551ReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("ERC-6551 reentrancy vulnerability at PC {}", location),
                pc: location,
                confidence: 0.92,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_erc6551_reentrancy(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_erc6551_reentrancy(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for ERC-6551 execute without reentrancy protection
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // execute, executeCall selectors for ERC-6551
            if matches!(self.bytecode[pos+1], 0x51 | 0xb6 | 0xc5) {
                let mut has_external_call = false;
                let mut has_reentrancy_guard = false;
                let mut has_state_change_after_call = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for reentrancy guard at function start
                    for j in (pos + 5)..(pos + 20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 2] == 0x15 && matches!(self.bytecode[j + 4], 0x57 | 0xfd) {
                                has_reentrancy_guard = true;
                            }
                        }
                    }
                    
                    // Check for external call (CALL/DELEGATECALL)
                    let mut call_pos = None;
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if matches!(self.bytecode[j], 0xf1 | 0xf4) { // CALL/DELEGATECALL
                            has_external_call = true;
                            call_pos = Some(j);
                            break;
                        }
                    }
                    
                    // Check if state changes happen after external call
                    if let Some(call) = call_pos {
                        for j in (call + 1)..(call + 15).min(self.bytecode.len()) {
                            if self.bytecode[j] == 0x55 { // SSTORE after CALL
                                has_state_change_after_call = true;
                                break;
                            }
                        }
                    }
                }
                
                // Vulnerable if makes external calls without guard or has state changes after
                return has_external_call && (!has_reentrancy_guard || has_state_change_after_call);
            }
        }
        false
    }
}
