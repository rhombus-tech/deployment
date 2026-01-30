/// ERC-721 Reentrancy Callback Detector
use crate::bytecode::SecurityFinding;

pub struct Erc721ReentrancyCallbackDetector {
    bytecode: Vec<u8>,
}

impl Erc721ReentrancyCallbackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("ERC-721 callback reentrancy vulnerability at PC {}", location),
                pc: location,
                confidence: 0.93,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_callback_reentrancy(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_callback_reentrancy(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for safeTransferFrom without reentrancy guard before callback
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // safeTransferFrom selector (0x42842e0e, 0xb88d4fde)
            if matches!(self.bytecode[pos+1], 0x42 | 0xb8) {
                let mut has_state_change_before_callback = false;
                let mut has_reentrancy_guard = false;
                let mut has_callback = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for SSTORE (state change) before CALL/STATICCALL
                    let mut sstore_pos = None;
                    let mut call_pos = None;
                    
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 && sstore_pos.is_none() { // SSTORE
                            sstore_pos = Some(j);
                        }
                        if matches!(self.bytecode[j], 0xf1 | 0xf4 | 0xfa) && call_pos.is_none() { // CALL/DELEGATECALL/STATICCALL
                            call_pos = Some(j);
                            has_callback = true;
                        }
                    }
                    
                    // Vulnerable if CALL happens before SSTORE (state update after callback)
                    if let (Some(call), Some(store)) = (call_pos, sstore_pos) {
                        if call < store {
                            has_state_change_before_callback = false;
                        } else {
                            has_state_change_before_callback = true;
                        }
                    }
                    
                    // Check for reentrancy guard (SLOAD check at start)
                    for j in (pos + 5)..(pos + 20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 2] == 0x15 && matches!(self.bytecode[j + 4], 0x57 | 0xfd) {
                                has_reentrancy_guard = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if has callback without guard or state changes after callback
                return has_callback && (!has_reentrancy_guard || !has_state_change_before_callback);
            }
        }
        false
    }
}
