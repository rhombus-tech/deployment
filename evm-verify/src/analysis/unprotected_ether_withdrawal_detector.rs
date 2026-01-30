/// Unprotected Ether Withdrawal Detector
/// Detects withdrawal functions without proper access control
/// Vulnerable pattern: Anyone can drain contract ETH

use crate::bytecode::SecurityFinding;

pub struct UnprotectedEtherWithdrawalDetector {
    bytecode: Vec<u8>,
}

impl UnprotectedEtherWithdrawalDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_unprotected_withdrawal() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Unprotected ether withdrawal at PC {}. Anyone can drain contract balance via CALL/SELFDESTRUCT without access control checks",
                    location
                ),
                pc: location,
                confidence: 0.92,
            });
        }

        findings
    }

    fn has_unprotected_withdrawal(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for CALL/SELFDESTRUCT that sends ETH
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xff { // CALL or SELFDESTRUCT
                // Check if BALANCE or value is being sent
                let has_balance = self.has_balance_before(i);
                
                // Check for missing access control
                let has_access_control = self.has_access_control_before(i);
                
                if has_balance && !has_access_control {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_balance_before(&self, call_pos: usize) -> bool {
        let start = call_pos.saturating_sub(30);
        
        for i in start..call_pos {
            if i >= self.bytecode.len() { break; }
            // BALANCE (0x31) or SELFBALANCE (0x47)
            if self.bytecode[i] == 0x31 || self.bytecode[i] == 0x47 {
                return true;
            }
            // Or check for non-zero value being pushed
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                if self.bytecode[i + 1] > 0 { // PUSH1 with non-zero value
                    return true;
                }
            }
        }
        false
    }

    fn has_access_control_before(&self, call_pos: usize) -> bool {
        let start = call_pos.saturating_sub(100);
        
        // Look for: msg.sender check (CALLER + EQ + JUMPI/REVERT)
        // Or: onlyOwner modifier pattern
        for i in start..call_pos {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x33 { // CALLER
                // Look for comparison
                for j in (i + 1)..(i + 15).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x14 { // EQ
                        // Check for conditional revert/jump
                        for k in (j + 1)..(j + 10).min(self.bytecode.len()) {
                            if k >= self.bytecode.len() { break; }
                            if self.bytecode[k] == 0xfd || self.bytecode[k] == 0x57 { // REVERT or JUMPI
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}
