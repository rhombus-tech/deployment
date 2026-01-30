/// Vesting Cliff Manipulation Detector
///
/// Detects token unlock schedule bypass and cliff manipulation.
/// Coverage: Team vesting, investor lockups, staking rewards
/// Market: $10B+ vesting contracts

use crate::bytecode::SecurityFinding;

pub struct VestingCliffManipulationDetector {
    bytecode: Vec<u8>,
}

impl VestingCliffManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_cliff_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Vesting cliff can be bypassed via timestamp manipulation at PC {}", pc),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_admin_unlock_backdoor() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Admin can unlock vested tokens early without timelock at PC {}", pc),
                pc,
                confidence: 0.92,
            });
        }

        findings
    }

    fn detect_cliff_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // release, claim selectors
                if matches!(self.bytecode[i+1], 0x19 | 0x4e) {
                    let mut has_cliff_check = false;
                    let mut has_block_timestamp = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            has_block_timestamp = true;
                        }
                        // Cliff validation: timestamp > cliff_time
                        if self.bytecode[j] == 0x11 && has_block_timestamp { // GT
                            has_cliff_check = true;
                        }
                    }

                    if has_block_timestamp && !has_cliff_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_admin_unlock_backdoor(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // emergencyWithdraw, adminUnlock selectors
                if matches!(self.bytecode[i+1], 0x5d | 0x6e | 0x7f) {
                    let mut has_timelock = false;

                    for j in i..i+40.min(self.bytecode.len()) {
                        // Check for timelock delay
                        if self.bytecode[j] == 0x42 && j+10 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j+8] == 0x01 { // ADD (delay)
                                has_timelock = true;
                            }
                        }
                    }

                    if !has_timelock {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
