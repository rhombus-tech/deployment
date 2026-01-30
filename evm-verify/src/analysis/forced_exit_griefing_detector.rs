/// Forced Exit Griefing Detector
use crate::bytecode::SecurityFinding;

pub struct ForcedExitGriefingDetector {
    bytecode: Vec<u8>,
}

impl ForcedExitGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Forced exit griefing vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_forced_exit_griefing(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_forced_exit_griefing(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for forced exit mechanisms that can be griefed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // forceExit, emergencyWithdraw, escapeHatch selectors
            if matches!(self.bytecode[pos+1], 0x3b | 0x5e | 0x82 | 0xd4) {
                let mut has_exit_cost = false;
                let mut prevents_spam_exits = false;
                let mut limits_exit_frequency = false;
                let mut validates_exit_conditions = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for exit cost (to prevent free griefing)
                    for j in (pos + 5)..(pos + 25).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x31 && j + 6 < self.bytecode.len() { // BALANCE
                            if self.bytecode[j + 3] == 0x10 { // LT (minimum balance check)
                                has_exit_cost = true;
                            }
                        }
                    }
                    
                    // Check for spam prevention (rate limiting)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 5] == 0x11 { // GT (checking exit count)
                                prevents_spam_exits = true;
                            }
                        }
                    }
                    
                    // Check for exit frequency limit (cooldown)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 8 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 4] == 0x01 { // ADD (cooldown period)
                                limits_exit_frequency = true;
                            }
                        }
                    }
                    
                    // Check for exit condition validation
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 { // GT/LT
                            // Should validate legitimate exit conditions
                            validates_exit_conditions = true;
                        }
                    }
                }
                
                // Vulnerable if forced exits can be griefed via:
                // 1. No cost to trigger exit
                // 2. No spam prevention
                // 3. No cooldown period
                // 4. No validation of exit conditions
                return !has_exit_cost || !prevents_spam_exits || !limits_exit_frequency || !validates_exit_conditions;
            }
        }
        false
    }
}
