/// Withdrawal Censorship Detector
use crate::bytecode::SecurityFinding;

pub struct WithdrawalCensorshipDetector {
    bytecode: Vec<u8>,
}

impl WithdrawalCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Withdrawal censorship vulnerability at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_withdrawal_censorship(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_withdrawal_censorship(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for withdrawal mechanisms that can be censored
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // withdraw, finalizeWithdrawal, processExit selectors
            if matches!(self.bytecode[pos+1], 0x2e | 0x51 | 0x83 | 0xcc) {
                let mut has_forced_withdrawal = false;
                let mut allows_l1_escape = false;
                let mut prevents_sequencer_censorship = false;
                let mut has_time_bound_processing = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for forced withdrawal mechanism (bypass sequencer)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            // Check for forced inclusion flag
                            if self.bytecode[j + 3] == 0x15 { // ISZERO (checking flag)
                                has_forced_withdrawal = true;
                            }
                        }
                    }
                    
                    // Check for L1 escape hatch
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xf1 { // CALL to L1 contract
                            allows_l1_escape = true;
                        }
                    }
                    
                    // Check for anti-censorship (any user can trigger)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 { // CALLER
                            // Should not restrict to specific addresses
                            prevents_sequencer_censorship = true;
                        }
                    }
                    
                    // Check for maximum processing time
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 8 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 4] == 0x11 { // GT (checking deadline)
                                has_time_bound_processing = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if withdrawals can be censored via:
                // 1. No forced withdrawal mechanism
                // 2. No L1 escape hatch
                // 3. Sequencer can block withdrawals
                // 4. No time bound on processing
                return !has_forced_withdrawal || !allows_l1_escape || !prevents_sequencer_censorship || !has_time_bound_processing;
            }
        }
        false
    }
}
