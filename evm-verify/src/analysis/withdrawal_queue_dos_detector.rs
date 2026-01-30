/// Withdrawal Queue DOS Detector
use crate::bytecode::SecurityFinding;

pub struct WithdrawalQueueDosDetector {
    bytecode: Vec<u8>,
}

impl WithdrawalQueueDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Withdrawal queue DOS vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_queue_dos(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_queue_dos(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for withdrawal queue processing without gas limits or batch size limits
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // requestWithdrawal, processWithdrawals, claimWithdrawal selectors
            if matches!(self.bytecode[pos+1], 0x85 | 0x9f | 0xa2 | 0xba) {
                let mut has_unbounded_loop = false;
                let mut has_gas_check = false;
                let mut has_batch_limit = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for loop (JUMPDEST + counter pattern)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x5b && j + 15 < self.bytecode.len() { // JUMPDEST
                            if self.bytecode[j + 10] == 0x56 || self.bytecode[j + 12] == 0x57 { // JUMP/JUMPI
                                has_unbounded_loop = true;
                                
                                // Check for GAS opcode in loop
                                for k in j..(j + 15).min(self.bytecode.len()) {
                                    if self.bytecode[k] == 0x5a { // GAS
                                        has_gas_check = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for batch size limit (LT/GT comparison before loop)
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) && j + 3 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // REVERT
                                has_batch_limit = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if has unbounded loop without gas or batch limits
                return has_unbounded_loop && !has_gas_check && !has_batch_limit;
            }
        }
        false
    }
}
