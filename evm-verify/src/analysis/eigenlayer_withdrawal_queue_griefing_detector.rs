use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct EigenlayerWithdrawalQueueGriefingDetector {
    bytecode: Vec<u8>,
}

impl EigenlayerWithdrawalQueueGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_withdrawal_queue_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Withdrawal queue can be griefed through spam or manipulation, blocking legitimate withdrawals. EigenLayer withdrawal processing is vulnerable to DOS.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_unbounded_withdrawal_loop() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Withdrawal queue processing has unbounded gas cost, allowing griefing attacks.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_withdrawal_queue_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x01 { // ADD (queue manipulation)
                let mut has_loop = false;
                let mut has_storage_write = false;

                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x57 { has_loop = true; } // JUMPI
                    if bytecode[j] == 0x55 { has_storage_write = true; } // SSTORE
                }

                if has_loop && has_storage_write {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_unbounded_withdrawal_loop(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(20) {
            if bytecode[i] == 0x5B { // JUMPDEST (loop start)
                let mut has_storage_load = false;
                let mut has_jump_back = false;

                for j in i+1..std::cmp::min(i+18, bytecode.len()) {
                    if bytecode[j] == 0x54 { has_storage_load = true; }
                    if bytecode[j] == 0x56 { has_jump_back = true; } // JUMP
                }

                if has_storage_load && has_jump_back {
                    return Some(i);
                }
            }
        }

        None
    }
}
