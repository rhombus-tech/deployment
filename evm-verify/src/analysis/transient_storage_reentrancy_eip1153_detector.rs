use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct TransientStorageReentrancyEip1153Detector {
    bytecode: Vec<u8>,
}

impl TransientStorageReentrancyEip1153Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_transient_reentrancy_guard_failure() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Transient storage used as reentrancy guard but cleared between external calls, allowing reentrancy attacks.".to_string(),
                pc,
                confidence: 0.95,
            });
        }

        findings
    }

    fn detect_transient_reentrancy_guard_failure(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x5D { // TSTORE (set guard)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0xF1 || bytecode[j] == 0xF4 { // CALL/DELEGATECALL
                        for k in j+1..std::cmp::min(j+10, bytecode.len()) {
                            if bytecode[k] == 0x5C { // TLOAD (check guard after call)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}
