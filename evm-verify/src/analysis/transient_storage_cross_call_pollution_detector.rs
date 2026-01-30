use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct TransientStorageCrossCallPollutionDetector {
    bytecode: Vec<u8>,
}

impl TransientStorageCrossCallPollutionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_cross_call_transient_pollution() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Transient storage can be polluted across external calls, causing state confusion in nested call contexts.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_cross_call_transient_pollution(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(30) {
            if bytecode[i] == 0x5D { // TSTORE
                for j in i+1..std::cmp::min(i+25, bytecode.len()) {
                    if bytecode[j] == 0xF1 || bytecode[j] == 0xF4 { // CALL or DELEGATECALL
                        for k in j+1..std::cmp::min(j+10, bytecode.len()) {
                            if bytecode[k] == 0x5C { // TLOAD after call
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
