use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct CentrifugeTinlakeCorporateActionAtomicityDetector {
    bytecode: Vec<u8>,
}

impl CentrifugeTinlakeCorporateActionAtomicityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_non_atomic_corporate_actions() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Corporate actions (rebalancing, asset updates) are not atomic, allowing exploitation during multi-step processes.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_nav_update_race_condition() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "NAV updates can race with investor actions causing mispricing.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_non_atomic_corporate_actions(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x55 { // SSTORE (first state change)
                let mut has_external_call = false;
                let mut has_second_store = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL (external)
                        has_external_call = true;
                    }
                    if bytecode[j] == 0x55 && has_external_call { // SSTORE after call
                        has_second_store = true;
                    }
                }

                if has_external_call && has_second_store {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_nav_update_race_condition(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (NAV calculation)
                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x55 { // SSTORE (update NAV)
                        for k in j+1..std::cmp::min(j+20, bytecode.len()) {
                            if bytecode[k] == 0xF1 { // CALL (investor action)
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
