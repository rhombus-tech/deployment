use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct SafeModulesDelegatecallEscalationDetector {
    bytecode: Vec<u8>,
}

impl SafeModulesDelegatecallEscalationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_module_delegatecall_escalation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Safe modules can escalate privileges through delegatecall to malicious contracts, bypassing multisig requirements.".to_string(),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_guard_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Transaction guards can be bypassed through module execution.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_module_delegatecall_escalation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (module list)
                let mut has_delegatecall = false;
                let mut lacks_validation = true;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0xF4 { // DELEGATECALL
                        has_delegatecall = true;
                    }
                    if bytecode[j] == 0x14 { // EQ (module validation)
                        lacks_validation = false;
                    }
                }

                if has_delegatecall && lacks_validation {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_guard_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0xF1 { // CALL (guard check)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x57 { // JUMPI (conditional skip)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xF4 { // DELEGATECALL (execute anyway)
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
