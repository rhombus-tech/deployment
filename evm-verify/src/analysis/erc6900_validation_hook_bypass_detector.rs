use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct Erc6900ValidationHookBypassDetector {
    bytecode: Vec<u8>,
}

impl Erc6900ValidationHookBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_validation_hook_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Validation hooks can be bypassed through plugin manipulation or execution context confusion.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_plugin_installation_race() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Plugin installation/uninstallation can race with execution causing validation bypass.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_validation_hook_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xF1 { // CALL (validation hook)
                let mut has_return_check = false;
                let mut has_execution = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x15 { // ISZERO (check return)
                        has_return_check = true;
                    }
                    if bytecode[j] == 0xF4 && !has_return_check { // DELEGATECALL without validation
                        has_execution = true;
                    }
                }

                if has_execution && !has_return_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_plugin_installation_race(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x55 { // SSTORE (plugin state)
                let mut has_external_call = false;
                let mut has_second_store = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL (external)
                        has_external_call = true;
                    }
                    if bytecode[j] == 0x55 && has_external_call { // SSTORE (update)
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
}
