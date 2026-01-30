use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct Erc7579ModuleExecutionOrderDependencyDetector {
    bytecode: Vec<u8>,
}

impl Erc7579ModuleExecutionOrderDependencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_module_execution_order_dependency() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Module execution order can be manipulated causing state inconsistencies or bypassing security checks.".to_string(),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_hook_callback_reentrancy() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Module hooks can be re-entered during execution causing unexpected state changes.".to_string(),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_module_execution_order_dependency(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut module_calls = 0;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xF4 { // DELEGATECALL (module execution)
                module_calls += 1;
                
                if module_calls >= 2 {
                    for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                        if bytecode[j] == 0x54 { // SLOAD (state dependency)
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_hook_callback_reentrancy(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0xF1 { // CALL (hook callback)
                let mut has_state_change = false;
                let mut has_reentrant_call = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x55 { // SSTORE
                        has_state_change = true;
                    }
                    if bytecode[j] == 0xF1 && has_state_change { // CALL (reentrant)
                        has_reentrant_call = true;
                    }
                }

                if has_state_change && has_reentrant_call {
                    return Some(i);
                }
            }
        }

        None
    }
}
