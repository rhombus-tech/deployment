use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct UniswapV4HookUpgradeAtomicityDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4HookUpgradeAtomicityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_non_atomic_hook_upgrade() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Hook upgrade process is not atomic, allowing exploitation during upgrade window.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_non_atomic_hook_upgrade(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(30) {
            if bytecode[i] == 0x55 { // SSTORE (upgrade)
                let mut has_call_between = false;
                
                for j in i+1..std::cmp::min(i+25, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL
                        has_call_between = true;
                        
                        for k in j+1..std::cmp::min(j+10, bytecode.len()) {
                            if bytecode[k] == 0x55 { // Another SSTORE
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
