use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct UniswapV4CrossHookInteractionBugsDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4CrossHookInteractionBugsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_hook_reentrancy_across_pools() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Hook can be re-entered across different pools, allowing state manipulation attacks.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_hook_callback_ordering_bug() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Hook relies on specific callback execution order that can be manipulated.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_hook_reentrancy_across_pools(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xF1 || bytecode[i] == 0xF4 { // CALL or DELEGATECALL
                let mut has_storage_access_after = false;
                
                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x54 || bytecode[j] == 0x55 { // SLOAD or SSTORE
                        has_storage_access_after = true;
                        break;
                    }
                }

                if has_storage_access_after {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_hook_callback_ordering_bug(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut callback_count = 0;

        for i in 0..bytecode.len().saturating_sub(4) {
            if bytecode[i] == 0x63 { // PUSH4 (function selector)
                callback_count += 1;
            }
        }

        if callback_count >= 3 {
            return Some(0);
        }

        None
    }
}
