use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct UniswapV4BeforeAfterHookAtomicityDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4BeforeAfterHookAtomicityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_before_after_state_inconsistency() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "State changes between beforeSwap and afterSwap hooks are not atomic, allowing manipulation between callback execution.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_before_after_state_inconsistency(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let before_swap = [0x1c, 0xb7, 0xb9, 0xf7]; // beforeSwap selector
        let after_swap = [0x3c, 0x6a, 0x5c, 0x54];  // afterSwap selector

        let mut before_pos = None;
        let mut after_pos = None;

        for i in 0..bytecode.len().saturating_sub(4) {
            if &bytecode[i..i+4] == &before_swap {
                before_pos = Some(i);
            }
            if &bytecode[i..i+4] == &after_swap {
                after_pos = Some(i);
            }
        }

        if let (Some(before), Some(after)) = (before_pos, after_pos) {
            for i in before..std::cmp::min(before+50, bytecode.len()) {
                if bytecode[i] == 0x55 { // SSTORE between hooks
                    return Some(before);
                }
            }
        }

        None
    }
}
