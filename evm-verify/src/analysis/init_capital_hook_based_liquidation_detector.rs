use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct InitCapitalHookBasedLiquidationDetector {
    bytecode: Vec<u8>,
}

impl InitCapitalHookBasedLiquidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_hook_liquidation_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Liquidation hooks can be exploited to bypass liquidation logic, allowing undercollateralized positions to persist or liquidators to be griefed.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_liquidation_callback_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Liquidation callbacks can be manipulated to extract value or prevent legitimate liquidations through reentrancy or state poisoning.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_hook_liquidation_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let before_liquidate = [0x4a, 0x39, 0x3b, 0x26]; // beforeLiquidate selector
        let after_liquidate = [0x8f, 0x1d, 0x72, 0x91];  // afterLiquidate selector

        for i in 0..bytecode.len().saturating_sub(50) {
            if &bytecode[i..i+4] == &before_liquidate {
                for j in i+4..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x57 { // JUMPI (bypass condition)
                        return Some(i);
                    }
                    if &bytecode[j..std::cmp::min(j+4, bytecode.len())] == &after_liquidate {
                        for k in j+4..std::cmp::min(j+20, bytecode.len()) {
                            if bytecode[k] == 0x55 { // SSTORE in hook
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_liquidation_callback_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0xF1 { // CALL (liquidation callback)
                let mut has_health_check = false;
                let mut has_reentrant_call = false;

                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 {
                        has_health_check = true;
                    }
                    if bytecode[j] == 0xF1 && has_health_check {
                        has_reentrant_call = true;
                    }
                }

                if has_health_check && has_reentrant_call {
                    return Some(i);
                }
            }
        }

        None
    }
}
