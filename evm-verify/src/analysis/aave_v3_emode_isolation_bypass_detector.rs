use crate::bytecode::SecurityFinding;

pub struct AaveV3EmodeIsolationBypassDetector {
    bytecode: Vec<u8>,
}

impl AaveV3EmodeIsolationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_emode_isolation_bypass() {
            findings.push(SecurityFinding {
                severity: "CRITICAL".to_string(),
                description: "E-Mode isolation can be bypassed allowing cross-collateral attacks between isolated and non-isolated assets.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_emode_isolation_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (eMode category)
                let mut has_isolation_check = false;
                let mut has_borrow = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { 
                        has_isolation_check = true;
                    }
                    if bytecode[j] == 0xF1 { has_borrow = true; }
                }

                if has_isolation_check && has_borrow {
                    return Some(i);
                }
            }
        }

        None
    }
}
