use crate::bytecode::SecurityFinding;

pub struct SymbioticRestakingSlashingBypassDetector {
    bytecode: Vec<u8>,
}

impl SymbioticRestakingSlashingBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_slashing_bypass() {
            findings.push(SecurityFinding {
                severity: "CRITICAL".to_string(),
                description: "Slashing mechanism can be bypassed through operator collusion or timing attacks, allowing malicious validators to avoid penalties.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        if let Some(pc) = self.detect_operator_collusion_risk() {
            findings.push(SecurityFinding {
                severity: "HIGH".to_string(),
                description: "Multiple operators can collude to bypass slashing conditions or extract restaked funds.".to_string(),
                pc,
                confidence: 0.80,
            });
        }

        findings
    }

    fn detect_slashing_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x42 { // TIMESTAMP
                let mut has_slashing_calc = false;
                let mut has_bypass_path = false;

                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x04 { has_slashing_calc = true; } // DIV
                    if bytecode[j] == 0x57 { // JUMPI (bypass condition)
                        if has_slashing_calc {
                            has_bypass_path = true;
                        }
                    }
                }

                if has_slashing_calc && has_bypass_path {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_operator_collusion_risk(&self) -> Option<usize> {
        let bytecode = &self.bytecode;
        let mut operator_checks = 0;

        for i in 0..bytecode.len().saturating_sub(20) {
            if bytecode[i] == 0x33 { // CALLER
                for j in i+1..std::cmp::min(i+15, bytecode.len()) {
                    if bytecode[j] == 0x14 { // EQ (operator check)
                        operator_checks += 1;
                        break;
                    }
                }
            }
        }

        if operator_checks >= 3 {
            return Some(0);
        }

        None
    }
}
