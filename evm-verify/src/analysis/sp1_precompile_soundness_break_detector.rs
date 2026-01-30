use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct Sp1PrecompileSoundnessBreakDetector {
    bytecode: Vec<u8>,
}

impl Sp1PrecompileSoundnessBreakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_precompile_soundness_break() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Custom precompiles in SP1 zkVM can break proof soundness through malformed inputs or constraint violations.".to_string(),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_constraint_system_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Precompile constraints can be bypassed to generate valid-looking but unsound proofs.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        findings
    }

    fn detect_precompile_soundness_break(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (precompile)
                let mut has_constraint_check = false;
                let mut has_result_use = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { // LT/GT (bounds)
                        has_constraint_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_constraint_check { // SSTORE without check
                        has_result_use = true;
                    }
                }

                if has_result_use && !has_constraint_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_constraint_system_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x02 || bytecode[i] == 0x01 { // MUL/ADD (constraint)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x57 { // JUMPI (conditional skip)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0xFA { // STATICCALL (use unchecked result)
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
