use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ModeSfsSequencerFeeSharingManipulationDetector {
    bytecode: Vec<u8>,
}

impl ModeSfsSequencerFeeSharingManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_sfs_fee_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Sequencer Fee Sharing (SFS) can be manipulated to redirect fees or claim fees belonging to other contracts.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_fee_registration_front_running() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Fee registration can be front-run to steal fee sharing rewards.".to_string(),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_sfs_fee_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xF1 { // CALL (SFS registry)
                let mut has_fee_calc = false;
                let mut has_claim = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x04 { // DIV (fee distribution)
                        has_fee_calc = true;
                    }
                    if bytecode[j] == 0x55 && has_fee_calc { // SSTORE (claim)
                        has_claim = true;
                    }
                }

                if has_fee_calc && has_claim {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_fee_registration_front_running(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x30 { // ADDRESS
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0xF1 { // CALL (register)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x54 { // SLOAD (check if registered)
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
