use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct JoltLassoPolynomialCommitmentBypassDetector {
    bytecode: Vec<u8>,
}

impl JoltLassoPolynomialCommitmentBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_lasso_commitment_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Lasso polynomial commitment scheme can be bypassed through malformed evaluation proofs, breaking zkVM soundness.".to_string(),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_lookup_table_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Lookup table commitments can be manipulated to alter execution traces.".to_string(),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_lasso_commitment_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x20 { // SHA3 (polynomial hash)
                let mut has_eval_check = false;
                let mut has_commitment = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xFA { // STATICCALL (pairing check)
                        has_eval_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_eval_check { // SSTORE without verification
                        has_commitment = true;
                    }
                }

                if has_commitment && !has_eval_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_lookup_table_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x54 { // SLOAD (lookup table)
                let mut has_table_check = false;
                let mut has_update = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x14 { // EQ (table entry validation)
                        has_table_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_table_check { // SSTORE without check
                        has_update = true;
                    }
                }

                if has_update && !has_table_check {
                    return Some(i);
                }
            }
        }

        None
    }
}
