use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct Plonky3FriBatchingSoundnessDetector {
    bytecode: Vec<u8>,
}

impl Plonky3FriBatchingSoundnessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_fri_batching_soundness_break() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "FRI proof batching can break soundness through malformed batch construction allowing invalid proofs to verify.".to_string(),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_commitment_aggregation_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Proof commitment aggregation can be bypassed to forge batch proofs.".to_string(),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_fri_batching_soundness_break(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x20 { // SHA3 (commitment hash)
                let mut has_batch_validation = false;
                let mut has_verify = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { // LT/GT (size check)
                        has_batch_validation = true;
                    }
                    if bytecode[j] == 0xFA && !has_batch_validation { // STATICCALL (verify without check)
                        has_verify = true;
                    }
                }

                if has_verify && !has_batch_validation {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_commitment_aggregation_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x02 { // MUL (aggregation)
                let mut has_commitment_check = false;
                let mut has_store = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x14 { // EQ (validate commitment)
                        has_commitment_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_commitment_check { // SSTORE without check
                        has_store = true;
                    }
                }

                if has_store && !has_commitment_check {
                    return Some(i);
                }
            }
        }

        None
    }
}
