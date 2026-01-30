use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct NearDaBlobAggregationManipulationDetector {
    bytecode: Vec<u8>,
}

impl NearDaBlobAggregationManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_blob_aggregation_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Blob aggregation in NEAR DA can be manipulated to include invalid data or omit required data.".to_string(),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_proof_aggregation_bypass() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Proof aggregation can be bypassed to accept unverified blobs.".to_string(),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_blob_aggregation_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (blob data)
                let mut has_merkle_verification = false;
                let mut has_aggregation = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0x20 { // SHA3 (merkle root)
                        has_merkle_verification = true;
                    }
                    if bytecode[j] == 0x01 { // ADD (aggregate blobs)
                        has_aggregation = true;
                    }
                }

                if has_aggregation && !has_merkle_verification {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_proof_aggregation_bypass(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (verify proof)
                let mut has_result_check = false;
                let mut has_accept = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x15 { // ISZERO (check result)
                        has_result_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_result_check { // SSTORE (accept without check)
                        has_accept = true;
                    }
                }

                if has_accept && !has_result_check {
                    return Some(i);
                }
            }
        }

        None
    }
}
