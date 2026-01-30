use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct AvailLightClientDataSamplingFraudDetector {
    bytecode: Vec<u8>,
}

impl AvailLightClientDataSamplingFraudDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_data_sampling_fraud() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Light client data availability sampling can be fooled through strategic blob withholding or invalid erasure coding.".to_string(),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_kate_commitment_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Kate polynomial commitments can be manipulated to pass sampling without valid data.".to_string(),
                pc,
                confidence: 0.84,
            });
        }

        findings
    }

    fn detect_data_sampling_fraud(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(60) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (blob data)
                let mut has_sample_verification = false;
                let mut has_acceptance = false;

                for j in i+1..std::cmp::min(i+55, bytecode.len()) {
                    if bytecode[j] == 0xFA { // STATICCALL (verify sample)
                        has_sample_verification = true;
                    }
                    if bytecode[j] == 0x55 && !has_sample_verification { // SSTORE (accept without verification)
                        has_acceptance = true;
                    }
                }

                if has_acceptance && !has_sample_verification {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_kate_commitment_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x20 { // SHA3 (commitment)
                let mut has_proof_check = false;
                let mut has_store = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x08 { // ECPAIRING precompile
                        has_proof_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_proof_check { // SSTORE without proof
                        has_store = true;
                    }
                }

                if has_store && !has_proof_check {
                    return Some(i);
                }
            }
        }

        None
    }
}
