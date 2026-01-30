use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AxelarThresholdSignatureVulnerability {
    InsufficientThreshold { description: String, location: usize, confidence: f32 },
    SignatureReuse { description: String, location: usize, confidence: f32 },
    ValidatorSetManipulation { description: String, location: usize, confidence: f32 },
}

pub struct AxelarThresholdSignatureDetector {
    bytecode: Vec<u8>,
}

impl AxelarThresholdSignatureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AxelarThresholdSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.validates_signatures() && !self.checks_sufficient_threshold() {
            vulnerabilities.push(AxelarThresholdSignatureVulnerability::InsufficientThreshold {
                description: "Signature validation without sufficient threshold - low security".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.processes_signatures() && !self.prevents_reuse() {
            vulnerabilities.push(AxelarThresholdSignatureVulnerability::SignatureReuse {
                description: "Signature processing without reuse prevention - replay attack".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.updates_validator_set() && !self.validates_quorum() {
            vulnerabilities.push(AxelarThresholdSignatureVulnerability::ValidatorSetManipulation {
                description: "Validator set update without quorum - validator manipulation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn validates_signatures(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        staticcall_count > 2 && sha3_count > 2
    }
    
    fn checks_sufficient_threshold(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 5 && mul_count > 1 && div_count > 1 && gt_count > 1
    }
    
    fn processes_signatures(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sha3_count > 3 && eq_count > 3
    }
    
    fn prevents_reuse(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sstore_count > 3 && sload_count > 4 && iszero_count > 1
    }
    
    fn updates_validator_set(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 4 && log_count > 1
    }
    
    fn validates_quorum(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 5 && mul_count > 1 && gt_count > 2
    }
}
