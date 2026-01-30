use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EigenpodWithdrawalProofVulnerability {
    InvalidWithdrawalProof { description: String, location: usize, confidence: f32 },
    ProofReplay { description: String, location: usize, confidence: f32 },
    TimestampManipulation { description: String, location: usize, confidence: f32 },
}

pub struct EigenpodWithdrawalProofDetector {
    bytecode: Vec<u8>,
}

impl EigenpodWithdrawalProofDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EigenpodWithdrawalProofVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.verifies_proof() && !self.validates_merkle_root() {
            vulnerabilities.push(EigenpodWithdrawalProofVulnerability::InvalidWithdrawalProof {
                description: "Withdrawal proof without root validation - invalid proof acceptance".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.processes_withdrawal() && !self.marks_proof_used() {
            vulnerabilities.push(EigenpodWithdrawalProofVulnerability::ProofReplay {
                description: "Proof processing without replay protection - double withdrawal".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_timestamp() && !self.validates_timestamp_range() {
            vulnerabilities.push(EigenpodWithdrawalProofVulnerability::TimestampManipulation {
                description: "Timestamp usage without range validation - timestamp manipulation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn verifies_proof(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sha3_count > 3 && eq_count > 3
    }
    
    fn validates_merkle_root(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 4 && eq_count > 4
    }
    
    fn processes_withdrawal(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 1 && sstore_count > 3
    }
    
    fn marks_proof_used(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 4 && sha3_count > 2
    }
    
    fn uses_timestamp(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        timestamp_count > 1
    }
    
    fn validates_timestamp_range(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        gt_count > 1 && lt_count > 1
    }
}
