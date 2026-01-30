use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolygonCDKZkproofVulnerability {
    InvalidProofAcceptance { description: String, location: usize, confidence: f32 },
    SequencerProofManipulation { description: String, location: usize, confidence: f32 },
    StateRootMismatch { description: String, location: usize, confidence: f32 },
}

pub struct PolygonCDKZkproofDetector {
    bytecode: Vec<u8>,
}

impl PolygonCDKZkproofDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PolygonCDKZkproofVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.verifies_proof() && !self.validates_public_inputs() {
            vulnerabilities.push(PolygonCDKZkproofVulnerability::InvalidProofAcceptance {
                description: "ZK proof verification without public input validation - invalid proof acceptance".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.sequences_batch() && !self.checks_proof_commitment() {
            vulnerabilities.push(PolygonCDKZkproofVulnerability::SequencerProofManipulation {
                description: "Batch sequencing without proof commitment - proof substitution".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.updates_state_root() && !self.verifies_previous_root() {
            vulnerabilities.push(PolygonCDKZkproofVulnerability::StateRootMismatch {
                description: "State root update without previous root verification - state inconsistency".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn verifies_proof(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        staticcall_count > 1 && iszero_count > 2
    }
    
    fn validates_public_inputs(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sha3_count > 2 && eq_count > 3 && sload_count > 4
    }
    
    fn sequences_batch(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 4 && log_count > 1
    }
    
    fn checks_proof_commitment(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sha3_count > 1 && sload_count > 3 && eq_count > 2
    }
    
    fn updates_state_root(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 3 && sha3_count > 1
    }
    
    fn verifies_previous_root(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 4 && eq_count > 3 && iszero_count > 2
    }
}
