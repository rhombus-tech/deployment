use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AirdropClaimFrontrunningVulnerability {
    UnprotectedClaimFunction { description: String, location: usize, confidence: f32 },
    MerkleProofReuse { description: String, location: usize, confidence: f32 },
    ClaimableWithoutCommitment { description: String, location: usize, confidence: f32 },
}

pub struct AirdropClaimFrontrunningDetector {
    bytecode: Vec<u8>,
}

impl AirdropClaimFrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AirdropClaimFrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_claim_function() && !self.uses_commit_reveal() {
            vulnerabilities.push(AirdropClaimFrontrunningVulnerability::UnprotectedClaimFunction {
                description: "Airdrop claim without commit-reveal - frontrunning risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.verifies_merkle_proof() && !self.marks_proof_used() {
            vulnerabilities.push(AirdropClaimFrontrunningVulnerability::MerkleProofReuse {
                description: "Merkle proof verification without usage tracking - proof reuse risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.distributes_tokens() && !self.requires_signature() {
            vulnerabilities.push(AirdropClaimFrontrunningVulnerability::ClaimableWithoutCommitment {
                description: "Token distribution without signature requirement - claim sniping".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_claim_function(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 1 && sstore_count > 2
    }
    
    fn uses_commit_reveal(&self) -> bool {
        // Two-step process: commit with hash, reveal later
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sha3_count > 2 && sload_count > 4 && eq_count > 3
    }
    
    fn verifies_merkle_proof(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sha3_count > 3 && eq_count > 2
    }
    
    fn marks_proof_used(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 2 && sha3_count > 1
    }
    
    fn distributes_tokens(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        call_count > 1
    }
    
    fn requires_signature(&self) -> bool {
        // ecrecover or signature verification
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        staticcall_count > 1 && eq_count > 2
    }
}
