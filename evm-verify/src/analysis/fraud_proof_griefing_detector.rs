use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FraudProofGriefingVulnerability {
    ChallengeSpamming { description: String, location: usize, confidence: f32 },
    BondLockupGriefing { description: String, location: usize, confidence: f32 },
    ComputationalDoS { description: String, location: usize, confidence: f32 },
}

pub struct FraudProofGriefingDetector {
    bytecode: Vec<u8>,
}

impl FraudProofGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FraudProofGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.accepts_fraud_proofs() && !self.rate_limits_challenges() {
            vulnerabilities.push(FraudProofGriefingVulnerability::ChallengeSpamming {
                description: "Fraud proof system without rate limiting - challenge spam griefing risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.requires_challenge_bond() && !self.has_bond_protection() {
            vulnerabilities.push(FraudProofGriefingVulnerability::BondLockupGriefing {
                description: "Challenge bond required without protection - griefing via bond lockup".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.verifies_proofs_onchain() && !self.limits_computation() {
            vulnerabilities.push(FraudProofGriefingVulnerability::ComputationalDoS {
                description: "On-chain proof verification without computation limits - DoS risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn accepts_fraud_proofs(&self) -> bool {
        // Pattern: external calls with state changes
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 2 && sstore_count > 3
    }
    
    fn rate_limits_challenges(&self) -> bool {
        // Check for timestamp-based rate limiting
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 1 && sub_count > 2 && lt_count > 1
    }
    
    fn requires_challenge_bond(&self) -> bool {
        // Check for value transfer requirement
        let callvalue_count = self.bytecode.iter().filter(|&&b| b == 0x34).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        callvalue_count > 0 && iszero_count > 1
    }
    
    fn has_bond_protection(&self) -> bool {
        // Check for slashing mechanism
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let selfdestruct_count = self.bytecode.iter().filter(|&&b| b == 0xFF).count();
        call_count > 3 || selfdestruct_count > 0
    }
    
    fn verifies_proofs_onchain(&self) -> bool {
        // Complex computation patterns
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        mul_count > 10 && div_count > 5 && mod_count > 2
    }
    
    fn limits_computation(&self) -> bool {
        // Check for gas checks
        let gas_count = self.bytecode.iter().filter(|&&b| b == 0x5A).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gas_count > 0 && gt_count > 1
    }
}
