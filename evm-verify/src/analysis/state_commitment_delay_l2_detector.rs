use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateCommitmentDelayL2Vulnerability {
    DelayedStateCommitment { description: String, location: usize, confidence: f32 },
    MissingFinalityCheck { description: String, location: usize, confidence: f32 },
    CommitmentReorgRisk { description: String, location: usize, confidence: f32 },
}

pub struct StateCommitmentDelayL2Detector {
    bytecode: Vec<u8>,
}

impl StateCommitmentDelayL2Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StateCommitmentDelayL2Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.relies_on_l2_state() && !self.validates_commitment_age() {
            vulnerabilities.push(StateCommitmentDelayL2Vulnerability::DelayedStateCommitment {
                description: "Relies on L2 state without commitment age validation - stale state risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.reads_l2_storage() && !self.checks_finality() {
            vulnerabilities.push(StateCommitmentDelayL2Vulnerability::MissingFinalityCheck {
                description: "L2 storage read without finality check - unconfirmed state usage".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_l2_oracle_data() && !self.has_reorg_protection() {
            vulnerabilities.push(StateCommitmentDelayL2Vulnerability::CommitmentReorgRisk {
                description: "L2 oracle data without reorg protection - commitment rollback risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn relies_on_l2_state(&self) -> bool {
        // External calls to L2 contracts
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        staticcall_count > 2 || call_count > 1
    }
    
    fn validates_commitment_age(&self) -> bool {
        // Check for timestamp validation
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 1 && sub_count > 1 && gt_count > 0
    }
    
    fn reads_l2_storage(&self) -> bool {
        // STATICCALL pattern for reading
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 1
    }
    
    fn checks_finality(&self) -> bool {
        // Block number checks
        let blocknumber_count = self.bytecode.iter().filter(|&&b| b == 0x43).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        blocknumber_count > 0 && sub_count > 1 && gt_count > 0
    }
    
    fn uses_l2_oracle_data(&self) -> bool {
        // External call for price/data
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let returndatasize_count = self.bytecode.iter().filter(|&&b| b == 0x3D).count();
        staticcall_count > 1 && returndatasize_count > 0
    }
    
    fn has_reorg_protection(&self) -> bool {
        // Multiple confirmations or time delay
        let blocknumber_count = self.bytecode.iter().filter(|&&b| b == 0x43).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        (blocknumber_count > 1 || timestamp_count > 1) && gt_count > 1
    }
}
