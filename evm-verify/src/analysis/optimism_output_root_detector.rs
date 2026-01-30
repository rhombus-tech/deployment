use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimismOutputRootVulnerability {
    OutputRootChallenge { description: String, location: usize, confidence: f32 },
    ProposerValidation { description: String, location: usize, confidence: f32 },
    FinalizationPeriodBypass { description: String, location: usize, confidence: f32 },
}

pub struct OptimismOutputRootDetector {
    bytecode: Vec<u8>,
}

impl OptimismOutputRootDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OptimismOutputRootVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.proposes_output_root() && !self.allows_challenge() {
            vulnerabilities.push(OptimismOutputRootVulnerability::OutputRootChallenge {
                description: "Output root proposal without challenge mechanism - invalid state finalization".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.validates_proposer() && !self.checks_bond() {
            vulnerabilities.push(OptimismOutputRootVulnerability::ProposerValidation {
                description: "Proposer validation without bond requirement - spam proposals".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.finalizes_output() && !self.enforces_finalization_period() {
            vulnerabilities.push(OptimismOutputRootVulnerability::FinalizationPeriodBypass {
                description: "Output finalization without time delay - immediate finalization risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn proposes_output_root(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 3 && sha3_count > 1
    }
    
    fn allows_challenge(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        sload_count > 4 && timestamp_count > 0 && lt_count > 1
    }
    
    fn validates_proposer(&self) -> bool {
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        eq_count > 2 && caller_count > 0
    }
    
    fn checks_bond(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let callvalue_count = self.bytecode.iter().filter(|&&b| b == 0x34).count();
        sload_count > 3 && gt_count > 1 && callvalue_count > 0
    }
    
    fn finalizes_output(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 4 && log_count > 1
    }
    
    fn enforces_finalization_period(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 0 && sload_count > 4 && add_count > 2 && gt_count > 1
    }
}
