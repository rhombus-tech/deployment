use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernorBravoThresholdVulnerability {
    ProposalThresholdManipulable { description: String, location: usize, confidence: f32 },
    QuorumDenominatorLow { description: String, location: usize },
    ThresholdNotEnforced { description: String, location: usize },
}

pub struct GovernorBravoThresholdDetector {
    bytecode: Vec<u8>,
}

impl GovernorBravoThresholdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GovernorBravoThresholdVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_propose_function(i) {
                if !self.validates_proposal_threshold(i, i + 100) {
                    vulnerabilities.push(GovernorBravoThresholdVulnerability::ThresholdNotEnforced {
                        description: "propose() without threshold validation - spam attack possible".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_propose_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // propose selector: 0xda95691a
        self.bytecode[location..location + 20]
            .windows(4)
            .any(|w| w == [0xda, 0x95, 0x69, 0x1a])
    }
    
    fn validates_proposal_threshold(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Must compare proposer's votes against threshold
        let has_comparison = self.bytecode[start..range_end].iter().any(|&b| b == 0x10 || b == 0x11);
        let has_revert = self.bytecode[start..range_end].iter().any(|&b| b == 0xFD);
        
        has_comparison && has_revert
    }
}
