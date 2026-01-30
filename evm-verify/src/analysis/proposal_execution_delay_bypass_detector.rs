use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalExecutionDelayBypassVulnerability {
    NoTimelockValidation { description: String, location: usize, confidence: f32 },
    EmergencyBypassWithoutCheck { description: String, location: usize },
}

pub struct ProposalExecutionDelayBypassDetector {
    bytecode: Vec<u8>,
}

impl ProposalExecutionDelayBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProposalExecutionDelayBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // execute selector (governance): 0xfe0d94c1
        let execute_selector = [0xfe, 0x0d, 0x94, 0xc1];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == execute_selector) {
                if !self.validates_timelock(i, i + 80) {
                    vulnerabilities.push(ProposalExecutionDelayBypassVulnerability::NoTimelockValidation {
                        description: "Proposal execution without timelock delay validation".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn validates_timelock(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Timelock: TIMESTAMP check + stored execution time comparison
        let has_timestamp = self.bytecode[start..range_end].iter().any(|&b| b == 0x42);
        let has_lt = self.bytecode[start..range_end].iter().any(|&b| b == 0x10);
        has_timestamp && has_lt
    }
}
