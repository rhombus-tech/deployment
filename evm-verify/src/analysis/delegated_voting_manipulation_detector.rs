use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegatedVotingManipulationVulnerability {
    NoSnapshotVoting { description: String, location: usize, confidence: f32 },
    DelegateSelfVote { description: String, location: usize },
}

pub struct DelegatedVotingManipulationDetector {
    bytecode: Vec<u8>,
}

impl DelegatedVotingManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DelegatedVotingManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // delegate selector: 0x5c19a95c
        let delegate_selector = [0x5c, 0x19, 0xa9, 0x5c];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == delegate_selector) {
                if !self.uses_snapshot(i, i + 80) {
                    vulnerabilities.push(DelegatedVotingManipulationVulnerability::NoSnapshotVoting {
                        description: "Voting delegation without snapshot - flash loan manipulation".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn uses_snapshot(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Snapshot uses block number in calculation
        self.bytecode[start..range_end].iter().any(|&b| b == 0x43) // NUMBER
    }
}
