use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlashLoanVotingVulnerability {
    VotingWithoutSnapshot { description: String, location: usize, confidence: f32 },
    SameBlockVoteAndProposal { description: String, location: usize },
    NoFlashLoanProtection { description: String, location: usize },
}

pub struct FlashLoanVotingDetector {
    bytecode: Vec<u8>,
}

impl FlashLoanVotingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FlashLoanVotingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_voting_function(i) {
                if !self.uses_historical_balance(i, i + 120) {
                    vulnerabilities.push(FlashLoanVotingVulnerability::VotingWithoutSnapshot {
                        description: "Voting uses current balance without snapshot - flash loan attack possible".to_string(),
                        location: i,
                        confidence: 0.95,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_voting_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // castVote: 0x56781388, castVoteWithReason: 0x7b3c71d3
        let selectors = [[0x56, 0x78, 0x13, 0x88], [0x7b, 0x3c, 0x71, 0xd3]];
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn uses_historical_balance(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // getPastVotes or snapshot-based balance check
        // Pattern: Block number subtraction for historical lookup
        let has_block_number_sub = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| w[0] == 0x43 && w[2] == 0x03); // NUMBER + SUB
        
        has_block_number_sub
    }
}
