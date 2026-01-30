use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeBanditReorgVulnerability {
    BlockRewardDependent {
        description: String,
        location: usize,
        confidence: f32,
    },
    DeepReorgVulnerable {
        description: String,
        location: usize,
        confirmations_required: u32,
    },
}

pub struct TimeBanditReorgDetector {
    bytecode: Vec<u8>,
}

impl TimeBanditReorgDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TimeBanditReorgVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.depends_on_block_reward(i) {
                vulnerabilities.push(TimeBanditReorgVulnerability::BlockRewardDependent {
                    description: "Logic depends on block.coinbase or block rewards - reorg risk".to_string(),
                    location: i,
                    confidence: 0.80,
                });
            }
            
            if let Some(confirms) = self.check_confirmation_requirement(i, i + 100) {
                if confirms < 12 {
                    vulnerabilities.push(TimeBanditReorgVulnerability::DeepReorgVulnerable {
                        description: format!("Only {} confirmations required - vulnerable to deep reorg", confirms),
                        location: i,
                        confirmations_required: confirms,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn depends_on_block_reward(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20].iter().any(|&b| b == 0x41)
    }
    
    fn check_confirmation_requirement(&self, start: usize, end: usize) -> Option<u32> {
        let range_end = end.min(self.bytecode.len());
        
        for i in start..range_end {
            if self.bytecode[i] == 0x43 {
                if i + 5 < range_end && self.bytecode[i + 1] == 0x60 {
                    return Some(self.bytecode[i + 2] as u32);
                }
            }
        }
        None
    }
}
