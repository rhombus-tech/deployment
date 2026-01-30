use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpochBoundaryGamingVulnerability {
    RewardTimingManipulation { description: String, location: usize, confidence: f32 },
    EpochBoundaryExploit { description: String, location: usize },
    StakingRewardGaming { description: String, location: usize },
}

pub struct EpochBoundaryGamingDetector {
    bytecode: Vec<u8>,
}

impl EpochBoundaryGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EpochBoundaryGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_epoch_based_rewards() {
            if !self.has_snapshot_protection() {
                vulnerabilities.push(EpochBoundaryGamingVulnerability::RewardTimingManipulation {
                    description: "Epoch rewards without snapshot - timing manipulation possible".to_string(),
                    location: 0,
                    confidence: 0.85,
                });
            }
            
            if self.allows_same_block_stake_claim() {
                vulnerabilities.push(EpochBoundaryGamingVulnerability::EpochBoundaryExploit {
                    description: "Can stake and claim rewards in same block - epoch boundary gaming".to_string(),
                    location: 0,
                });
            }
        }
        
        if self.has_staking_rewards() && !self.has_minimum_stake_duration() {
            vulnerabilities.push(EpochBoundaryGamingVulnerability::StakingRewardGaming {
                description: "No minimum stake duration - flash staking for rewards".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_epoch_based_rewards(&self) -> bool {
        // MOD operation for epoch calculation
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        mod_count > 0 && timestamp_count > 0
    }
    
    fn has_snapshot_protection(&self) -> bool {
        // Block number + storage checks
        let has_number = self.bytecode.iter().any(|&b| b == 0x43);
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        has_number && sload_count > 3
    }
    
    fn allows_same_block_stake_claim(&self) -> bool {
        // No block.number difference check
        let number_count = self.bytecode.iter().filter(|&&b| b == 0x43).count();
        number_count < 2
    }
    
    fn has_staking_rewards(&self) -> bool {
        // MUL and DIV for reward calculation
        let has_mul = self.bytecode.iter().any(|&b| b == 0x02);
        let has_div = self.bytecode.iter().any(|&b| b == 0x04);
        has_mul && has_div
    }
    
    fn has_minimum_stake_duration(&self) -> bool {
        // Timestamp comparison for duration
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count >= 2 && lt_count > 0
    }
}
