use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityLockBypassVulnerability {
    NoLockPeriod { description: String, location: usize, confidence: f32 },
    OwnerBypassLock { description: String, location: usize },
    EmergencyWithdraw { description: String, location: usize },
}

pub struct LiquidityLockBypassDetector {
    bytecode: Vec<u8>,
}

impl LiquidityLockBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityLockBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // removeLiquidity selector: 0xbaa2abde
        let remove_liquidity = [0xba, 0xa2, 0xab, 0xde];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == remove_liquidity) {
                if !self.has_timelock_check(i, i + 80) {
                    vulnerabilities.push(LiquidityLockBypassVulnerability::NoLockPeriod {
                        description: "Liquidity can be removed without time lock - rug pull risk".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if self.has_owner_bypass(i, i + 80) {
                    vulnerabilities.push(LiquidityLockBypassVulnerability::OwnerBypassLock {
                        description: "Owner can bypass liquidity lock".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_timelock_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // TIMESTAMP + comparison pattern
        let has_timestamp = self.bytecode[start..range_end].iter().any(|&b| b == 0x42);
        let has_lt = self.bytecode[start..range_end].iter().any(|&b| b == 0x10);
        has_timestamp && has_lt
    }
    
    fn has_owner_bypass(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // CALLER check
        let has_caller = self.bytecode[start..range_end].iter().any(|&b| b == 0x33);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        has_caller && has_eq
    }
}
