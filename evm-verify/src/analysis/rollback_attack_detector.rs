use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackVulnerability {
    ForceDowngrade { description: String, location: usize, confidence: f32 },
    VersionRevert { description: String, location: usize, confidence: f32 },
}

pub struct RollbackAttackDetector {
    bytecode: Vec<u8>,
}

impl RollbackAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<RollbackVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(65) {
            let section = &self.bytecode[i..std::cmp::min(i + 65, self.bytecode.len())];
            
            // Pattern: Implementation can be set to any address
            let has_implementation_write = section.windows(10).any(|w| {
                w.contains(&0x55) // SSTORE
            });
            
            let has_delegate = section.contains(&0xF4); // DELEGATECALL
            let no_forward_only = !section.windows(15).any(|w| {
                w.contains(&0x10) && w.contains(&0x57) // LT + JUMPI (version must increase)
            });
            
            if has_implementation_write && has_delegate && no_forward_only {
                vulnerabilities.push(RollbackVulnerability::ForceDowngrade {
                    description: format!("Rollback attack at PC {}. Implementation can be downgraded to vulnerable version. Attack: Admin/attacker reverts proxy to old implementation with known bug → exploit. Example: V3 fixed reentrancy, attacker forces rollback to V2 → exploits reentrancy. Or: Governance vote to downgrade → attackers vote yes → rollback to vulnerable version. Mitigation: Enforce monotonic version increases, or disable rollback entirely.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
