use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZombieProtocolVulnerability {
    DeprecatedButActive { description: String, location: usize, confidence: f32 },
    UnmaintainedDependency { description: String, location: usize, confidence: f32 },
}

pub struct ZombieProtocolDetector {
    bytecode: Vec<u8>,
}

impl ZombieProtocolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ZombieProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let section = &self.bytecode[i..std::cmp::min(i + 60, self.bytecode.len())];
            
            // Pattern: External call without version check
            let has_external_call = section.windows(10).any(|w| {
                w.contains(&0xFA) || w.contains(&0xF1) // STATICCALL or CALL
            });
            
            let no_version_check = !section.windows(12).any(|w| {
                w.contains(&0x54) && w.contains(&0x14) // SLOAD + EQ (version check)
            });
            
            if has_external_call && no_version_check {
                vulnerabilities.push(ZombieProtocolVulnerability::DeprecatedButActive {
                    description: format!("Zombie protocol at PC {}. Calls external protocol without checking if deprecated. Attack: Protocol deprecated but still running → security assumptions broken → exploit. Example: Old Chainlink oracle deprecated, no longer monitored → returns stale data → protocol uses it. Or: V1 contract deprecated but callable → bypass V2 protections. Mitigation: Check protocol version, track deprecation status, or fail-safe to trusted alternative.", i),
                    location: i,
                    confidence: 0.76,
                });
            }
        }
        
        vulnerabilities
    }
}
