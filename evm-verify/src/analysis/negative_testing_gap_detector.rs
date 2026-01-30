use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NegativeTestingVulnerability {
    MissingRevertCheck { description: String, location: usize, confidence: f32 },
    UnexpectedSuccess { description: String, location: usize, confidence: f32 },
}

pub struct NegativeTestingGapDetector {
    bytecode: Vec<u8>,
}

impl NegativeTestingGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<NegativeTestingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let section = &self.bytecode[i..std::cmp::min(i + 60, self.bytecode.len())];
            
            // Pattern: Function without access control but should have
            let has_state_change = section.contains(&0x55); // SSTORE
            let no_access_control = !section.windows(12).any(|w| {
                w.contains(&0x33) && w.contains(&0x14) && w.contains(&0x57) // CALLER + EQ + JUMPI
            });
            
            if has_state_change && no_access_control {
                vulnerabilities.push(NegativeTestingVulnerability::MissingRevertCheck {
                    description: format!("Negative testing gap at PC {}. Function SHOULD revert for unauthorized caller but doesn't. Attack: Call privileged function without authorization → succeeds when it should fail. Example: withdraw() callable by anyone when should be admin-only. Tests verify admin CAN call, but never test that non-admin CANNOT. Mitigation: Test negative cases - unauthorized access should revert, invalid inputs should revert, edge cases should be rejected.", i),
                    location: i,
                    confidence: 0.79,
                });
            }
        }
        
        vulnerabilities
    }
}
