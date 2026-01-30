use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChronicleVulnerability {
    ValidatorQuorumBypass { description: String, location: usize, confidence: f32 },
    InsufficientValidatorCount { description: String, location: usize, confidence: f32 },
}

pub struct ChronicleValidatorQuorumBypassDetector {
    bytecode: Vec<u8>,
}

impl ChronicleValidatorQuorumBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ChronicleVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Chronicle oracle: validator set must reach quorum
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Oracle read without quorum validation
            let has_oracle_read = section.contains(&0xFA); // STATICCALL
            let has_quorum_check = section.windows(10).any(|w| {
                w.contains(&0x04) && // DIV (count/total)
                w.contains(&0x10) && // LT (vs threshold)
                w.contains(&0x57)    // JUMPI
            });
            
            if has_oracle_read && !has_quorum_check {
                vulnerabilities.push(ChronicleVulnerability::ValidatorQuorumBypass {
                    description: format!("Chronicle validator quorum not verified at PC {}. Chronicle uses validator set (13 feeds typical). Quorum = minimum validators that must sign. Risk: If only 1/13 validators updates → price accepted → manipulation. Example: Attacker compromises 1 validator → submits fake price → protocol uses it if no quorum check. Require: bar >= MIN_QUORUM (e.g., 8/13 = 61%).", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
