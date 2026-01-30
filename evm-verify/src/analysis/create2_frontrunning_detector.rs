use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Create2FrontrunningVulnerability {
    PredictableAddress { description: String, location: usize, confidence: f32 },
    NoSaltRandomization { description: String, location: usize },
    InitCodePublic { description: String, location: usize },
}

pub struct Create2FrontrunningDetector {
    bytecode: Vec<u8>,
}

impl Create2FrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Create2FrontrunningVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // CREATE2 opcode: 0xF5
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF5 {
                if !self.has_random_salt(i) {
                    vulnerabilities.push(Create2FrontrunningVulnerability::NoSaltRandomization {
                        description: "CREATE2 with static salt - address predictable, frontrun risk".to_string(),
                        location: i,
                    });
                }
                
                vulnerabilities.push(Create2FrontrunningVulnerability::PredictableAddress {
                    description: "CREATE2 deployment - attacker can frontrun to same address".to_string(),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_random_salt(&self, create2_location: usize) -> bool {
        let start = create2_location.saturating_sub(30);
        // Random salt uses: TIMESTAMP, BLOCKHASH, DIFFICULTY, etc.
        self.bytecode[start..create2_location].iter().any(|&b| {
            b == 0x42 || // TIMESTAMP
            b == 0x40 || // BLOCKHASH
            b == 0x44    // DIFFICULTY/PREVRANDAO
        })
    }
}
