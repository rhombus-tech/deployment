use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7412PullOracleVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct Erc7412PullOracleDetector {
    bytecode: Vec<u8>,
}

impl Erc7412PullOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc7412PullOracleVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // Pull oracle without staleness check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 { // CALL (external oracle call)
                let has_timestamp_check = self.bytecode[i+5..i+20]
                    .iter()
                    .any(|&b| b == 0x42); // TIMESTAMP
                if !has_timestamp_check {
                    vulnerabilities.push(Erc7412PullOracleVulnerability::High {
                        description: "Pull oracle without staleness validation".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
