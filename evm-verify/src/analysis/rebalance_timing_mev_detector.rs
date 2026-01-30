use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RebalanceTimingMevDetectorVulnerability {
    PredictableRebalance { description: String, location: usize },
}

pub struct RebalanceTimingMevDetector { bytecode: Vec<u8> }

impl RebalanceTimingMevDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<RebalanceTimingMevDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let followed_by_mod = self.bytecode[i..std::cmp::min(i+15, self.bytecode.len())]
                    .iter().any(|&b| b == 0x06); // MOD (periodic check)
                if followed_by_mod {
                    let has_randomness = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                        .iter().any(|&b| b == 0x40); // BLOCKHASH
                    if !has_randomness {
                        vulnerabilities.push(RebalanceTimingMevDetectorVulnerability::PredictableRebalance {
                            description: "Rebalance timing is predictable".to_string(), location: i,
                        });
                        break;
                    }
                }
            }
        }
        vulnerabilities
    }
}