use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofMarketManipulationDetectorVulnerability {
    ProofPriceManipulation { description: String, location: usize },
}

pub struct ProofMarketManipulationDetector { bytecode: Vec<u8> }

impl ProofMarketManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ProofMarketManipulationDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        // Check for proof bidding/pricing
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x04 { // DIV (price calculation)
                // Check for min/max price bounds
                let has_bounds = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .windows(2).filter(|w| w[0] == 0x10 || w[0] == 0x11).count() >= 2;
                if !has_bounds {
                    vulnerabilities.push(ProofMarketManipulationDetectorVulnerability::ProofPriceManipulation {
                        description: "Proof pricing without bounds".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}