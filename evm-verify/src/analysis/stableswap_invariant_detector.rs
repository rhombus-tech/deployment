use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StableswapInvariantVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct StableswapInvariantDetector {
    bytecode: Vec<u8>,
}

impl StableswapInvariantDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StableswapInvariantVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // Curve-style stableswap invariant violations
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x0a { // EXP (D calculation)
                let complex_calc = self.bytecode[i..i+40]
                    .windows(2)
                    .filter(|w| w[0] == 0x02 || w[0] == 0x04) // MUL or DIV
                    .count() > 5;
                if complex_calc {
                    let has_precision_check = self.bytecode[i..i+40]
                        .iter()
                        .any(|&b| b == 0x10); // LT
                    if !has_precision_check {
                        vulnerabilities.push(StableswapInvariantVulnerability::High {
                            description: "Stableswap invariant calculation without precision checks".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        vulnerabilities
    
    }
}
