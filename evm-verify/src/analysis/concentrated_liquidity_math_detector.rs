use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConcentratedLiquidityMathVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct ConcentratedLiquidityMathDetector {
    bytecode: Vec<u8>,
}

impl ConcentratedLiquidityMathDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConcentratedLiquidityMathVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // Uniswap V3 style concentrated liquidity math errors
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x0a { // EXP (for sqrt calculations)
                let has_overflow_check = self.bytecode[i..i+30]
                    .iter()
                    .any(|&b| b == 0x13); // ISZERO (overflow detection)
                if !has_overflow_check {
                    vulnerabilities.push(ConcentratedLiquidityMathVulnerability::High {
                        description: "Concentrated liquidity math without overflow protection".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
