use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncorrectDecimalHandlingVulnerability {
    DecimalMismatch { description: String, location: usize, confidence: f32, expected: u8, actual: u8 },
    MissingDecimalConversion { description: String, location: usize },
    HardcodedDecimalAssumption { description: String, location: usize },
}

pub struct IncorrectDecimalHandlingDetector {
    bytecode: Vec<u8>,
}

impl IncorrectDecimalHandlingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<IncorrectDecimalHandlingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Common decimal values: 10^18, 10^6, 10^8
        let decimals_18 = vec![0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]; // 10^18
        let decimals_6 = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40]; // 10^6
        
        // Check for hardcoded decimal assumptions
        if self.has_hardcoded_decimals(&decimals_18) {
            vulnerabilities.push(IncorrectDecimalHandlingVulnerability::HardcodedDecimalAssumption {
                description: "Hardcoded 18 decimals - fails with USDC/USDT (6 decimals)".to_string(),
                location: 0,
            });
        }
        
        // Check for missing decimal() call before calculations
        if self.has_price_calculation() && !self.calls_decimals() {
            vulnerabilities.push(IncorrectDecimalHandlingVulnerability::MissingDecimalConversion {
                description: "Price calculation without checking token decimals".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn has_hardcoded_decimals(&self, decimal_bytes: &[u8]) -> bool {
        self.bytecode.windows(decimal_bytes.len()).any(|w| w == decimal_bytes)
    }
    
    fn has_price_calculation(&self) -> bool {
        // Price calc: MUL + DIV pattern
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x02 { // MUL
                if self.bytecode[i..i+10].iter().any(|&b| b == 0x04) { // followed by DIV
                    return true;
                }
            }
        }
        false
    }
    
    fn calls_decimals(&self) -> bool {
        // decimals() selector: 0x313ce567
        let decimals_selector = [0x31, 0x3c, 0xe5, 0x67];
        self.bytecode.windows(4).any(|w| w == decimals_selector)
    }
}
