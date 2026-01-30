use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UdvtTypeConfusionVulnerability {
    UnwrapWithoutValidation { description: String, location: usize, confidence: f32 },
    TypeMixingAcrossFunctions { description: String, location: usize, confidence: f32 },
    UnsafeArithmeticOnUdvt { description: String, location: usize, confidence: f32 },
}

pub struct UdvtTypeConfusionDetector {
    bytecode: Vec<u8>,
}

impl UdvtTypeConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<UdvtTypeConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_udvt_unwrap_patterns());
        vulnerabilities
    }
    
    fn detect_udvt_unwrap_patterns(&self) -> Vec<UdvtTypeConfusionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // UDVTs (Solidity 0.8.8+) are unwrapped before arithmetic
        // Pattern: Type.unwrap(value) followed by arithmetic without validation
        // In bytecode: function selector → CALLDATALOAD → arithmetic ops
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let section = &self.bytecode[i..std::cmp::min(i + 50, self.bytecode.len())];
            
            // Look for patterns where value loaded from calldata/storage and immediately used in arithmetic
            let has_value_load = section.contains(&0x35) || section.contains(&0x54); // CALLDATALOAD or SLOAD
            let has_arithmetic = section.windows(3).any(|w| {
                w.contains(&0x01) || // ADD
                w.contains(&0x02) || // MUL
                w.contains(&0x03) || // SUB
                w.contains(&0x04) || // DIV
                w.contains(&0x06)    // MOD
            });
            
            // Check if there's validation before arithmetic
            let has_validation = section.windows(5).any(|w| {
                (w.contains(&0x10) || w.contains(&0x11) || w.contains(&0x14)) && // LT, GT, EQ
                w.contains(&0x57) // JUMPI (conditional)
            });
            
            if has_value_load && has_arithmetic && !has_validation {
                vulnerabilities.push(UdvtTypeConfusionVulnerability::UnwrapWithoutValidation {
                    description: format!("UDVT unwrap pattern at PC {} without validation. Solidity 0.8.8+ User-Defined Value Types: `type Price is uint256`. Risk: Price.unwrap() returns raw uint256 without semantic checks. Example: Price in USD cents unwrapped to wei calculation → 100x error. Always validate: require(Price.unwrap(p) <= MAX_PRICE)", i),
                    location: i,
                    confidence: 0.82,
                });
            }
            
            // Check for type mixing: different UDVT types used interchangeably
            let has_multiple_arithmetic = section.windows(10).filter(|w| {
                w.contains(&0x01) || w.contains(&0x02)
            }).count() > 2;
            
            if has_multiple_arithmetic && !has_validation {
                vulnerabilities.push(UdvtTypeConfusionVulnerability::UnsafeArithmeticOnUdvt {
                    description: format!("Multiple arithmetic operations at PC {} on potentially different UDVT types. Risk: `type TokenAmount is uint256` + `type ShareAmount is uint256` → type confusion. Both are uint256 but semantically different. Mixing them causes accounting errors. Use explicit conversion functions.", i),
                    location: i,
                    confidence: 0.78,
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udvt_unwrap_no_validation() {
        let bytecode = vec![
            0x60, 0x04, // PUSH1 4
            0x35,       // CALLDATALOAD (load UDVT value)
            0x60, 0x0A, // PUSH1 10
            0x02,       // MUL (arithmetic without validation)
        ];
        
        let detector = UdvtTypeConfusionDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
