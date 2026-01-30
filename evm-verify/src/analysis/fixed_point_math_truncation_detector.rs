use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FixedPointMathTruncationVulnerability {
    NoScalingFactor { description: String, location: usize, confidence: f32 },
    TruncationInConversion { description: String, location: usize },
    PrecisionLossInDivision { description: String, location: usize },
}

pub struct FixedPointMathTruncationDetector {
    bytecode: Vec<u8>,
}

impl FixedPointMathTruncationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<FixedPointMathTruncationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.is_fixed_point_operation(i, i + 60) {
                if !self.uses_proper_scaling(i, i + 60) {
                    vulnerabilities.push(FixedPointMathTruncationVulnerability::TruncationInConversion {
                        description: "Fixed-point math without proper scaling - precision loss".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_fixed_point_operation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Fixed point uses large constants like 1e18
        for i in start..range_end.saturating_sub(10) {
            if self.bytecode[i] == 0x6B { // PUSH12 (1e18 needs 12 bytes)
                return true;
            }
        }
        
        false
    }
    
    fn uses_proper_scaling(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Proper scaling: multiply before divide
        let mut has_mul_before_div = false;
        
        for i in start..range_end.saturating_sub(5) {
            if self.bytecode[i] == 0x02 { // MUL
                for j in i+1..i.saturating_add(5).min(range_end) {
                    if self.bytecode[j] == 0x04 { // DIV
                        has_mul_before_div = true;
                        break;
                    }
                }
            }
        }
        
        has_mul_before_div
    }
}
