use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SqrtRoundingManipulationVulnerability {
    SqrtWithoutRoundingCheck { description: String, location: usize, confidence: f32 },
    NewtonMethodTruncation { description: String, location: usize },
    SqrtInPriceCalculation { description: String, location: usize },
}

pub struct SqrtRoundingManipulationDetector {
    bytecode: Vec<u8>,
}

impl SqrtRoundingManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SqrtRoundingManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Square root implementations (Newton's method pattern)
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.is_sqrt_implementation(i, i + 80) {
                if !self.validates_rounding(i, i + 80) {
                    vulnerabilities.push(SqrtRoundingManipulationVulnerability::SqrtWithoutRoundingCheck {
                        description: "Square root calculation without rounding validation - manipulable".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_sqrt_implementation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Newton's method: x_new = (x + n/x) / 2
        // Pattern: DIV, ADD, PUSH 2, DIV
        let has_iterative_div = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| w[0] == 0x04 && w[2] == 0x60 && w[3] == 0x02);
        
        has_iterative_div
    }
    
    fn validates_rounding(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Should verify: result * result <= input && (result+1) * (result+1) > input
        let mul_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x02).count();
        mul_count >= 2 // Multiple multiplications suggest validation
    }
}
