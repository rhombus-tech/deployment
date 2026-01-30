use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpTaylorOverflowVulnerability {
    TaylorSeriesOverflow {
        description: String,
        location: usize,
        confidence: f32,
    },
    NoOverflowCheck {
        description: String,
        location: usize,
    },
}

pub struct ExpTaylorOverflowDetector {
    bytecode: Vec<u8>,
}

impl ExpTaylorOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ExpTaylorOverflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_exponential_calculation(i) {
                let has_overflow_check = self.has_overflow_protection(i, i + 150);
                
                if !has_overflow_check {
                    vulnerabilities.push(ExpTaylorOverflowVulnerability::NoOverflowCheck {
                        description: "Exponential Taylor series without overflow check".to_string(),
                        location: i,
                    });
                }
                
                let uses_unsafe_bounds = self.uses_unsafe_input_bounds(i, i + 150);
                if uses_unsafe_bounds {
                    vulnerabilities.push(ExpTaylorOverflowVulnerability::TaylorSeriesOverflow {
                        description: "Exponential with unbounded input can overflow".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_exponential_calculation(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        let exp_count = self.bytecode[location..location + 50].iter().filter(|&&b| b == 0x0a).count();
        let mul_count = self.bytecode[location..location + 50].iter().filter(|&&b| b == 0x02).count();
        
        exp_count >= 2 && mul_count >= 3
    }
    
    fn has_overflow_protection(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x10 && w[1] == 0x15 && w[2] == 0xfd
        })
    }
    
    fn uses_unsafe_input_bounds(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        !self.bytecode[start..range_end].iter().any(|&b| b == 0x10 || b == 0x11)
    }
}
