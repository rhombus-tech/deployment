use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogarithmicApproximationErrorVulnerability {
    FixedPointLogError { description: String, location: usize, confidence: f32 },
}

pub struct LogarithmicApproximationErrorDetector {
    bytecode: Vec<u8>,
}

impl LogarithmicApproximationErrorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LogarithmicApproximationErrorVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_log_operations() && !self.has_precision_checks() {
            vulnerabilities.push(LogarithmicApproximationErrorVulnerability::FixedPointLogError {
                description: "Fixed-point logarithm approximation vulnerable to precision errors".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_log_operations(&self) -> bool {
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        div_count > 5 && mul_count > 5
    }
    
    fn has_precision_checks(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gt_count > 3
    }
}
