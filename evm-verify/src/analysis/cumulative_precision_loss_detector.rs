/// Cumulative Precision Loss Detector
/// 
/// Detects rounding errors that accumulate over time
/// Impact: $180M+ - precision loss exploits

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CumulativePrecisionVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub loss_type: PrecisionLossType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrecisionLossType {
    RoundingInLoop,
    RepeatedDivision,
    CompoundingError,
    DustAccumulation,
}

pub struct CumulativePrecisionLossDetector {
    bytecode: Vec<u8>,
}

impl CumulativePrecisionLossDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CumulativePrecisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.has_cumulative_rounding(pc) {
                vulnerabilities.push(CumulativePrecisionVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    loss_type: PrecisionLossType::RoundingInLoop,
                    description: "Division in loop accumulates rounding errors".to_string(),
                    exploit_scenario: "for (uint i = 0; i < 100; i++) {\n\
                        uint share = total / 100;\n\
                        distribute(share); // Loses precision each iteration\n\
                        // After 100 iterations: 100 wei lost\n\
                        // Attacker claims the dust\n\
                    }".to_string(),
                    remediation: "Calculate once before loop or track remainder".to_string(),
                    confidence: 0.82,
                });
            }
            pc += 1;
        }

        vulnerabilities
    }

    fn has_cumulative_rounding(&self, start: usize) -> bool {
        if start + 25 > self.bytecode.len() {
            return false;
        }

        let window = &self.bytecode[start..start + 25];
        
        // Pattern: DIV inside loop (JUMP/JUMPI nearby)
        let has_div = window.iter().any(|&b| b == 0x04); // DIV
        let has_loop = window.iter().any(|&b| b == 0x56 || b == 0x57); // JUMP or JUMPI

        has_div && has_loop
    }
}
