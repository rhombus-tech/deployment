use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogDataManipulationVulnerability {
    FakeEventEmission { description: String, location: usize, confidence: f32 },
    UntrustedLogData { description: String, location: usize },
}

pub struct LogDataManipulationDetector {
    bytecode: Vec<u8>,
}

impl LogDataManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LogDataManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // LOG0-LOG4 opcodes (0xA0-0xA4)
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] >= 0xA0 && self.bytecode[i] <= 0xA4 {
                // Check if event data comes from user input without validation
                if self.has_unvalidated_input(i, 30) {
                    vulnerabilities.push(LogDataManipulationVulnerability::UntrustedLogData {
                        description: "Event emits unvalidated user input - log manipulation risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_unvalidated_input(&self, location: usize, lookback: usize) -> bool {
        let start = location.saturating_sub(lookback);
        // CALLDATALOAD without subsequent validation (EQ, LT, GT checks)
        let has_calldataload = self.bytecode[start..location].iter().any(|&b| b == 0x35);
        let has_validation = self.bytecode[start..location].iter().any(|&b| {
            b == 0x14 || b == 0x10 || b == 0x11 // EQ, LT, GT
        });
        has_calldataload && !has_validation
    }
}
