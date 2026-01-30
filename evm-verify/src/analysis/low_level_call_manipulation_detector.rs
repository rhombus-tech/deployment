use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LowLevelCallManipulationVulnerability {
    UncheckedCallReturn { description: String, location: usize, confidence: f32 },
    CalldataManipulation { description: String, location: usize },
    DelegatecallRisk { description: String, location: usize },
}

pub struct LowLevelCallManipulationDetector {
    bytecode: Vec<u8>,
}

impl LowLevelCallManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LowLevelCallManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0xF1 | 0xFA => { // CALL, STATICCALL
                    if !self.checks_return_value(i) {
                        vulnerabilities.push(LowLevelCallManipulationVulnerability::UncheckedCallReturn {
                            description: "Low-level call without return value check - silent failure risk".to_string(),
                            location: i,
                            confidence: 0.90,
                        });
                    }
                },
                0xF4 => { // DELEGATECALL
                    if self.has_user_controlled_data(i) {
                        vulnerabilities.push(LowLevelCallManipulationVulnerability::DelegatecallRisk {
                            description: "Delegatecall with user-controlled data - code injection risk".to_string(),
                            location: i,
                        });
                    }
                },
                _ => {}
            }
        }
        
        vulnerabilities
    }
    
    fn checks_return_value(&self, call_location: usize) -> bool {
        let check_end = (call_location + 10).min(self.bytecode.len());
        // ISZERO + JUMPI pattern after call
        self.bytecode[call_location..check_end].windows(2).any(|w| w[0] == 0x15 && w[1] == 0x57)
    }
    
    fn has_user_controlled_data(&self, call_location: usize) -> bool {
        let start = call_location.saturating_sub(20);
        // CALLDATALOAD before delegatecall
        self.bytecode[start..call_location].iter().any(|&b| b == 0x35)
    }
}
