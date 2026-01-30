use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReturndatacopyBombVulnerability {
    UnboundedReturndatacopy { description: String, location: usize, confidence: f32 },
    NoReturnSizeCheck { description: String, location: usize },
    MaliciousContractVector { description: String, location: usize },
}

pub struct ReturndatacopyBombDetector {
    bytecode: Vec<u8>,
}

impl ReturndatacopyBombDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReturndatacopyBombVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x3E { // RETURNDATACOPY
                if !self.has_size_limit_before(i) {
                    vulnerabilities.push(ReturndatacopyBombVulnerability::UnboundedReturndatacopy {
                        description: "RETURNDATACOPY without size limit - malicious contract can return huge data".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                if !self.validates_return_size(i) {
                    vulnerabilities.push(ReturndatacopyBombVulnerability::NoReturnSizeCheck {
                        description: "No validation of RETURNDATASIZE before copy - DoS vector".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_size_limit_before(&self, location: usize) -> bool {
        let start = location.saturating_sub(20);
        // Check for size comparison before RETURNDATACOPY
        self.bytecode[start..location].iter().any(|&b| b == 0x10 || b == 0x11) // LT or GT
    }
    
    fn validates_return_size(&self, location: usize) -> bool {
        let start = location.saturating_sub(15);
        // RETURNDATASIZE opcode: 0x3D
        self.bytecode[start..location].iter().any(|&b| b == 0x3D)
    }
}
