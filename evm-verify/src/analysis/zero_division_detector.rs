use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZeroDivisionVulnerability {
    DivisionByZero { description: String, location: usize, confidence: f32 },
    ModuloByZero { description: String, location: usize, confidence: f32 },
}

pub struct ZeroDivisionDetector {
    bytecode: Vec<u8>,
}

impl ZeroDivisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ZeroDivisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x04 { // DIV
                if !self.has_zero_check_before(i) {
                    vulnerabilities.push(ZeroDivisionVulnerability::DivisionByZero {
                        description: "Division without zero check - DoS via revert".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
            
            if self.bytecode[i] == 0x06 { // MOD
                if !self.has_zero_check_before(i) {
                    vulnerabilities.push(ZeroDivisionVulnerability::ModuloByZero {
                        description: "Modulo without zero check - DoS via revert".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_zero_check_before(&self, operation_location: usize) -> bool {
        let start = operation_location.saturating_sub(20);
        let has_iszero = self.bytecode[start..operation_location].iter().any(|&b| b == 0x15);
        let has_revert = self.bytecode[start..operation_location].iter().any(|&b| b == 0xFD);
        has_iszero && has_revert
    }
}
