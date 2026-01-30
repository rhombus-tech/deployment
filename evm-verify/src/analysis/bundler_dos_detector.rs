use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BundlerDosVulnerability {
    UnboundedUserOpValidation { description: String, location: usize },
    ExpensiveValidation { description: String, location: usize, confidence: f32 },
    ValidationGasGriefing { description: String, location: usize },
}

pub struct BundlerDosDetector {
    bytecode: Vec<u8>,
}

impl BundlerDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BundlerDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_user_op_validation(i) {
                if self.has_unbounded_loop_in_validation(i, i + 100) {
                    vulnerabilities.push(BundlerDosVulnerability::UnboundedUserOpValidation {
                        description: "UserOp validation contains unbounded loop - bundler DoS".to_string(),
                        location: i,
                    });
                }
                
                if self.has_expensive_operations(i, i + 100) {
                    vulnerabilities.push(BundlerDosVulnerability::ExpensiveValidation {
                        description: "Expensive operations in validation phase - can grief bundler".to_string(),
                        location: i,
                        confidence: 0.80,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_user_op_validation(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // validateUserOp: 0x3a871cdd
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0x3a, 0x87, 0x1c, 0xdd])
    }
    
    fn has_unbounded_loop_in_validation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_loop = self.bytecode[start..range_end].iter().any(|&b| b == 0x57); // JUMPI
        let has_limit = self.bytecode[start..range_end].windows(2).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && w[1] == 0xFD
        });
        has_loop && !has_limit
    }
    
    fn has_expensive_operations(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // External calls, CREATE, CREATE2
        self.bytecode[start..range_end].iter().any(|&b| {
            b == 0xF1 || b == 0xFA || b == 0xF0 || b == 0xF5 // CALL, STATICCALL, CREATE, CREATE2
        })
    }
}
