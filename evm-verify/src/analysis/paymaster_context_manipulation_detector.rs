use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymasterContextManipulationVulnerability {
    UntrustedContextData { description: String, location: usize },
    NoContextValidation { description: String, location: usize, confidence: f32 },
    ContextReplayAttack { description: String, location: usize },
}

pub struct PaymasterContextManipulationDetector {
    bytecode: Vec<u8>,
}

impl PaymasterContextManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PaymasterContextManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_paymaster_validation(i) {
                if !self.validates_context(i, i + 120) {
                    vulnerabilities.push(PaymasterContextManipulationVulnerability::NoContextValidation {
                        description: "Paymaster accepts context without validation - manipulation risk".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                if self.uses_context_in_postop(i, i + 120) && !self.has_context_integrity_check(i, i + 120) {
                    vulnerabilities.push(PaymasterContextManipulationVulnerability::UntrustedContextData {
                        description: "postOp uses context data without integrity verification".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_paymaster_validation(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // validatePaymasterUserOp selector: 0xf465c77e
        self.bytecode[location..location + 20].windows(4).any(|w| w == [0xf4, 0x65, 0xc7, 0x7e])
    }
    
    fn validates_context(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for context validation (keccak256 or signature check)
        self.bytecode[start..range_end].iter().any(|&b| b == 0x20) // KECCAK256
    }
    
    fn uses_context_in_postop(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // postOp selector: 0xa9a23409
        self.bytecode[start..range_end].windows(4).any(|w| w == [0xa9, 0xa2, 0x34, 0x09])
    }
    
    fn has_context_integrity_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Should verify context matches what was returned in validation
        self.bytecode[start..range_end].windows(2).any(|w| {
            w[0] == 0x14 && w[1] == 0xFD // EQ + REVERT
        })
    }
}
