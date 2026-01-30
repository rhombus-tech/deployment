use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymasterGasDrainVulnerability {
    NoRateLimiting { description: String, location: usize, confidence: f32 },
    UnboundedGasSponsorship { description: String, location: usize },
    NoUserValidation { description: String, location: usize },
}

pub struct PaymasterGasDrainDetector {
    bytecode: Vec<u8>,
}

impl PaymasterGasDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PaymasterGasDrainVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // validatePaymasterUserOp selector (ERC-4337): 0xf465c77e
        let validate_paymaster = [0xf4, 0x65, 0xc7, 0x7e];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == validate_paymaster) {
                if !self.has_rate_limiting(i, i + 100) {
                    vulnerabilities.push(PaymasterGasDrainVulnerability::NoRateLimiting {
                        description: "Paymaster without rate limiting - gas drainage attack".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if !self.validates_user(i, i + 100) {
                    vulnerabilities.push(PaymasterGasDrainVulnerability::NoUserValidation {
                        description: "Paymaster sponsors any user - no whitelist/validation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_rate_limiting(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Rate limiting: TIMESTAMP check + storage tracking
        let has_timestamp = self.bytecode[start..range_end].iter().any(|&b| b == 0x42);
        let has_storage = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        has_timestamp && has_storage
    }
    
    fn validates_user(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // User validation: CALLER check + comparison
        let has_caller = self.bytecode[start..range_end].iter().any(|&b| b == 0x33);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        has_caller && has_eq
    }
}
