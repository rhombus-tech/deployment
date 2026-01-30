use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RocketPoolMinipoolDelegateVulnerability {
    UnsafeDelegateUpgrade { description: String, location: usize, confidence: f32 },
    MinipoolStateManipulation { description: String, location: usize, confidence: f32 },
    DelegateCallWithoutValidation { description: String, location: usize, confidence: f32 },
}

pub struct RocketPoolMinipoolDelegateDetector {
    bytecode: Vec<u8>,
}

impl RocketPoolMinipoolDelegateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RocketPoolMinipoolDelegateVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.upgrades_delegate() && !self.requires_guardian() {
            vulnerabilities.push(RocketPoolMinipoolDelegateVulnerability::UnsafeDelegateUpgrade {
                description: "Minipool delegate upgrade without guardian approval - unauthorized upgrade".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.manages_minipool_state() && !self.validates_state_transition() {
            vulnerabilities.push(RocketPoolMinipoolDelegateVulnerability::MinipoolStateManipulation {
                description: "Minipool state change without validation - invalid state transition".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_delegatecall() && !self.validates_target() {
            vulnerabilities.push(RocketPoolMinipoolDelegateVulnerability::DelegateCallWithoutValidation {
                description: "Delegatecall without target validation - malicious delegate risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn upgrades_delegate(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let delegatecall_count = self.bytecode.iter().filter(|&&b| b == 0xF4).count();
        sstore_count > 2 && delegatecall_count > 0
    }
    
    fn requires_guardian(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        sload_count > 3 && eq_count > 2 && caller_count > 1
    }
    
    fn manages_minipool_state(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 3 && log_count > 1
    }
    
    fn validates_state_transition(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 4 && eq_count > 3 && jumpi_count > 4
    }
    
    fn uses_delegatecall(&self) -> bool {
        let delegatecall_count = self.bytecode.iter().filter(|&&b| b == 0xF4).count();
        delegatecall_count > 0
    }
    
    fn validates_target(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 2 && eq_count > 2 && iszero_count > 1
    }
}
