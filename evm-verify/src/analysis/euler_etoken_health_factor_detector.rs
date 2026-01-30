use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EulerEtokenHealthFactorVulnerability {
    HealthFactorManipulation { description: String, location: usize, confidence: f32 },
    StaleHealthFactorCalculation { description: String, location: usize, confidence: f32 },
    HealthFactorBypass { description: String, location: usize, confidence: f32 },
}

pub struct EulerEtokenHealthFactorDetector {
    bytecode: Vec<u8>,
}

impl EulerEtokenHealthFactorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EulerEtokenHealthFactorVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.calculates_health_factor() && !self.uses_fresh_prices() {
            vulnerabilities.push(EulerEtokenHealthFactorVulnerability::HealthFactorManipulation {
                description: "Health factor calculation without fresh prices - manipulation risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.checks_health_factor() && !self.validates_oracle_update() {
            vulnerabilities.push(EulerEtokenHealthFactorVulnerability::StaleHealthFactorCalculation {
                description: "Health factor check without oracle validation - stale data risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.enforces_health_factor() && !self.prevents_reentrant_calculation() {
            vulnerabilities.push(EulerEtokenHealthFactorVulnerability::HealthFactorBypass {
                description: "Health factor enforcement without reentrancy guard - bypass risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn calculates_health_factor(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        mul_count > 3 && div_count > 2 && sload_count > 5
    }
    
    fn uses_fresh_prices(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        staticcall_count > 2 && timestamp_count > 0
    }
    
    fn checks_health_factor(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        lt_count > 2 && jumpi_count > 3
    }
    
    fn validates_oracle_update(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        sload_count > 6 && timestamp_count > 0 && sub_count > 1
    }
    
    fn enforces_health_factor(&self) -> bool {
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        revert_count > 1 && jumpi_count > 3
    }
    
    fn prevents_reentrant_calculation(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 6 && sstore_count > 4 && iszero_count > 2
    }
}
