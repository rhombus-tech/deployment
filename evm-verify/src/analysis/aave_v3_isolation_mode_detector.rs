use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AaveV3IsolationModeVulnerability {
    IsolationModeBypass { description: String, location: usize, confidence: f32 },
    DebtCeilingViolation { description: String, location: usize, confidence: f32 },
    CrossCollateralRisk { description: String, location: usize, confidence: f32 },
}

pub struct AaveV3IsolationModeDetector {
    bytecode: Vec<u8>,
}

impl AaveV3IsolationModeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AaveV3IsolationModeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.checks_isolation_mode() && !self.enforces_restrictions() {
            vulnerabilities.push(AaveV3IsolationModeVulnerability::IsolationModeBypass {
                description: "Isolation mode check without enforcement - mode bypass".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.tracks_debt() && !self.validates_debt_ceiling() {
            vulnerabilities.push(AaveV3IsolationModeVulnerability::DebtCeilingViolation {
                description: "Debt tracking without ceiling validation - debt ceiling breach".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.allows_collateral() && !self.checks_isolation_compatibility() {
            vulnerabilities.push(AaveV3IsolationModeVulnerability::CrossCollateralRisk {
                description: "Collateral allowed without isolation check - cross-collateral risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn checks_isolation_mode(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let and_count = self.bytecode.iter().filter(|&&b| b == 0x16).count();
        sload_count > 4 && and_count > 2
    }
    
    fn enforces_restrictions(&self) -> bool {
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        iszero_count > 2 && jumpi_count > 3 && revert_count > 1
    }
    
    fn tracks_debt(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sload_count > 5 && add_count > 2
    }
    
    fn validates_debt_ceiling(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 6 && lt_count > 1 && jumpi_count > 3
    }
    
    fn allows_collateral(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sstore_count > 3 && sload_count > 4
    }
    
    fn checks_isolation_compatibility(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 5 && eq_count > 3 && iszero_count > 2
    }
}
