use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalancerV3PoolCreationVulnerability {
    UnvalidatedPoolParameters { description: String, location: usize, confidence: f32 },
    PoolFactoryBypass { description: String, location: usize, confidence: f32 },
    MaliciousPoolRegistration { description: String, location: usize, confidence: f32 },
}

pub struct BalancerV3PoolCreationDetector {
    bytecode: Vec<u8>,
}

impl BalancerV3PoolCreationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BalancerV3PoolCreationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.creates_pool() && !self.validates_parameters() {
            vulnerabilities.push(BalancerV3PoolCreationVulnerability::UnvalidatedPoolParameters {
                description: "Pool creation without parameter validation - invalid pool config".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.registers_pool() && !self.checks_factory_authorization() {
            vulnerabilities.push(BalancerV3PoolCreationVulnerability::PoolFactoryBypass {
                description: "Pool registration without factory check - unauthorized pool".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.adds_to_registry() && !self.validates_pool_contract() {
            vulnerabilities.push(BalancerV3PoolCreationVulnerability::MaliciousPoolRegistration {
                description: "Pool registry addition without contract validation - malicious pool".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn creates_pool(&self) -> bool {
        let create_count = self.bytecode.iter().filter(|&&b| b == 0xF0).count();
        let create2_count = self.bytecode.iter().filter(|&&b| b == 0xF5).count();
        (create_count + create2_count) > 0
    }
    
    fn validates_parameters(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        (gt_count + lt_count) > 3 && jumpi_count > 3 && revert_count > 1
    }
    
    fn registers_pool(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 3 && log_count > 1
    }
    
    fn checks_factory_authorization(&self) -> bool {
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        caller_count > 0 && eq_count > 2 && sload_count > 3
    }
    
    fn adds_to_registry(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 2 && sha3_count > 1
    }
    
    fn validates_pool_contract(&self) -> bool {
        let extcodesize_count = self.bytecode.iter().filter(|&&b| b == 0x3B).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        extcodesize_count > 0 && iszero_count > 1 && staticcall_count > 1
    }
}
