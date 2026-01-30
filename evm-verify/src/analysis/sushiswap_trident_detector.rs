use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SushiswapTridentVulnerability {
    PoolTypeConfusion { description: String, location: usize, confidence: f32 },
    BentoBoxIntegrationRisk { description: String, location: usize, confidence: f32 },
    RouterManipulation { description: String, location: usize, confidence: f32 },
}

pub struct SushiswapTridentDetector {
    bytecode: Vec<u8>,
}

impl SushiswapTridentDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SushiswapTridentVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.handles_multiple_pool_types() && !self.validates_pool_type() {
            vulnerabilities.push(SushiswapTridentVulnerability::PoolTypeConfusion {
                description: "Multiple pool types without validation - pool type confusion".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.interacts_with_bentobox() && !self.validates_bento_state() {
            vulnerabilities.push(SushiswapTridentVulnerability::BentoBoxIntegrationRisk {
                description: "BentoBox interaction without state validation - integration risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_router() && !self.validates_route() {
            vulnerabilities.push(SushiswapTridentVulnerability::RouterManipulation {
                description: "Router usage without route validation - manipulation risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn handles_multiple_pool_types(&self) -> bool {
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        jumpi_count > 5 && eq_count > 4
    }
    
    fn validates_pool_type(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let and_count = self.bytecode.iter().filter(|&&b| b == 0x16).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        sload_count > 4 && and_count > 1 && revert_count > 1
    }
    
    fn interacts_with_bentobox(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        call_count > 3 && sload_count > 5
    }
    
    fn validates_bento_state(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        staticcall_count > 2 && iszero_count > 1 && jumpi_count > 3
    }
    
    fn uses_router(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        call_count > 2 && jumpi_count > 4
    }
    
    fn validates_route(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 5 && eq_count > 3 && gt_count > 1
    }
}
