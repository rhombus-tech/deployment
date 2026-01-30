use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PancakeswapV3PositionManagerVulnerability {
    PositionManipulation { description: String, location: usize, confidence: f32 },
    UnauthorizedPositionAccess { description: String, location: usize, confidence: f32 },
    FeeCollectionExploit { description: String, location: usize, confidence: f32 },
}

pub struct PancakeswapV3PositionManagerDetector {
    bytecode: Vec<u8>,
}

impl PancakeswapV3PositionManagerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PancakeswapV3PositionManagerVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_positions() && !self.validates_position_owner() {
            vulnerabilities.push(PancakeswapV3PositionManagerVulnerability::PositionManipulation {
                description: "Position management without owner validation - position manipulation".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.modifies_position() && !self.checks_authorization() {
            vulnerabilities.push(PancakeswapV3PositionManagerVulnerability::UnauthorizedPositionAccess {
                description: "Position modification without authorization - unauthorized access".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.collects_fees() && !self.validates_fee_recipient() {
            vulnerabilities.push(PancakeswapV3PositionManagerVulnerability::FeeCollectionExploit {
                description: "Fee collection without recipient validation - fee theft".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_positions(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 4 && sload_count > 5 && sha3_count > 2
    }
    
    fn validates_position_owner(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 5 && caller_count > 0 && eq_count > 3
    }
    
    fn modifies_position(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        sstore_count > 3 && (add_count + sub_count) > 3
    }
    
    fn checks_authorization(&self) -> bool {
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        caller_count > 0 && eq_count > 2 && jumpi_count > 2 && revert_count > 1
    }
    
    fn collects_fees(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        call_count > 2 && sload_count > 4
    }
    
    fn validates_fee_recipient(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 5 && eq_count > 2 && iszero_count > 1
    }
}
