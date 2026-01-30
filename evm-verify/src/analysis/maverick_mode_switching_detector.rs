use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaverickModeSwitchingVulnerability {
    UnsafeModeSwitching { description: String, location: usize, confidence: f32 },
    LiquidityModeExploit { description: String, location: usize, confidence: f32 },
    BinModeManipulation { description: String, location: usize, confidence: f32 },
}

pub struct MaverickModeSwitchingDetector {
    bytecode: Vec<u8>,
}

impl MaverickModeSwitchingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MaverickModeSwitchingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.switches_mode() && !self.validates_mode_change() {
            vulnerabilities.push(MaverickModeSwitchingVulnerability::UnsafeModeSwitching {
                description: "Mode switching without validation - unsafe state transition".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.manages_liquidity() && !self.checks_mode_compatibility() {
            vulnerabilities.push(MaverickModeSwitchingVulnerability::LiquidityModeExploit {
                description: "Liquidity management without mode check - incompatible operation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.adjusts_bins() && !self.validates_bin_state() {
            vulnerabilities.push(MaverickModeSwitchingVulnerability::BinModeManipulation {
                description: "Bin adjustment without state validation - bin manipulation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn switches_mode(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sstore_count > 3 && jumpi_count > 3
    }
    
    fn validates_mode_change(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        sload_count > 5 && eq_count > 3 && revert_count > 1
    }
    
    fn manages_liquidity(&self) -> bool {
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        add_count > 2 && sub_count > 2 && sstore_count > 4
    }
    
    fn checks_mode_compatibility(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let and_count = self.bytecode.iter().filter(|&&b| b == 0x16).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 4 && and_count > 1 && jumpi_count > 2
    }
    
    fn adjusts_bins(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 3 && sha3_count > 2
    }
    
    fn validates_bin_state(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 5 && iszero_count > 2
    }
}
