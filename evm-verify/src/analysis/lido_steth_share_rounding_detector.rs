use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LidoStethShareRoundingVulnerability {
    RoundingLossAccumulation { description: String, location: usize, confidence: f32 },
    ShareToStethConversion { description: String, location: usize, confidence: f32 },
    RebaseRoundingExploit { description: String, location: usize, confidence: f32 },
}

pub struct LidoStethShareRoundingDetector {
    bytecode: Vec<u8>,
}

impl LidoStethShareRoundingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LidoStethShareRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.performs_division() && !self.checks_remainder() {
            vulnerabilities.push(LidoStethShareRoundingVulnerability::RoundingLossAccumulation {
                description: "Division without remainder checking - rounding dust accumulation".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.converts_shares() && !self.validates_minimum() {
            vulnerabilities.push(LidoStethShareRoundingVulnerability::ShareToStethConversion {
                description: "Share conversion without minimum validation - zero amount exploit".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.handles_rebase() && !self.protects_rounding() {
            vulnerabilities.push(LidoStethShareRoundingVulnerability::RebaseRoundingExploit {
                description: "Rebase handling without rounding protection - rebase manipulation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn performs_division(&self) -> bool {
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        div_count > 2
    }
    
    fn checks_remainder(&self) -> bool {
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        mod_count > 0 && iszero_count > 1
    }
    
    fn converts_shares(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        mul_count > 2 && div_count > 1 && sload_count > 3
    }
    
    fn validates_minimum(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        gt_count > 1 && jumpi_count > 2
    }
    
    fn handles_rebase(&self) -> bool {
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        add_count > 3 && mul_count > 2 && sstore_count > 2
    }
    
    fn protects_rounding(&self) -> bool {
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        mod_count > 1 && add_count > 4 && sstore_count > 3
    }
}
