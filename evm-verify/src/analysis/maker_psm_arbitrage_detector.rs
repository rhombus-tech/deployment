use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MakerPsmArbitrageVulnerability {
    PegDeviationArbitrage { description: String, location: usize, confidence: f32 },
    FeeBypassExploit { description: String, location: usize, confidence: f32 },
    FlashMintArbitrage { description: String, location: usize, confidence: f32 },
}

pub struct MakerPsmArbitrageDetector {
    bytecode: Vec<u8>,
}

impl MakerPsmArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MakerPsmArbitrageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.allows_swap() && !self.enforces_peg_bounds() {
            vulnerabilities.push(MakerPsmArbitrageVulnerability::PegDeviationArbitrage {
                description: "PSM swap without peg bounds - arbitrage when off-peg".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.charges_fee() && !self.validates_fee_application() {
            vulnerabilities.push(MakerPsmArbitrageVulnerability::FeeBypassExploit {
                description: "Fee charging without validation - fee bypass possible".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.supports_flash_operations() && !self.prevents_atomic_arbitrage() {
            vulnerabilities.push(MakerPsmArbitrageVulnerability::FlashMintArbitrage {
                description: "Flash operations without atomic arbitrage prevention - flash arbitrage".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn allows_swap(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 2 && sstore_count > 3
    }
    
    fn enforces_peg_bounds(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        mul_count > 2 && div_count > 1 && (lt_count + gt_count) > 2
    }
    
    fn charges_fee(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        mul_count > 2 && div_count > 1 && sub_count > 1
    }
    
    fn validates_fee_application(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 4 && iszero_count > 1 && jumpi_count > 2
    }
    
    fn supports_flash_operations(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        call_count > 3 && sload_count > 5
    }
    
    fn prevents_atomic_arbitrage(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sstore_count > 4 && sload_count > 6 && eq_count > 3
    }
}
