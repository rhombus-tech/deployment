use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraderJoeLbBinLiquidityVulnerability {
    BinLiquidityImbalance { description: String, location: usize, confidence: f32 },
    LiquidityBookManipulation { description: String, location: usize, confidence: f32 },
    BinIdOverflow { description: String, location: usize, confidence: f32 },
}

pub struct TraderJoeLbBinLiquidityDetector {
    bytecode: Vec<u8>,
}

impl TraderJoeLbBinLiquidityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TraderJoeLbBinLiquidityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_bin_liquidity() && !self.validates_bin_balance() {
            vulnerabilities.push(TraderJoeLbBinLiquidityVulnerability::BinLiquidityImbalance {
                description: "Bin liquidity management without balance check - imbalance risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.updates_liquidity_book() && !self.prevents_manipulation() {
            vulnerabilities.push(TraderJoeLbBinLiquidityVulnerability::LiquidityBookManipulation {
                description: "Liquidity book update without manipulation protection - book manipulation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.calculates_bin_id() && !self.checks_bin_bounds() {
            vulnerabilities.push(TraderJoeLbBinLiquidityVulnerability::BinIdOverflow {
                description: "Bin ID calculation without bounds check - overflow risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_bin_liquidity(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        sstore_count > 4 && add_count > 2 && sub_count > 1
    }
    
    fn validates_bin_balance(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 5 && (lt_count + gt_count) > 2
    }
    
    fn updates_liquidity_book(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 5 && sha3_count > 2
    }
    
    fn prevents_manipulation(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        sload_count > 6 && timestamp_count > 0 && sub_count > 2
    }
    
    fn calculates_bin_id(&self) -> bool {
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        add_count > 2 && div_count > 1
    }
    
    fn checks_bin_bounds(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        lt_count > 1 && jumpi_count > 2 && revert_count > 1
    }
}
