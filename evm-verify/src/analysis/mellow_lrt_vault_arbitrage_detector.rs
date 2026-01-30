use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MellowLrtVaultArbitrageVulnerability {
    DelayedPriceUpdate { description: String, location: usize, confidence: f32 },
    CrossVaultArbitrage { description: String, location: usize, confidence: f32 },
    SharePriceManipulation { description: String, location: usize, confidence: f32 },
}

pub struct MellowLrtVaultArbitrageDetector {
    bytecode: Vec<u8>,
}

impl MellowLrtVaultArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MellowLrtVaultArbitrageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.updates_share_price() && !self.uses_twap() {
            vulnerabilities.push(MellowLrtVaultArbitrageVulnerability::DelayedPriceUpdate {
                description: "Share price update without TWAP - flash loan manipulation".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.allows_cross_vault_ops() && !self.checks_price_consistency() {
            vulnerabilities.push(MellowLrtVaultArbitrageVulnerability::CrossVaultArbitrage {
                description: "Cross-vault operations without price consistency - arbitrage opportunity".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.calculates_shares() && !self.protects_against_inflation() {
            vulnerabilities.push(MellowLrtVaultArbitrageVulnerability::SharePriceManipulation {
                description: "Share calculation without inflation protection - first depositor attack".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn updates_share_price(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        mul_count > 3 && div_count > 2 && sstore_count > 2
    }
    
    fn uses_twap(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        sload_count > 5 && add_count > 4 && div_count > 3
    }
    
    fn allows_cross_vault_ops(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        call_count > 3
    }
    
    fn checks_price_consistency(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        staticcall_count > 2 && (lt_count + gt_count) > 3
    }
    
    fn calculates_shares(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 2 && div_count > 1
    }
    
    fn protects_against_inflation(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        gt_count > 2 && jumpi_count > 3 && sload_count > 4
    }
}
