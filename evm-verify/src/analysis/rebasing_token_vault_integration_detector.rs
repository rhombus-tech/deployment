use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RebasingTokenVaultIntegrationVulnerability {
    SharePriceManipulation { description: String, location: usize, confidence: f32 },
    RebaseIgnored { description: String, location: usize, confidence: f32 },
    AccountingMismatch { description: String, location: usize, confidence: f32 },
}

pub struct RebasingTokenVaultIntegrationDetector {
    bytecode: Vec<u8>,
}

impl RebasingTokenVaultIntegrationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RebasingTokenVaultIntegrationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.handles_rebasing_tokens() && !self.tracks_share_adjustments() {
            vulnerabilities.push(RebasingTokenVaultIntegrationVulnerability::SharePriceManipulation {
                description: "Rebasing token in vault without share adjustment tracking - manipulation risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.has_balance_queries() && self.stores_balances() && !self.adjusts_for_rebase() {
            vulnerabilities.push(RebasingTokenVaultIntegrationVulnerability::RebaseIgnored {
                description: "Stored balances not adjusted for token rebase - accounting error".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.calculates_shares() && self.uses_total_supply() && !self.handles_supply_changes() {
            vulnerabilities.push(RebasingTokenVaultIntegrationVulnerability::AccountingMismatch {
                description: "Share calculation using total supply without rebase handling - mismatch risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn handles_rebasing_tokens(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        staticcall_count > 2 && mul_count > 5 && div_count > 3
    }
    
    fn tracks_share_adjustments(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        sload_count > 5 && sstore_count > 3 && mul_count > 8
    }
    
    fn has_balance_queries(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 1
    }
    
    fn stores_balances(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sstore_count > 2
    }
    
    fn adjusts_for_rebase(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        mul_count > 4 && div_count > 2 && sload_count > 4
    }
    
    fn calculates_shares(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 3 && div_count > 2
    }
    
    fn uses_total_supply(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 0
    }
    
    fn handles_supply_changes(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        timestamp_count > 1 && sub_count > 3
    }
}
