use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RebasingTokenAccountingVulnerability {
    BalanceChangeWithoutTransfer { description: String, location: usize, confidence: f32 },
    NoSharesTracking { description: String, location: usize },
    RebaseNotHandled { description: String, location: usize },
    InternalBalanceNotScaled { description: String, location: usize },
}

pub struct RebasingTokenAccountingDetector {
    bytecode: Vec<u8>,
}

impl RebasingTokenAccountingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RebasingTokenAccountingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.handles_erc20_tokens() {
            if !self.uses_shares_accounting() {
                vulnerabilities.push(RebasingTokenAccountingVulnerability::NoSharesTracking {
                    description: "ERC20 integration without shares-based accounting - rebasing token risk".to_string(),
                    location: 0,
                });
            }
            
            for i in 0..self.bytecode.len().saturating_sub(100) {
                if self.stores_balance_directly(i, i + 100) {
                    vulnerabilities.push(RebasingTokenAccountingVulnerability::InternalBalanceNotScaled {
                        description: "Stores token balance directly without scaling factor - rebasing will break accounting".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn handles_erc20_tokens(&self) -> bool {
        // transferFrom selector: 0x23b872dd, transfer: 0xa9059cbb
        self.bytecode.windows(4).any(|w| {
            w == [0x23, 0xb8, 0x72, 0xdd] || w == [0xa9, 0x05, 0x9c, 0xbb]
        })
    }
    
    fn uses_shares_accounting(&self) -> bool {
        // Look for share conversion logic: balanceOf * totalShares / totalSupply pattern
        let has_mul = self.bytecode.iter().any(|&b| b == 0x02);
        let has_div = self.bytecode.iter().any(|&b| b == 0x04);
        
        // Multiple MUL and DIV suggest shares conversion
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        
        has_mul && has_div && mul_count >= 2 && div_count >= 2
    }
    
    fn stores_balance_directly(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: balanceOf() followed by SSTORE without conversion
        let mut has_balance_of = false;
        
        for i in start..range_end.saturating_sub(10) {
            // balanceOf selector: 0x70a08231
            if self.bytecode[i..].get(0..4) == Some(&[0x70, 0xa0, 0x82, 0x31]) {
                has_balance_of = true;
            }
            
            // If balanceOf followed by SSTORE within 10 bytes (no conversion)
            if has_balance_of && i < range_end && self.bytecode[i] == 0x55 {
                // Check no MUL/DIV between balanceOf and SSTORE
                let between = &self.bytecode[i.saturating_sub(10)..i];
                if !between.contains(&0x02) && !between.contains(&0x04) {
                    return true;
                }
            }
        }
        
        false
    }
}
