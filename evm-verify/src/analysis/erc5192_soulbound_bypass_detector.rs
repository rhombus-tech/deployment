use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc5192SoulboundBypassVulnerability {
    TransferNotBlocked { description: String, location: usize, confidence: f32 },
    LockedFlagMutable { description: String, location: usize },
    ApprovalBypassesLock { description: String, location: usize },
    BurnBypassesSoulbound { description: String, location: usize },
}

pub struct Erc5192SoulboundBypassDetector {
    bytecode: Vec<u8>,
}

impl Erc5192SoulboundBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5192SoulboundBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_transfer_function(i) {
                if !self.checks_locked_status(i, i + 120) {
                    vulnerabilities.push(Erc5192SoulboundBypassVulnerability::TransferNotBlocked {
                        description: "Transfer function doesn't check ERC-5192 locked status".to_string(),
                        location: i,
                        confidence: 0.95,
                    });
                }
            }
            
            if self.is_approve_function(i) {
                if !self.blocks_approval_when_locked(i, i + 120) {
                    vulnerabilities.push(Erc5192SoulboundBypassVulnerability::ApprovalBypassesLock {
                        description: "Approval allowed on locked soulbound token".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        if self.has_locked_function() && self.locked_flag_is_mutable() {
            vulnerabilities.push(Erc5192SoulboundBypassVulnerability::LockedFlagMutable {
                description: "Soulbound locked flag can be changed - defeats purpose".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn is_transfer_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // transferFrom: 0x23b872dd, safeTransferFrom: 0x42842e0e
        let selectors = [[0x23, 0xb8, 0x72, 0xdd], [0x42, 0x84, 0x2e, 0x0e]];
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn checks_locked_status(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Should SLOAD locked status and REVERT if locked
        let has_locked_check = self.bytecode[start..range_end].iter().any(|&b| b == 0x54); // SLOAD
        let has_revert = self.bytecode[start..range_end].iter().any(|&b| b == 0xFD);
        
        has_locked_check && has_revert
    }
    
    fn is_approve_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        // approve: 0x095ea7b3, setApprovalForAll: 0xa22cb465
        let selectors = [[0x09, 0x5e, 0xa7, 0xb3], [0xa2, 0x2c, 0xb4, 0x65]];
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn blocks_approval_when_locked(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Should check locked status in approve
        self.bytecode[start..range_end].windows(2).any(|w| {
            w[0] == 0x54 && w[1] == 0xFD // SLOAD + REVERT
        })
    }
    
    fn has_locked_function(&self) -> bool {
        // locked(uint256) selector: 0xcf309012
        self.bytecode.windows(4).any(|w| w == [0xcf, 0x30, 0x90, 0x12])
    }
    
    fn locked_flag_is_mutable(&self) -> bool {
        // Check if there's a function that can change locked status
        // Look for SSTORE to locked storage slot without immutable pattern
        
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        
        // If there are SSTOREs and no constructor-only pattern, it's likely mutable
        sstore_count > 0
    }
}
