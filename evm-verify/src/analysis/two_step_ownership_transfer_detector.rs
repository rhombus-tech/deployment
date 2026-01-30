use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwoStepOwnershipTransferVulnerability {
    DirectTransferOwnership { description: String, location: usize, confidence: f32 },
    NoAcceptOwnershipFunction { description: String, location: usize },
    OwnershipLossRisk { description: String, location: usize },
}

pub struct TwoStepOwnershipTransferDetector {
    bytecode: Vec<u8>,
}

impl TwoStepOwnershipTransferDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TwoStepOwnershipTransferVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // transferOwnership selector: 0xf2fde38b
        let transfer_ownership_selector = [0xf2, 0xfd, 0xe3, 0x8b];
        
        if self.has_transfer_ownership() {
            if !self.has_accept_ownership() {
                vulnerabilities.push(TwoStepOwnershipTransferVulnerability::NoAcceptOwnershipFunction {
                    description: "transferOwnership without acceptOwnership - typo in address = permanent ownership loss".to_string(),
                    location: 0,
                });
            }
            
            // Check if transferOwnership directly changes owner
            for i in 0..self.bytecode.len().saturating_sub(60) {
                if self.bytecode[i..].windows(4).next() == Some(&transfer_ownership_selector) {
                    if self.directly_changes_owner(i, i + 60) {
                        vulnerabilities.push(TwoStepOwnershipTransferVulnerability::DirectTransferOwnership {
                            description: "transferOwnership directly sets new owner without pending/accept pattern".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_transfer_ownership(&self) -> bool {
        let transfer_ownership_selector = [0xf2, 0xfd, 0xe3, 0x8b];
        self.bytecode.windows(4).any(|w| w == transfer_ownership_selector)
    }
    
    fn has_accept_ownership(&self) -> bool {
        // acceptOwnership selector: 0x79ba5097
        let accept_ownership_selector = [0x79, 0xba, 0x50, 0x97];
        self.bytecode.windows(4).any(|w| w == accept_ownership_selector)
    }
    
    fn directly_changes_owner(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: CALLDATALOAD (new owner) → SSTORE (set owner slot)
        // Without intermediate "pending owner" storage
        let calldataload_positions: Vec<_> = self.bytecode[start..range_end]
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x35)
            .map(|(i, _)| i)
            .collect();
        
        for pos in calldataload_positions {
            let check_end = (pos + 20).min(range_end - start);
            if self.bytecode[start + pos..start + check_end].contains(&0x55) { // SSTORE
                // Check if there's only ONE SSTORE (direct) vs TWO (pending + accepted)
                let sstore_count = self.bytecode[start + pos..start + check_end]
                    .iter()
                    .filter(|&&b| b == 0x55)
                    .count();
                if sstore_count == 1 {
                    return true;
                }
            }
        }
        
        false
    }
}
