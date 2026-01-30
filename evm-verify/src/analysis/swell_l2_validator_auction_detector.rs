use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwellL2ValidatorAuctionVulnerability {
    AuctionBidManipulation { description: String, location: usize, confidence: f32 },
    UnfairValidatorSelection { description: String, location: usize, confidence: f32 },
    BidWithdrawalExploit { description: String, location: usize, confidence: f32 },
}

pub struct SwellL2ValidatorAuctionDetector {
    bytecode: Vec<u8>,
}

impl SwellL2ValidatorAuctionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SwellL2ValidatorAuctionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.processes_bids() && !self.validates_bid_timing() {
            vulnerabilities.push(SwellL2ValidatorAuctionVulnerability::AuctionBidManipulation {
                description: "Bid processing without timing validation - last-block bid manipulation".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.selects_validator() && !self.uses_vrf() {
            vulnerabilities.push(SwellL2ValidatorAuctionVulnerability::UnfairValidatorSelection {
                description: "Validator selection without VRF - predictable selection".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.allows_bid_withdrawal() && !self.enforces_lock_period() {
            vulnerabilities.push(SwellL2ValidatorAuctionVulnerability::BidWithdrawalExploit {
                description: "Bid withdrawal without lock period - auction griefing".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn processes_bids(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let callvalue_count = self.bytecode.iter().filter(|&&b| b == 0x34).count();
        sstore_count > 3 && callvalue_count > 0
    }
    
    fn validates_bid_timing(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        timestamp_count > 0 && lt_count > 1 && jumpi_count > 2
    }
    
    fn selects_validator(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        sload_count > 4 && mod_count > 0
    }
    
    fn uses_vrf(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        staticcall_count > 1 && sha3_count > 2
    }
    
    fn allows_bid_withdrawal(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        call_count > 1 && sub_count > 1
    }
    
    fn enforces_lock_period(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 0 && sload_count > 3 && gt_count > 1
    }
}
