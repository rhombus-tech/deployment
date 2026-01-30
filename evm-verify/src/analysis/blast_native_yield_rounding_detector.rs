use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlastNativeYieldRoundingVulnerability {
    YieldAccrualRounding { description: String, location: usize, confidence: f32 },
    ClaimRoundingExploit { description: String, location: usize, confidence: f32 },
    CompoundingRoundingLoss { description: String, location: usize, confidence: f32 },
}

pub struct BlastNativeYieldRoundingDetector {
    bytecode: Vec<u8>,
}

impl BlastNativeYieldRoundingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlastNativeYieldRoundingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.accrues_yield() && !self.rounds_up_user() {
            vulnerabilities.push(BlastNativeYieldRoundingVulnerability::YieldAccrualRounding {
                description: "Yield accrual without user-favorable rounding - yield loss accumulation".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.processes_claim() && !self.validates_minimum() {
            vulnerabilities.push(BlastNativeYieldRoundingVulnerability::ClaimRoundingExploit {
                description: "Yield claim without minimum validation - dust claim griefing".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.compounds_yield() && !self.tracks_remainder() {
            vulnerabilities.push(BlastNativeYieldRoundingVulnerability::CompoundingRoundingLoss {
                description: "Yield compounding without remainder tracking - compounding loss".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn accrues_yield(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        mul_count > 2 && div_count > 1 && sstore_count > 2
    }
    
    fn rounds_up_user(&self) -> bool {
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        mod_count > 0 && add_count > 3 && iszero_count > 1
    }
    
    fn processes_claim(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        call_count > 1 && sload_count > 3
    }
    
    fn validates_minimum(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        gt_count > 1 && jumpi_count > 2
    }
    
    fn compounds_yield(&self) -> bool {
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        add_count > 3 && mul_count > 2 && sstore_count > 3
    }
    
    fn tracks_remainder(&self) -> bool {
        let mod_count = self.bytecode.iter().filter(|&&b| b == 0x06).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        mod_count > 1 && sstore_count > 4
    }
}
