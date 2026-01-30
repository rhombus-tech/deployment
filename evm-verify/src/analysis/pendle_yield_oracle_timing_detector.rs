use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendleYieldOracleTimingVulnerability {
    StaleYieldData { description: String, location: usize, confidence: f32 },
    OracleTimingManipulation { description: String, location: usize, confidence: f32 },
    YieldRateFrontrunning { description: String, location: usize, confidence: f32 },
}

pub struct PendleYieldOracleTimingDetector {
    bytecode: Vec<u8>,
}

impl PendleYieldOracleTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PendleYieldOracleTimingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.reads_yield_oracle() && !self.validates_freshness() {
            vulnerabilities.push(PendleYieldOracleTimingVulnerability::StaleYieldData {
                description: "Yield oracle read without freshness validation - stale data risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.updates_oracle() && !self.has_rate_limit() {
            vulnerabilities.push(PendleYieldOracleTimingVulnerability::OracleTimingManipulation {
                description: "Oracle update without rate limiting - timing manipulation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.uses_yield_rate() && !self.has_commit_reveal() {
            vulnerabilities.push(PendleYieldOracleTimingVulnerability::YieldRateFrontrunning {
                description: "Yield rate usage without commit-reveal - frontrunning risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn reads_yield_oracle(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        staticcall_count > 1 && sload_count > 3
    }
    
    fn validates_freshness(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 0 && sub_count > 1 && lt_count > 1
    }
    
    fn updates_oracle(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        sstore_count > 2 && mul_count > 2
    }
    
    fn has_rate_limit(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 1 && sload_count > 4 && gt_count > 2
    }
    
    fn uses_yield_rate(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 3 && div_count > 2
    }
    
    fn has_commit_reveal(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sha3_count > 2 && sload_count > 4 && sstore_count > 3
    }
}
