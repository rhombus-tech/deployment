use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PointsFarmingSybilVulnerability {
    UnlimitedAccountCreation { description: String, location: usize, confidence: f32 },
    NoSybilResistance { description: String, location: usize, confidence: f32 },
    PointSplittingExploit { description: String, location: usize, confidence: f32 },
}

pub struct PointsFarmingSybilDetector {
    bytecode: Vec<u8>,
}

impl PointsFarmingSybilDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PointsFarmingSybilVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.distributes_points() && !self.limits_account_creation() {
            vulnerabilities.push(PointsFarmingSybilVulnerability::UnlimitedAccountCreation {
                description: "Points distribution without account limits - sybil farming via unlimited accounts".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.rewards_activity() && !self.implements_sybil_resistance() {
            vulnerabilities.push(PointsFarmingSybilVulnerability::NoSybilResistance {
                description: "Activity rewards without sybil resistance - multi-account exploitation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.allows_point_transfer() && !self.tracks_point_concentration() {
            vulnerabilities.push(PointsFarmingSybilVulnerability::PointSplittingExploit {
                description: "Transferable points without concentration tracking - point splitting farming".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn distributes_points(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sstore_count > 3 && add_count > 2
    }
    
    fn limits_account_creation(&self) -> bool {
        // Per-address or per-block limits
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let blocknumber_count = self.bytecode.iter().filter(|&&b| b == 0x43).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 4 && (blocknumber_count > 0 || gt_count > 2)
    }
    
    fn rewards_activity(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        timestamp_count > 1 && sstore_count > 3 && mul_count > 2
    }
    
    fn implements_sybil_resistance(&self) -> bool {
        // Cost barrier or proof-of-humanity
        let callvalue_count = self.bytecode.iter().filter(|&&b| b == 0x34).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        callvalue_count > 0 || staticcall_count > 3
    }
    
    fn allows_point_transfer(&self) -> bool {
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        caller_count > 1 && sload_count > 4 && sstore_count > 4
    }
    
    fn tracks_point_concentration(&self) -> bool {
        // Total tracking and concentration limits
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        sload_count > 6 && div_count > 1 && lt_count > 1
    }
}
