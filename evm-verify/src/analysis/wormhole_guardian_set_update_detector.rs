use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WormholeGuardianSetUpdateVulnerability {
    UnsafeGuardianUpdate { description: String, location: usize, confidence: f32 },
    InsufficientGuardianSignatures { description: String, location: usize, confidence: f32 },
    GuardianSetTransitionRisk { description: String, location: usize, confidence: f32 },
}

pub struct WormholeGuardianSetUpdateDetector {
    bytecode: Vec<u8>,
}

impl WormholeGuardianSetUpdateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WormholeGuardianSetUpdateVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.updates_guardian_set() && !self.requires_quorum() {
            vulnerabilities.push(WormholeGuardianSetUpdateVulnerability::UnsafeGuardianUpdate {
                description: "Guardian set update without quorum - unauthorized update".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.validates_signatures() && !self.checks_threshold() {
            vulnerabilities.push(WormholeGuardianSetUpdateVulnerability::InsufficientGuardianSignatures {
                description: "Signature validation without threshold - insufficient signatures".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.transitions_guardian_set() && !self.enforces_delay() {
            vulnerabilities.push(WormholeGuardianSetUpdateVulnerability::GuardianSetTransitionRisk {
                description: "Guardian set transition without delay - immediate takeover risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn updates_guardian_set(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 4 && log_count > 1
    }
    
    fn requires_quorum(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 5 && div_count > 1 && gt_count > 1
    }
    
    fn validates_signatures(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        staticcall_count > 2 && sha3_count > 2
    }
    
    fn checks_threshold(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 4 && mul_count > 1 && gt_count > 1
    }
    
    fn transitions_guardian_set(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sstore_count > 3 && add_count > 1
    }
    
    fn enforces_delay(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 0 && add_count > 1 && gt_count > 1
    }
}
