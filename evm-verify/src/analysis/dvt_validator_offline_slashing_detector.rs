use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DvtValidatorOfflineSlashingVulnerability {
    UncoordinatedOffline { description: String, location: usize, confidence: f32 },
    MissingLivenessCheck { description: String, location: usize, confidence: f32 },
    SlashingAmplification { description: String, location: usize, confidence: f32 },
}

pub struct DvtValidatorOfflineSlashingDetector {
    bytecode: Vec<u8>,
}

impl DvtValidatorOfflineSlashingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DvtValidatorOfflineSlashingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_dvt_validators() && !self.coordinates_offline() {
            vulnerabilities.push(DvtValidatorOfflineSlashingVulnerability::UncoordinatedOffline {
                description: "DVT validators without offline coordination - unintended slashing risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.has_validator_logic() && !self.checks_liveness() {
            vulnerabilities.push(DvtValidatorOfflineSlashingVulnerability::MissingLivenessCheck {
                description: "Validator logic without liveness checks - offline slashing exposure".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        if self.handles_slashing() && self.has_multiple_validators() {
            vulnerabilities.push(DvtValidatorOfflineSlashingVulnerability::SlashingAmplification {
                description: "Multiple validators with slashing - amplified penalty risk".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_dvt_validators(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        sload_count > 5 && call_count > 2
    }
    
    fn coordinates_offline(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        timestamp_count > 1 && staticcall_count > 2
    }
    
    fn has_validator_logic(&self) -> bool {
        let jumpdest_count = self.bytecode.iter().filter(|&&b| b == 0x5B).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        jumpdest_count > 5 && call_count > 2
    }
    
    fn checks_liveness(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 0 && sub_count > 1 && lt_count > 0
    }
    
    fn handles_slashing(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 1 && sstore_count > 3
    }
    
    fn has_multiple_validators(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sload_count > 8
    }
}
