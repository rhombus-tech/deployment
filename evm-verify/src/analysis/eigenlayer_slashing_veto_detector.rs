use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EigenlayerSlashingVetoVulnerability {
    UnilateralSlashingPower { description: String, location: usize, confidence: f32 },
    NoVetoMechanism { description: String, location: usize, confidence: f32 },
    SlashingWithoutAppeal { description: String, location: usize, confidence: f32 },
}

pub struct EigenlayerSlashingVetoDetector {
    bytecode: Vec<u8>,
}

impl EigenlayerSlashingVetoDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EigenlayerSlashingVetoVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.implements_slashing() && !self.requires_multi_sig() {
            vulnerabilities.push(EigenlayerSlashingVetoVulnerability::UnilateralSlashingPower {
                description: "EigenLayer slashing without multi-sig - single point of failure".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.executes_slash() && !self.checks_veto() {
            vulnerabilities.push(EigenlayerSlashingVetoVulnerability::NoVetoMechanism {
                description: "Slashing execution without veto period - immediate irreversible slash".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.finalizes_slash() && !self.allows_appeal() {
            vulnerabilities.push(EigenlayerSlashingVetoVulnerability::SlashingWithoutAppeal {
                description: "Slash finalization without appeal mechanism - no recourse".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn implements_slashing(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        sstore_count > 3 && sub_count > 2
    }
    
    fn requires_multi_sig(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 4 && eq_count > 3 && gt_count > 2
    }
    
    fn executes_slash(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 1 && sstore_count > 3
    }
    
    fn checks_veto(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        timestamp_count > 0 && lt_count > 2 && sload_count > 3
    }
    
    fn finalizes_slash(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 4 && log_count > 1
    }
    
    fn allows_appeal(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        timestamp_count > 1 && jumpi_count > 4 && revert_count > 2
    }
}
