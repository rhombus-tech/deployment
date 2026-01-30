use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiAvsSlashingAmplificationVulnerability {
    CascadingSlashRisk { description: String, location: usize, confidence: f32 },
    NoSlashingIsolation { description: String, location: usize },
    AmplifiedPenalty { description: String, location: usize },
}

pub struct MultiAvsSlashingAmplificationDetector {
    bytecode: Vec<u8>,
}

impl MultiAvsSlashingAmplificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiAvsSlashingAmplificationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_multi_protocol_staking() {
            if !self.has_slashing_isolation() {
                vulnerabilities.push(MultiAvsSlashingAmplificationVulnerability::CascadingSlashRisk {
                    description: "Multiple AVS staking without isolation - single fault cascading slash".to_string(),
                    location: 0,
                    confidence: 0.85,
                });
            }
            
            if self.has_amplified_slashing() {
                vulnerabilities.push(MultiAvsSlashingAmplificationVulnerability::AmplifiedPenalty {
                    description: "Slashing penalty amplified across protocols - excessive punishment".to_string(),
                    location: 0,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_multi_protocol_staking(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        call_count > 3
    }
    
    fn has_slashing_isolation(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sload_count > 5
    }
    
    fn has_amplified_slashing(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        mul_count > 3
    }
}
