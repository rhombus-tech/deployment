use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustedSetupCompromiseVulnerability {
    UntrustedCeremony { description: String, location: usize, confidence: f32 },
    MissingVerification { description: String, location: usize },
}

pub struct TrustedSetupCompromiseDetector {
    bytecode: Vec<u8>,
}

impl TrustedSetupCompromiseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TrustedSetupCompromiseVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_zk_verification() && !self.validates_setup_parameters() {
            vulnerabilities.push(TrustedSetupCompromiseVulnerability::UntrustedCeremony {
                description: "ZK proof uses trusted setup without parameter validation".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_zk_verification(&self) -> bool {
        self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count() > 2
    }
    
    fn validates_setup_parameters(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sload_count > 3
    }
}
