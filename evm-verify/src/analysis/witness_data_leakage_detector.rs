use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WitnessDataLeakageVulnerability {
    PrivateInputExposed { description: String, location: usize, confidence: f32 },
}

pub struct WitnessDataLeakageDetector {
    bytecode: Vec<u8>,
}

impl WitnessDataLeakageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<WitnessDataLeakageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_zk_proof() && self.exposes_witness_data() {
            vulnerabilities.push(WitnessDataLeakageVulnerability::PrivateInputExposed {
                description: "ZK proof exposes witness data via side channels".to_string(),
                location: 0,
                confidence: 0.70,
            });
        }
        
        vulnerabilities
    }
    
    fn has_zk_proof(&self) -> bool {
        self.bytecode.iter().filter(|&&b| b == 0xF1).count() > 2
    }
    
    fn exposes_witness_data(&self) -> bool {
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        log_count > 0
    }
}
