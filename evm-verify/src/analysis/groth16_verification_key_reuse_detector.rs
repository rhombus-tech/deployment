use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Groth16VerificationKeyReuseVulnerability {
    KeyReuseAcrossCircuits { description: String, location: usize, confidence: f32 },
}

pub struct Groth16VerificationKeyReuseDetector {
    bytecode: Vec<u8>,
}

impl Groth16VerificationKeyReuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Groth16VerificationKeyReuseVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_groth16_verification() && !self.has_unique_verification_key() {
            vulnerabilities.push(Groth16VerificationKeyReuseVulnerability::KeyReuseAcrossCircuits {
                description: "Groth16 verification key reused across circuits - security risk".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_groth16_verification(&self) -> bool {
        self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count() > 3
    }
    
    fn has_unique_verification_key(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sload_count > 4
    }
}
