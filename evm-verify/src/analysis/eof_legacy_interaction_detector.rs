use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EofLegacyInteractionVulnerability {
    EofLegacyIncompatibility { description: String, location: usize, confidence: f32 },
}

pub struct EofLegacyInteractionDetector {
    bytecode: Vec<u8>,
}

impl EofLegacyInteractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EofLegacyInteractionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_eof_format() && self.interacts_with_legacy() {
            vulnerabilities.push(EofLegacyInteractionVulnerability::EofLegacyIncompatibility {
                description: "EOF contract interacts with legacy contracts - compatibility issues".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_eof_format(&self) -> bool {
        self.bytecode.len() > 2 && self.bytecode[0] == 0xEF && self.bytecode[1] == 0x00
    }
    
    fn interacts_with_legacy(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        call_count > 0
    }
}
