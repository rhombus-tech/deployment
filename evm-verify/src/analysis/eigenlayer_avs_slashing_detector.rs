use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EigenlayerAvsSlashingVulnerability {
    pub location: usize,
    pub confidence: f32,
    pub vulnerability_type: String,
    pub description: String,
}

pub struct EigenlayerAvsSlashingDetector {
    bytecode: Vec<u8>,
}

impl EigenlayerAvsSlashingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EigenlayerAvsSlashingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect unrestricted slashing without proper authorization
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE (slashing state change)
                let mut has_authorization = false;
                
                // Check for authorization check before SSTORE
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x33 { // CALLER
                        has_authorization = true;
                    }
                }
                
                if !has_authorization {
                    vulnerabilities.push(EigenlayerAvsSlashingVulnerability {
                        location: i,
                        confidence: 0.80,
                        vulnerability_type: "UnauthorizedSlashing".to_string(),
                        description: "AVS slashing function lacks proper authorization checks".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
}
