use serde::{Deserialize, Serialize};

/// Create2 Salt Grinding: Brute-force salts for favorable addresses
/// Attack: Generate contracts at addresses that bypass checks

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Create2SaltGrindingVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Create2SaltGrindingDetector {
    bytecode: Vec<u8>,
}

impl Create2SaltGrindingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<Create2SaltGrindingVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_address_check_bypass() {
            vulnerabilities.push(Create2SaltGrindingVulnerability {
                vulnerability_type: "CREATE2 Address Check Bypass".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Address-based checks bypassable via CREATE2 salt grinding".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_address_check_bypass(&self) -> Option<usize> {
        // CREATE2 followed by address comparison
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf5 { // CREATE2
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ (address check)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
