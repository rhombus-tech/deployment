use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModularArithmeticVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ModularArithmeticWeaknessDetector {
    bytecode: Vec<u8>,
}

impl ModularArithmeticWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ModularArithmeticVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_modular_inverse_weakness() {
            vulnerabilities.push(ModularArithmeticVulnerability {
                vulnerability_type: "Modular Inverse Without GCD Check".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Modular inverse without coprime verification".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_modular_inverse_weakness(&self) -> Option<usize> {
        // Pattern: MOD without prior GCD check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x06 { // MOD
                let mut has_gcd = false;
                for j in i.saturating_sub(15)..i {
                    // Extended Euclidean uses repeated MOD
                    if self.bytecode[j] == 0x06 && self.bytecode.get(j+5) == Some(&0x06) {
                        has_gcd = true;
                    }
                }
                if !has_gcd { return Some(i); }
            }
        }
        None
    }
}
