use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymasterDosAdvancedDetectorVulnerability {
    GasTankDraining { description: String, location: usize },
}
pub struct PaymasterDosAdvancedDetector { bytecode: Vec<u8> }
impl PaymasterDosAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<PaymasterDosAdvancedDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5a { // GAS
                let has_limit = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                    .windows(2).any(|w| w[0] == 0x10 || w[0] == 0x11);
                if !has_limit {
                    vulnerabilities.push(PaymasterDosAdvancedDetectorVulnerability::GasTankDraining {
                        description: "Paymaster without gas limit".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}