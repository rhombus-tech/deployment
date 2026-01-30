use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationGasGriefingDetectorVulnerability {
    ExpensiveValidation { description: String, location: usize },
}
pub struct ValidationGasGriefingDetector { bytecode: Vec<u8> }
impl ValidationGasGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ValidationGasGriefingDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.bytecode[i] == 0x01 { // ECRECOVER
                let has_gas_check = self.bytecode[i.saturating_sub(20)..i].iter().any(|&b| b == 0x5a);
                if !has_gas_check {
                    vulnerabilities.push(ValidationGasGriefingDetectorVulnerability::ExpensiveValidation {
                        description: "Validation without gas limit".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}