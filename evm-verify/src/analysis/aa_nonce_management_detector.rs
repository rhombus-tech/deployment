use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AaNonceManagementDetectorVulnerability {
    NonceReuse { description: String, location: usize },
}
pub struct AaNonceManagementDetector { bytecode: Vec<u8> }
impl AaNonceManagementDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<AaNonceManagementDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 { // SLOAD (nonce)
                let is_incremented = self.bytecode[i..std::cmp::min(i+15, self.bytecode.len())]
                    .windows(3).any(|w| w[0] == 0x01 && w[2] == 0x55); // ADD, SSTORE
                if !is_incremented {
                    vulnerabilities.push(AaNonceManagementDetectorVulnerability::NonceReuse {
                        description: "Nonce not incremented after use".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}