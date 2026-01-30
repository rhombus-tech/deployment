use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkEmailAdvancedDetectorVulnerability {
    EmailProofBug { description: String, location: usize },
}
pub struct ZkEmailAdvancedDetector { bytecode: Vec<u8> }
impl ZkEmailAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ZkEmailAdvancedDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 { // KECCAK256 (email hash)
                let validates_domain = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(3).any(|w| w[0] == 0x14 && w[2] == 0x57);
                if !validates_domain {
                    vulnerabilities.push(ZkEmailAdvancedDetectorVulnerability::EmailProofBug {
                        description: "Email proof without domain validation".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}