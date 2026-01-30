use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FheSidechannelDetectorVulnerability {
    SideChannelLeak { description: String, location: usize },
}
pub struct FheSidechannelDetector { bytecode: Vec<u8> }
impl FheSidechannelDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<FheSidechannelDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x57 { // JUMPI (timing-dependent branch)
                let depends_on_secret = self.bytecode[i.saturating_sub(20)..i]
                    .iter().any(|&b| b == 0x54); // SLOAD (secret data)
                if depends_on_secret {
                    vulnerabilities.push(FheSidechannelDetectorVulnerability::SideChannelLeak {
                        description: "Timing-dependent branch on secret data".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}