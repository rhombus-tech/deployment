use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BundlerCensorshipDetectorVulnerability {
    UserOpFiltering { description: String, location: usize },
}
pub struct BundlerCensorshipDetector { bytecode: Vec<u8> }
impl BundlerCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<BundlerCensorshipDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x33 { // CALLER
                let has_whitelist = self.bytecode[i..std::cmp::min(i+30, self.bytecode.len())]
                    .windows(3).any(|w| w[0] == 0x54 && w[1] == 0x14);
                if has_whitelist {
                    vulnerabilities.push(BundlerCensorshipDetectorVulnerability::UserOpFiltering {
                        description: "Bundler with caller whitelist".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}