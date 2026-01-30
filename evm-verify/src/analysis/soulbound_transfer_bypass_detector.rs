use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoulboundTransferBypassDetectorVulnerability {
    TransferBypass { description: String, location: usize },
}
pub struct SoulboundTransferBypassDetector { bytecode: Vec<u8> }
impl SoulboundTransferBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SoulboundTransferBypassDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2], self.bytecode[i+3], self.bytecode[i+4],
                ]);
                // transferFrom: 0x23b872dd
                if selector == 0x23b872dd {
                    let always_reverts = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                        .iter().any(|&b| b == 0xfd); // REVERT
                    if !always_reverts {
                        vulnerabilities.push(SoulboundTransferBypassDetectorVulnerability::TransferBypass {
                            description: "Soulbound token with working transfer".to_string(), location: i,
                        });
                        break;
                    }
                }
            }
        }
        vulnerabilities
    }
}