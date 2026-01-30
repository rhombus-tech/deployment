use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NftLendingOracleDetectorVulnerability {
    PriceManipulation { description: String, location: usize },
}
pub struct NftLendingOracleDetector { bytecode: Vec<u8> }
impl NftLendingOracleDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<NftLendingOracleDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle)
                let has_staleness = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .iter().any(|&b| b == 0x42); // TIMESTAMP check
                if !has_staleness {
                    vulnerabilities.push(NftLendingOracleDetectorVulnerability::PriceManipulation {
                        description: "NFT oracle without staleness check".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}