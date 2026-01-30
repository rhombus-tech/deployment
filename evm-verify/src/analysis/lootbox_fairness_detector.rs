use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LootboxFairnessDetectorVulnerability {
    UnfairDropRates { description: String, location: usize },
}
pub struct LootboxFairnessDetector { bytecode: Vec<u8> }
impl LootboxFairnessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<LootboxFairnessDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x06 { // MOD (probability calculation)
                let has_verifiable_seed = self.bytecode[i.saturating_sub(20)..i]
                    .iter().any(|&b| b == 0x40); // BLOCKHASH
                if !has_verifiable_seed {
                    vulnerabilities.push(LootboxFairnessDetectorVulnerability::UnfairDropRates {
                        description: "Lootbox RNG without verifiable seed".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}