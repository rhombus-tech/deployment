use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GamingRngPredictionDetectorVulnerability {
    PredictableRNG { description: String, location: usize },
}
pub struct GamingRngPredictionDetector { bytecode: Vec<u8> }
impl GamingRngPredictionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<GamingRngPredictionDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x40 { // BLOCKHASH
                let uses_timestamp = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                    .iter().any(|&b| b == 0x42);
                if uses_timestamp {
                    vulnerabilities.push(GamingRngPredictionDetectorVulnerability::PredictableRNG {
                        description: "RNG using blockhash+timestamp - predictable".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}