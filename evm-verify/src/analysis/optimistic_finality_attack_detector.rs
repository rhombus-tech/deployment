use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimisticFinalityAttackDetectorVulnerability {
    WithdrawalDelayExploit { description: String, location: usize },
}

pub struct OptimisticFinalityAttackDetector { bytecode: Vec<u8> }

impl OptimisticFinalityAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    
    pub fn detect_vulnerabilities(&self) -> Vec<OptimisticFinalityAttackDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                let has_challenge_period = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .windows(3).any(|w| w[0] == 0x01 && w[2] == 0x10); // ADD, LT
                if has_challenge_period {
                    let has_fraud_check = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                        .iter().filter(|&&b| b == 0x57).count() >= 2; // Multiple JUMPI
                    if !has_fraud_check {
                        vulnerabilities.push(OptimisticFinalityAttackDetectorVulnerability::WithdrawalDelayExploit {
                            description: "Optimistic withdrawal without fraud proof check".to_string(), location: i,
                        });
                        break;
                    }
                }
            }
        }
        vulnerabilities
    }
}