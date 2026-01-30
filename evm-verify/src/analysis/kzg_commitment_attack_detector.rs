use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KzgCommitmentAttackDetectorVulnerability {
    CommitmentAttack { description: String, location: usize },
}
pub struct KzgCommitmentAttackDetector { bytecode: Vec<u8> }
impl KzgCommitmentAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<KzgCommitmentAttackDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa {
                // Check if calling KZG precompile (0x0A)
                let calls_kzg = i > 10 && self.bytecode[i-10..i].windows(2)
                    .any(|w| w[0] == 0x60 && w[1] == 0x0a);
                if calls_kzg {
                    let checks_result = self.bytecode[i..std::cmp::min(i+20, self.bytecode.len())]
                        .iter().any(|&b| b == 0x15 || b == 0x14);
                    if !checks_result {
                        vulnerabilities.push(KzgCommitmentAttackDetectorVulnerability::CommitmentAttack {
                            description: "KZG precompile result not verified".to_string(), location: i,
                        });
                        break;
                    }
                }
            }
        }
        vulnerabilities
    }
}